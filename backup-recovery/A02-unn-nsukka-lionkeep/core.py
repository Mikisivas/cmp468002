"""LionKeep core: full + differential encrypted archives with Grandfather-Father-Son
rotation, file-signature (magic byte) and entropy validation, and host monitoring.

Design: a FULL archive is a ZIP of every protected file. A DIFFERENTIAL archive holds
only files changed since the last FULL. Restore therefore needs at most two archives
(full + newest differential), which keeps recovery simple for a small ICT team.
Archives are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) under a key derived
from the operator passphrase with PBKDF2-HMAC-SHA256 (600,000 iterations).
"""
import base64
import datetime as dt
import hashlib
import io
import json
import math
import os
import shutil
import socket
import sqlite3
import time
import urllib.request
import zipfile

from cryptography.fernet import Fernet, InvalidToken

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")

# expected leading bytes for common university file types
SIGNATURES = {".pdf": [b"%PDF"], ".docx": [b"PK\x03\x04"], ".xlsx": [b"PK\x03\x04"], ".zip": [b"PK\x03\x04"],
              ".png": [b"\x89PNG"], ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"]}
TEXT_TYPES = {".csv", ".txt", ".sql", ".json", ".html", ".md"}


def cfg():
    with open(os.path.join(BASE, "config.json")) as fh:
        return json.load(fh)


def p(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "lionkeep.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS archives(id INTEGER PRIMARY KEY, name TEXT, kind TEXT, base_full INT, created TEXT,
        files INT, raw_bytes INT, stored_bytes INT, seconds REAL, sha256 TEXT, tier TEXT, quarantined INT);
    CREATE TABLE IF NOT EXISTS quarantine(id INTEGER PRIMARY KEY, ts TEXT, path TEXT, reason TEXT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts TEXT, level TEXT, message TEXT);
    CREATE TABLE IF NOT EXISTS metrics(ts TEXT, cpu REAL, mem REAL, disk REAL);
    CREATE TABLE IF NOT EXISTS services(name TEXT PRIMARY KEY, status TEXT, since TEXT);
    CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, pw TEXT, role TEXT, failed INT DEFAULT 0, locked_until REAL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY, ts TEXT, who TEXT, what TEXT, prev TEXT, hash TEXT);
    CREATE TABLE IF NOT EXISTS restores(ts TEXT, archive TEXT, files INT, seconds REAL);
    """)
    return con


def alert(level, message):
    with db() as con:
        con.execute("INSERT INTO alerts(ts,level,message) VALUES(?,?,?)", (now(), level, message))
    print(f"[{level}] {message}")


def log(who, what):
    """Append-only activity log linked by SHA-256 (each row hashes the previous row's hash)."""
    with db() as con:
        prev = con.execute("SELECT hash FROM log ORDER BY id DESC LIMIT 1").fetchone()
        prev = prev["hash"] if prev else "0" * 64
        ts = now()
        h = hashlib.sha256(f"{prev}{ts}{who}{what}".encode()).hexdigest()
        con.execute("INSERT INTO log(ts,who,what,prev,hash) VALUES(?,?,?,?,?)", (ts, who, what, prev, h))


def log_intact():
    prev = "0" * 64
    with db() as con:
        for r in con.execute("SELECT * FROM log ORDER BY id"):
            if r["prev"] != prev or hashlib.sha256(f"{prev}{r['ts']}{r['who']}{r['what']}".encode()).hexdigest() != r["hash"]:
                return False
            prev = r["hash"]
    return True


# ----------------------------------------------------------------- keys
def fernet():
    """Key = PBKDF2(passphrase, salt). Passphrase comes from the environment or the local key file
    created at setup (demo only; in production keep it in the environment, not on disk)."""
    c = cfg()
    pw = os.environ.get(c["passphrase_env"])
    if not pw:
        with open(os.path.join(DATA, "keys", "passphrase.txt")) as fh:
            pw = fh.read().strip()
    with open(os.path.join(DATA, "keys", "salt.bin"), "rb") as fh:
        salt = fh.read()
    key = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000)
    return Fernet(base64.urlsafe_b64encode(key))


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    with open(os.path.join(DATA, "keys", "salt.bin"), "wb") as fh:
        fh.write(os.urandom(16))
    if not os.environ.get(cfg()["passphrase_env"]):
        with open(os.path.join(DATA, "keys", "passphrase.txt"), "w") as fh:
            fh.write(base64.urlsafe_b64encode(os.urandom(24)).decode())
    for d in [cfg()["store"]] + cfg()["copies"]:
        os.makedirs(p(d), exist_ok=True)


# ----------------------------------------------------------------- validation
def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def validate(path):
    """Return None if the file looks normal, else the reason it is suspicious."""
    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as fh:
        head = fh.read(65536)
    if ext in SIGNATURES and not any(head.startswith(s) for s in SIGNATURES[ext]):
        return f"signature mismatch for {ext}"
    if ext in TEXT_TYPES:
        try:
            head.decode("utf-8")
        except UnicodeDecodeError:
            return "text file no longer decodes as UTF-8"
    if ext not in (".zip", ".docx", ".xlsx", ".png", ".jpg", ".jpeg") and len(head) > 512:
        e = entropy(head)
        if e > cfg()["entropy_limit"]:
            return f"entropy {e:.2f} bits/byte (looks encrypted)"
    return None


def scan():
    src = p(cfg()["source"])
    out = {}
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            full = os.path.join(root, f)
            with open(full, "rb") as fh:
                out[os.path.relpath(full, src).replace("\\", "/")] = hashlib.sha256(fh.read()).hexdigest()
    return out


# ----------------------------------------------------------------- archives
def last_full():
    with db() as con:
        return con.execute("SELECT * FROM archives WHERE kind='full' ORDER BY id DESC LIMIT 1").fetchone()


def manifest_of(row):
    data = fernet().decrypt(open(os.path.join(p(cfg()["store"]), row["name"]), "rb").read())
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return json.loads(z.read("__manifest__.json"))


def backup(kind="auto", who="scheduler"):
    c = cfg()
    t0 = time.time()
    src = p(c["source"])
    current = scan()
    full = last_full()
    if kind == "auto":
        kind = "full" if not full else "diff"
    base = manifest_of(full)["hashes"] if (kind == "diff" and full) else {}
    if kind == "diff" and not full:
        kind = "full"
    suspicious = {}
    for rel in current:
        reason = validate(os.path.join(src, rel))
        if reason:
            suspicious[rel] = reason
    for rel in current:
        if any(rel.lower().endswith(x) for x in c["blocked_extensions"]):
            suspicious[rel] = "ransomware extension"
    if suspicious:
        with db() as con:
            for rel, why in suspicious.items():
                con.execute("INSERT INTO quarantine(ts,path,reason) VALUES(?,?,?)", (now(), rel, why))
        alert("critical", f"{len(suspicious)} suspicious files kept OUT of the backup (possible ransomware): "
                          + ", ".join(list(suspicious)[:4]))
    if len(suspicious) >= c["abort_if_suspicious"]:
        log(who, f"backup aborted, {len(suspicious)} suspicious files")
        return {"status": "aborted", "suspicious": len(suspicious)}
    chosen = {r: h for r, h in current.items() if r not in suspicious and (kind == "full" or base.get(r) != h)}
    # keep the last good copy of quarantined files listed so restore still brings them back
    hashes = {r: h for r, h in current.items() if r not in suspicious}
    if kind == "diff":
        for r in suspicious:
            if r in base:
                hashes[r] = base[r]
    buf = io.BytesIO()
    raw = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for rel in chosen:
            z.write(os.path.join(src, rel), rel)
            raw += os.path.getsize(os.path.join(src, rel))
        z.writestr("__manifest__.json", json.dumps({"kind": kind, "created": now(), "hashes": hashes,
                                                    "included": list(chosen)}))
    token = fernet().encrypt(buf.getvalue())
    name = f"{dt.datetime.now():%Y%m%d-%H%M%S-%f}-{kind}.lk"
    with open(os.path.join(p(c["store"]), name), "wb") as fh:
        fh.write(token)
    for copy in c["copies"]:
        shutil.copyfile(os.path.join(p(c["store"]), name), os.path.join(p(copy), name))
    digest = hashlib.sha256(token).hexdigest()
    secs = time.time() - t0
    with db() as con:
        con.execute("INSERT INTO archives(name,kind,base_full,created,files,raw_bytes,stored_bytes,seconds,sha256,"
                    "tier,quarantined) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (name, kind, full["id"] if (kind == "diff" and full) else None, now(), len(chosen), raw,
                     len(token), secs, digest, tier_for(dt.date.today()), len(suspicious)))
    log(who, f"{kind} backup {name} files={len(chosen)}")
    return {"status": "ok", "kind": kind, "archive": name, "files": len(chosen), "raw_bytes": raw,
            "stored_bytes": len(token), "seconds": round(secs, 3), "quarantined": len(suspicious)}


def tier_for(day):
    """Grandfather-Father-Son: last day of month = grandfather, Friday = father, other days = son."""
    if (day + dt.timedelta(days=1)).month != day.month:
        return "grandfather"
    if day.weekday() == 4:
        return "father"
    return "son"


def rotate():
    """Keep 7 sons, 5 fathers and 12 grandfathers. Never delete a full that a kept diff needs."""
    keep = cfg()["gfs"]
    with db() as con:
        rows = con.execute("SELECT * FROM archives ORDER BY id DESC").fetchall()
    kept, count = set(), {"son": 0, "father": 0, "grandfather": 0}
    for r in rows:
        if count[r["tier"]] < keep[r["tier"]]:
            kept.add(r["id"])
            count[r["tier"]] += 1
    kept |= {r["base_full"] for r in rows if r["id"] in kept and r["base_full"]}
    removed = []
    for r in rows:
        if r["id"] not in kept:
            for d in [cfg()["store"]] + cfg()["copies"]:
                try:
                    os.remove(os.path.join(p(d), r["name"]))
                except FileNotFoundError:
                    pass
            with db() as con:
                con.execute("DELETE FROM archives WHERE id=?", (r["id"],))
            removed.append(r["name"])
    log("system", f"GFS rotation removed {len(removed)}")
    return removed


def verify():
    """Check SHA-256 of every archive file against the catalogue, then decrypt it (HMAC check).
    A damaged primary is replaced from the first good copy."""
    c = cfg()
    report = {"ok": 0, "repaired": [], "lost": []}
    with db() as con:
        rows = con.execute("SELECT * FROM archives").fetchall()
    for r in rows:
        prim = os.path.join(p(c["store"]), r["name"])
        good = _good(prim, r)
        if not good:
            for copy in c["copies"]:
                alt = os.path.join(p(copy), r["name"])
                if os.path.exists(alt) and _good(alt, r):
                    shutil.copyfile(alt, prim)
                    good = True
                    report["repaired"].append(r["name"])
                    break
            if not good:
                report["lost"].append(r["name"])
                continue
        report["ok"] += 1
    if report["lost"]:
        alert("critical", f"{len(report['lost'])} archives damaged on every copy")
    log("system", f"verify ok={report['ok']} repaired={len(report['repaired'])}")
    return report


def _good(path, row):
    try:
        data = open(path, "rb").read()
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            return False
        fernet().decrypt(data)
        return True
    except (OSError, InvalidToken):
        return False


def restore(archive_id=None, target=None, who="admin"):
    """Restore = FULL archive, then overlay the chosen DIFFERENTIAL (if any)."""
    c = cfg()
    t0 = time.time()
    with db() as con:
        row = (con.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone() if archive_id else
               con.execute("SELECT * FROM archives ORDER BY id DESC LIMIT 1").fetchone())
        chain = [row] if row["kind"] == "full" else [
            con.execute("SELECT * FROM archives WHERE id=?", (row["base_full"],)).fetchone(), row]
    target = target or p(c["source"])
    final = None
    staged = {}
    for a in chain:
        data = fernet().decrypt(open(os.path.join(p(c["store"]), a["name"]), "rb").read())
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            man = json.loads(z.read("__manifest__.json"))
            for rel in man["included"]:
                staged[rel] = z.read(rel)
            final = man["hashes"]
    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), target).replace("\\", "/")
                if rel not in final:
                    os.remove(os.path.join(root, f))
    for rel in final:
        blob = staged[rel]
        if hashlib.sha256(blob).hexdigest() != final[rel]:
            raise ValueError(f"hash mismatch on {rel}")
        out = os.path.join(target, *rel.split("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(blob)
    secs = time.time() - t0
    with db() as con:
        con.execute("INSERT INTO restores VALUES(?,?,?,?)", (now(), row["name"], len(final), secs))
    log(who, f"restored {row['name']} ({len(chain)} archive(s)) in {secs:.2f}s")
    return {"archive": row["name"], "chain": len(chain), "files": len(final), "seconds": round(secs, 3)}


# ----------------------------------------------------------------- monitoring
def monitor_once():
    c = cfg()
    try:
        import psutil
        m = {"cpu": psutil.cpu_percent(interval=0.3), "mem": psutil.virtual_memory().percent}
    except ImportError:
        m = {"cpu": 0.0, "mem": 0.0}
    du = shutil.disk_usage(BASE)
    m["disk"] = round(du.used / du.total * 100, 1)
    with db() as con:
        con.execute("INSERT INTO metrics VALUES(?,?,?,?)", (now(), m["cpu"], m["mem"], m["disk"]))
    for k, lim in c["thresholds"].items():
        if m[k] > lim:
            alert("warning", f"{k} {m[k]}% above {lim}%")
    for s in c["services"]:
        try:
            if s.get("url"):
                urllib.request.urlopen(s["url"], timeout=3).close()
            else:
                socket.create_connection((s["host"], s["port"]), timeout=3).close()
            status = "UP"
        except Exception:  # noqa: BLE001
            status = "DOWN"
        with db() as con:
            old = con.execute("SELECT status FROM services WHERE name=?", (s["name"],)).fetchone()
            if not old or old["status"] != status:
                con.execute("INSERT OR REPLACE INTO services VALUES(?,?,?)", (s["name"], status, now()))
        if status == "DOWN" and (not old or old["status"] == "UP"):
            alert("critical", f"{s['name']} is DOWN")
    return m
