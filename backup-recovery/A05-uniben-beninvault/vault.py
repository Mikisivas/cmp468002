"""BeninVault: erasure-coded encrypted backups with service uptime (SLA) tracking.

Storage design (2 + 1 parity, like RAID-5 spread over three buildings):
    archive  = AES-256-GCM( zip of all protected files )
    shard A  = first half of archive
    shard B  = second half (padded to the same length)
    shard P  = A XOR B
A, B and P go to three different locations. Any two rebuild the archive, so the
university survives the loss of one whole site (fire, theft, flood, failed disk).
"""
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import socket
import sqlite3
import time
import urllib.request
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
SHARDS = ("A", "B", "P")


def cfg():
    with open(os.path.join(BASE, "config.json")) as fh:
        return json.load(fh)


def p(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def stamp():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "beninvault.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS backups(id TEXT PRIMARY KEY, created TEXT, files INT, plain_bytes INT, cipher_bytes INT,
        seconds REAL, state TEXT, reason TEXT, sha_a TEXT, sha_b TEXT, sha_p TEXT, length INT);
    CREATE TABLE IF NOT EXISTS checks(ts TEXT, service TEXT, up INT, ms REAL);
    CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY, ts TEXT, sev TEXT, msg TEXT);
    CREATE TABLE IF NOT EXISTS people(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS trail(id INTEGER PRIMARY KEY, ts TEXT, who TEXT, act TEXT, h TEXT);
    """)
    return con


def notice(sev, msg):
    with db() as con:
        con.execute("INSERT INTO notices(ts,sev,msg) VALUES(?,?,?)", (stamp(), sev, msg))
    print(f"[{sev}] {msg}")


def trail(who, act):
    with db() as con:
        prev = con.execute("SELECT h FROM trail ORDER BY id DESC LIMIT 1").fetchone()
        ts = stamp()
        h = hashlib.sha256(f"{prev['h'] if prev else ''}|{ts}|{who}|{act}".encode()).hexdigest()
        con.execute("INSERT INTO trail(ts,who,act,h) VALUES(?,?,?,?)", (ts, who, act, h))


def trail_ok():
    prev = ""
    with db() as con:
        for r in con.execute("SELECT * FROM trail ORDER BY id"):
            if hashlib.sha256(f"{prev}|{r['ts']}|{r['who']}|{r['act']}".encode()).hexdigest() != r["h"]:
                return False
            prev = r["h"]
    return True


# ----------------------------------------------------------------- key
_KEY = {}


def key():
    """scrypt(passphrase, salt) with n=2**15, r=8: slow for an attacker who steals the shards."""
    c = cfg()
    pw = os.environ.get(c["passphrase_env"]) or open(os.path.join(DATA, "keys", "pass.txt")).read().strip()
    salt = open(os.path.join(DATA, "keys", "salt"), "rb").read()
    if (pw, salt) not in _KEY:
        _KEY.clear()
        _KEY[(pw, salt)] = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(pw.encode())
    return _KEY[(pw, salt)]


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    open(os.path.join(DATA, "keys", "salt"), "wb").write(os.urandom(16))
    if not os.environ.get(cfg()["passphrase_env"]):
        open(os.path.join(DATA, "keys", "pass.txt"), "w").write(os.urandom(18).hex())
    for site in cfg()["sites"].values():
        os.makedirs(p(site), exist_ok=True)


# ----------------------------------------------------------------- erasure coding
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def split(blob):
    half = (len(blob) + 1) // 2
    a, b = blob[:half], blob[half:].ljust(half, b"\0")
    return {"A": a, "B": b, "P": xor(a, b)}


def join(shards, length):
    a, b, par = shards.get("A"), shards.get("B"), shards.get("P")
    if a is None:
        a = xor(b, par)
    if b is None:
        b = xor(a, par)
    return (a + b)[:length]


def shard_path(bid, s):
    return os.path.join(p(cfg()["sites"][s]), f"{bid}.{s}")


def read_shards(row):
    """Return the shards that exist and pass their SHA-256 check."""
    good = {}
    for s in SHARDS:
        try:
            data = open(shard_path(row["id"], s), "rb").read()
        except FileNotFoundError:
            continue
        if hashlib.sha256(data).hexdigest() == row[f"sha_{s.lower()}"]:
            good[s] = data
    return good


# ----------------------------------------------------------------- detection
def printable_ratio(data):
    if not data:
        return 1.0
    ok = sum(1 for b in data if b in (9, 10, 13) or 32 <= b < 127 or b >= 0xC2)
    return ok / len(data)


def inspect(prev_names, files):
    """Rename burst: many old names vanish and the same stems reappear with a new extension.
    Text check: CSV/TXT files whose bytes are no longer mostly printable."""
    reasons = []
    stems_new = {}
    for rel in files:
        stem, ext = os.path.splitext(rel)
        stems_new.setdefault(stem, set()).add(ext)
    renamed = [n for n in prev_names if n not in files and n in stems_new]
    if len(renamed) >= cfg()["rename_burst"]:
        reasons.append(f"rename burst: {len(renamed)} files got a new extension (e.g. {renamed[0]})")
    garbled = [rel for rel, data in files.items()
               if rel.lower().endswith((".csv", ".txt")) and len(data) > 256 and printable_ratio(data[:4096]) < 0.85]
    if len(garbled) >= cfg()["garbled_limit"]:
        reasons.append(f"{len(garbled)} text files are no longer readable text")
    if any("decrypt" in os.path.basename(r).lower() for r in files):
        reasons.append("ransom note found")
    return reasons


# ----------------------------------------------------------------- backup / restore
def collect():
    src = p(cfg()["source"])
    files = {}
    for root, dirs, names in os.walk(src):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for n in names:
            full = os.path.join(root, n)
            files[os.path.relpath(full, src).replace("\\", "/")] = open(full, "rb").read()
    return files


def last_good():
    with db() as con:
        return con.execute("SELECT * FROM backups WHERE state='ok' ORDER BY created DESC, id DESC LIMIT 1").fetchone()


def backup(who="scheduler"):
    t0 = time.time()
    files = collect()
    lg = last_good()
    prev_names = set(load_manifest(lg)) if lg else set()
    reasons = inspect(prev_names, files)
    bid = dt.datetime.now().strftime("%Y%m%d%H%M%S%f")
    if reasons:
        with db() as con:
            con.execute("INSERT INTO backups(id,created,files,state,reason,seconds) VALUES(?,?,?,?,?,?)",
                        (bid, stamp(), len(files), "refused", "; ".join(reasons), time.time() - t0))
        notice("critical", "Backup refused, possible ransomware: " + "; ".join(reasons))
        trail(who, "backup refused")
        return {"state": "refused", "reasons": reasons}
    buf = io.BytesIO()
    manifest = {rel: hashlib.sha256(d).hexdigest() for rel, d in files.items()}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rel, d in files.items():
            z.writestr(rel, d)
        z.writestr("__manifest__.json", json.dumps(manifest))
    nonce = os.urandom(12)
    blob = nonce + AESGCM(key()).encrypt(nonce, buf.getvalue(), bid.encode())
    shards = split(blob)
    for s, data in shards.items():
        open(shard_path(bid, s), "wb").write(data)
    secs = time.time() - t0
    with db() as con:
        con.execute("INSERT INTO backups VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (bid, stamp(), len(files), sum(map(len, files.values())), len(blob), secs, "ok", "",
                     *(hashlib.sha256(shards[s]).hexdigest() for s in SHARDS), len(blob)))
    trail(who, f"backup {bid}")
    return {"state": "ok", "id": bid, "files": len(files), "plain_bytes": sum(map(len, files.values())),
            "cipher_bytes": len(blob), "shard_bytes": len(shards["A"]), "seconds": round(secs, 3)}


def open_archive(row):
    shards = read_shards(row)
    if len(shards) < 2:
        raise ValueError(f"backup {row['id']}: only {len(shards)} healthy shard(s); need 2")
    blob = join(shards, row["length"])
    return zipfile.ZipFile(io.BytesIO(AESGCM(key()).decrypt(blob[:12], blob[12:], row["id"].encode())))


def load_manifest(row):
    with open_archive(row) as z:
        return json.loads(z.read("__manifest__.json"))


def restore(bid=None, target=None, who="admin"):
    t0 = time.time()
    with db() as con:
        row = con.execute("SELECT * FROM backups WHERE id=?", (bid,)).fetchone() if bid else last_good()
    target = target or p(cfg()["source"])
    with open_archive(row) as z:
        manifest = json.loads(z.read("__manifest__.json"))
        if os.path.isdir(target):
            for root, dirs, names in os.walk(target):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for n in names:
                    rel = os.path.relpath(os.path.join(root, n), target).replace("\\", "/")
                    if rel not in manifest:
                        os.remove(os.path.join(root, n))
        for rel, h in manifest.items():
            data = z.read(rel)
            if hashlib.sha256(data).hexdigest() != h:
                raise ValueError(f"{rel} failed SHA-256")
            out = os.path.join(target, *rel.split("/"))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            open(out, "wb").write(data)
    secs = time.time() - t0
    trail(who, f"restore {row['id']} in {secs:.2f}s")
    return {"id": row["id"], "files": len(manifest), "seconds": round(secs, 3),
            "shards_used": sorted(read_shards(row))}


def scrub():
    """Check every shard. Rebuild a missing or damaged shard from the other two."""
    out = {"healthy": 0, "rebuilt": [], "unrecoverable": []}
    with db() as con:
        rows = con.execute("SELECT * FROM backups WHERE state='ok'").fetchall()
    for r in rows:
        good = read_shards(r)
        if len(good) == 3:
            out["healthy"] += 1
            continue
        if len(good) < 2:
            out["unrecoverable"].append(r["id"])
            continue
        full = split(join(good, r["length"]))
        for s in SHARDS:
            if s not in good:
                os.makedirs(os.path.dirname(shard_path(r["id"], s)), exist_ok=True)
                open(shard_path(r["id"], s), "wb").write(full[s])
                out["rebuilt"].append(f"{r['id']}.{s}")
    if out["rebuilt"]:
        notice("warning", f"scrub rebuilt {len(out['rebuilt'])} shard(s) from parity")
    if out["unrecoverable"]:
        notice("critical", f"{len(out['unrecoverable'])} backups lost two sites")
    trail("system", f"scrub {out['healthy']} healthy, {len(out['rebuilt'])} rebuilt")
    return out


# ----------------------------------------------------------------- monitoring and SLA
def check_services():
    for s in cfg()["services"]:
        t0 = time.time()
        try:
            if s["kind"] == "http":
                urllib.request.urlopen(s["target"], timeout=3).close()
            else:
                h, port = s["target"].split(":")
                socket.create_connection((h, int(port)), timeout=3).close()
            up = 1
        except Exception:  # noqa: BLE001
            up = 0
        with db() as con:
            last = con.execute("SELECT up FROM checks WHERE service=? ORDER BY rowid DESC LIMIT 1",
                               (s["name"],)).fetchone()
            con.execute("INSERT INTO checks VALUES(?,?,?,?)", (stamp(), s["name"], up, (time.time() - t0) * 1000))
        if last is not None and last["up"] != up:
            notice("critical" if not up else "info", f"{s['name']} {'DOWN' if not up else 'restored'}")
        elif last is None and not up:
            notice("critical", f"{s['name']} DOWN")


def sla(hours=24):
    """Uptime percentage per service over the last N hours, compared with the target in config."""
    since = (dt.datetime.now() - dt.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    out = []
    with db() as con:
        for s in cfg()["services"]:
            r = con.execute("SELECT COUNT(*) n, SUM(up) u FROM checks WHERE service=? AND ts>=?",
                            (s["name"], since)).fetchone()
            pct = round(100 * (r["u"] or 0) / r["n"], 2) if r["n"] else None
            out.append({"service": s["name"], "uptime": pct, "target": s["sla"],
                        "met": pct is not None and pct >= s["sla"]})
    return out
