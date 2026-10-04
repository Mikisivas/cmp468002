"""ZariaSafe core: versioned-mirror backup, mass-change ransomware detector,
host and service monitoring, and a signed audit trail.

Design (different from a chunk store): every backup run is a "version folder".
Only files whose SHA-256 changed since the previous version are copied into the
new version, each sealed with AES-256-GCM. A manifest lists every file of the
version (changed or inherited) and is signed with HMAC-SHA256, so a restore can
rebuild any point in time and detect any edited manifest or object.
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import shutil
import socket
import sqlite3
import time
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
KEYFILE = os.path.join(DATA, "keys", "master.key")
RANSOM_EXT = {".locked", ".encrypted", ".crypt", ".enc", ".wncry", ".lockbit", ".zzz"}
NOTE_HINTS = ("readme_to_decrypt", "read_me_to_decrypt", "how_to_recover", "decrypt_instructions", "restore_files")


def load_config():
    with open(os.path.join(BASE, "config.json")) as fh:
        return json.load(fh)


def path(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ----------------------------------------------------------------- storage
def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "zariasafe.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS versions(id TEXT PRIMARY KEY, created TEXT, files INT, changed INT,
        bytes_in INT, bytes_stored INT, seconds REAL, status TEXT, note TEXT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts TEXT, level TEXT, source TEXT, message TEXT);
    CREATE TABLE IF NOT EXISTS metrics(ts TEXT, cpu REAL, mem REAL, disk REAL);
    CREATE TABLE IF NOT EXISTS services(name TEXT PRIMARY KEY, status TEXT, checked TEXT, latency_ms REAL);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, action TEXT, detail TEXT,
        sig TEXT);
    CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt TEXT, hash TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS drills(ts TEXT, rto_s REAL, files INT, identical INT);
    """)
    return con


def master_key():
    with open(KEYFILE, "rb") as fh:
        return fh.read()


def subkey(label):
    return hmac.new(master_key(), label.encode(), hashlib.sha256).digest()


def alert(level, source, message):
    with db() as con:
        con.execute("INSERT INTO alerts(ts,level,source,message) VALUES(?,?,?,?)", (now(), level, source, message))
    print(f"[{level.upper()}] {source}: {message}")


def audit(actor, action, detail=""):
    """Each audit row is signed with an HMAC over its content AND the previous signature,
    so deleting or editing a row breaks every signature after it."""
    with db() as con:
        prev = con.execute("SELECT sig FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = prev["sig"] if prev else "GENESIS"
        ts = now()
        sig = hmac.new(subkey("audit"), f"{prev}|{ts}|{actor}|{action}|{detail}".encode(), "sha256").hexdigest()
        con.execute("INSERT INTO audit(ts,actor,action,detail,sig) VALUES(?,?,?,?,?)", (ts, actor, action, detail, sig))


def audit_ok():
    prev = "GENESIS"
    with db() as con:
        for r in con.execute("SELECT * FROM audit ORDER BY id"):
            exp = hmac.new(subkey("audit"), f"{prev}|{r['ts']}|{r['actor']}|{r['action']}|{r['detail']}".encode(),
                           "sha256").hexdigest()
            if not hmac.compare_digest(exp, r["sig"]):
                return False, r["id"]
            prev = r["sig"]
    return True, None


# ----------------------------------------------------------------- users
def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16).hex()
    return salt, hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 310_000).hex()


def add_user(name, pw, role):
    salt, h = hash_pw(pw)
    with db() as con:
        con.execute("INSERT OR REPLACE INTO users VALUES(?,?,?,?)", (name, salt, h, role))


def check_user(name, pw):
    with db() as con:
        r = con.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
    if not r:
        hash_pw(pw)  # same cost for unknown users, so timing does not reveal valid names
        return None
    return r["role"] if hmac.compare_digest(hash_pw(pw, r["salt"])[1], r["hash"]) else None


# ----------------------------------------------------------------- setup
def init(admin_pw="ChangeMe@468"):
    cfg = load_config()
    os.makedirs(os.path.dirname(KEYFILE), exist_ok=True)
    if not os.path.exists(KEYFILE):
        with open(KEYFILE, "wb") as fh:
            fh.write(os.urandom(32))
    os.makedirs(path(cfg["vault"]), exist_ok=True)
    add_user("admin", admin_pw, "admin")
    add_user("auditor", admin_pw, "viewer")
    audit("system", "init", "keys and users created")


# ----------------------------------------------------------------- scanning
def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def scan(source):
    out = {}
    for root, dirs, files in os.walk(source):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            p = os.path.join(root, f)
            st = os.stat(p)
            out[os.path.relpath(p, source).replace("\\", "/")] = {"size": st.st_size, "mtime": st.st_mtime}
    return out


# ----------------------------------------------------------------- versions
def vault():
    return path(load_config()["vault"])


def sign_manifest(m):
    body = json.dumps(m["files"], sort_keys=True).encode()
    return hmac.new(subkey("manifest"), body + m["id"].encode() + str(m["parent"]).encode(), "sha256").hexdigest()


def read_manifest(vid):
    with open(os.path.join(vault(), vid, "manifest.json")) as fh:
        m = json.load(fh)
    if not hmac.compare_digest(sign_manifest(m), m["sig"]):
        raise ValueError(f"manifest of {vid} has been altered")
    return m


def last_version():
    with db() as con:
        r = con.execute("SELECT id FROM versions WHERE status='ok' ORDER BY id DESC LIMIT 1").fetchone()
    return r["id"] if r else None


def detect_ransomware(prev, cur, source, cfg):
    """Mass-change detector. Looks at the run as a whole instead of file by file."""
    reasons = []
    names = [os.path.basename(k).lower() for k in cur]
    bad_ext = [k for k in cur if os.path.splitext(k)[1].lower() in RANSOM_EXT]
    if bad_ext:
        reasons.append(f"{len(bad_ext)} files with ransomware extensions (e.g. {bad_ext[0]})")
    if any(any(h in n for h in NOTE_HINTS) for n in names):
        reasons.append("ransom note file present")
    if prev:
        common = set(prev) & set(cur)
        changed = [k for k in common if cur[k]["sha"] != prev[k]["sha"]]
        deleted = set(prev) - set(cur)
        ratio = (len(changed) + len(deleted)) / max(1, len(prev))
        if ratio >= cfg["detector"]["max_change_ratio"] and len(prev) >= 5:
            reasons.append(f"{ratio:.0%} of protected files changed or vanished in one interval")
    return reasons


def backup(actor="scheduler", force=False):
    cfg = load_config()
    source = path(cfg["source"])
    t0 = time.time()
    parent = last_version()
    prev = read_manifest(parent)["files"] if parent else {}
    cur = scan(source)
    for k, meta in cur.items():
        meta["sha"] = sha256_file(os.path.join(source, k))
    reasons = detect_ransomware(prev, cur, source, cfg)
    vid = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    if reasons and not force:
        with db() as con:
            con.execute("INSERT INTO versions VALUES(?,?,?,?,?,?,?,?,?)",
                        (vid, now(), len(cur), 0, 0, 0, time.time() - t0, "held", "; ".join(reasons)))
        alert("critical", "ransomware-detector", "Backup HELD, history protected: " + "; ".join(reasons))
        audit(actor, "backup-held", "; ".join(reasons))
        return {"status": "held", "reasons": reasons}
    vdir = os.path.join(vault(), vid)
    os.makedirs(os.path.join(vdir, "objects"))
    aes = AESGCM(subkey("data"))
    files, changed, bytes_in, stored = {}, 0, 0, 0
    for k, meta in cur.items():
        p = prev.get(k)
        if p and p["sha"] == meta["sha"]:
            files[k] = {**meta, "in": p["in"]}  # inherited from an older version
            continue
        with open(os.path.join(source, k), "rb") as fh:
            raw = fh.read()
        nonce = os.urandom(12)
        blob = nonce + aes.encrypt(nonce, raw, k.encode())  # file path is bound as associated data
        obj = hashlib.sha256(k.encode()).hexdigest()[:32]
        with open(os.path.join(vdir, "objects", obj), "wb") as fh:
            fh.write(blob)
        files[k] = {**meta, "in": vid}
        changed += 1
        bytes_in += len(raw)
        stored += len(blob)
    m = {"id": vid, "parent": parent, "created": now(), "files": files}
    m["sig"] = sign_manifest(m)
    with open(os.path.join(vdir, "manifest.json"), "w") as fh:
        json.dump(m, fh, indent=1)
    secs = time.time() - t0
    with db() as con:
        con.execute("INSERT INTO versions VALUES(?,?,?,?,?,?,?,?,?)",
                    (vid, now(), len(files), changed, bytes_in, stored, secs, "ok", ""))
    replicate(vid)
    audit(actor, "backup", f"{vid} changed={changed}")
    return {"status": "ok", "version": vid, "files": len(files), "changed": changed, "seconds": round(secs, 3),
            "bytes_in": bytes_in, "bytes_stored": stored}


def replicate(vid):
    for rep in load_config()["replicas"]:
        dst = os.path.join(path(rep), vid)
        if not os.path.exists(dst):
            shutil.copytree(os.path.join(vault(), vid), dst)


def object_path(k, vid, base=None):
    return os.path.join(base or vault(), vid, "objects", hashlib.sha256(k.encode()).hexdigest()[:32])


def verify(repair=True):
    """Decrypt every object of every version. GCM fails on any flipped bit."""
    aes = AESGCM(subkey("data"))
    bad, fixed, checked = [], [], 0
    for vid in sorted(os.listdir(vault())):
        try:
            m = read_manifest(vid)
        except Exception as exc:  # noqa: BLE001
            bad.append(f"{vid}: {exc}")
            continue
        for k, meta in m["files"].items():
            if meta["in"] != vid:
                continue
            checked += 1
            op = object_path(k, vid)
            try:
                with open(op, "rb") as fh:
                    blob = fh.read()
                aes.decrypt(blob[:12], blob[12:], k.encode())
            except Exception:  # noqa: BLE001
                ok = False
                if repair:
                    for rep in load_config()["replicas"]:
                        rp = object_path(k, vid, path(rep))
                        if os.path.exists(rp):
                            shutil.copyfile(rp, op)
                            ok = True
                            break
                (fixed if ok else bad).append(f"{vid}:{k}")
    if bad:
        alert("critical", "verify", f"{len(bad)} damaged objects could not be repaired")
    audit("system", "verify", f"checked={checked} fixed={len(fixed)} bad={len(bad)}")
    return {"checked": checked, "repaired": fixed, "bad": bad}


def restore(vid=None, target=None, actor="admin", clean=True):
    cfg = load_config()
    vid = vid or last_version()
    target = target or path(cfg["source"])
    t0 = time.time()
    m = read_manifest(vid)
    aes = AESGCM(subkey("data"))
    if clean and os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), target).replace("\\", "/")
                if rel not in m["files"]:
                    os.remove(os.path.join(root, f))  # remove ransom notes and .locked leftovers
    for k, meta in m["files"].items():
        with open(object_path(k, meta["in"]), "rb") as fh:
            blob = fh.read()
        raw = aes.decrypt(blob[:12], blob[12:], k.encode())
        out = os.path.join(target, *k.split("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(raw)
    secs = time.time() - t0
    audit(actor, "restore", f"{vid} -> {target} in {secs:.2f}s")
    return {"version": vid, "files": len(m["files"]), "seconds": round(secs, 3)}


def prune(keep):
    with db() as con:
        ids = [r["id"] for r in con.execute("SELECT id FROM versions WHERE status='ok' ORDER BY id DESC")]
    needed = set()
    for vid in ids[:keep]:
        needed |= {meta["in"] for meta in read_manifest(vid)["files"].values()}
        needed.add(vid)
    removed = [v for v in ids[keep:] if v not in needed]
    for vid in removed:
        shutil.rmtree(os.path.join(vault(), vid), ignore_errors=True)
        with db() as con:
            con.execute("DELETE FROM versions WHERE id=?", (vid,))
    audit("system", "prune", f"removed={len(removed)}")
    return removed


# ----------------------------------------------------------------- monitoring
def metrics():
    try:
        import psutil
        cpu, mem = psutil.cpu_percent(interval=0.3), psutil.virtual_memory().percent
    except ImportError:
        cpu = mem = 0.0
    du = shutil.disk_usage(BASE)
    return {"cpu": cpu, "mem": mem, "disk": round(du.used / du.total * 100, 1)}


def check_service(s):
    t0 = time.time()
    try:
        if s["type"] == "http":
            with urllib.request.urlopen(s["url"], timeout=3) as r:
                ok = r.status == 200
        else:
            with socket.create_connection((s["host"], s["port"]), timeout=3):
                ok = True
    except Exception:  # noqa: BLE001
        ok = False
    return ok, (time.time() - t0) * 1000


def monitor_once():
    cfg = load_config()
    m = metrics()
    with db() as con:
        con.execute("INSERT INTO metrics VALUES(?,?,?,?)", (now(), m["cpu"], m["mem"], m["disk"]))
    for key, limit in cfg["thresholds"].items():
        if m.get(key, 0) > limit:
            alert("warning", "host", f"{key} at {m[key]}% (limit {limit}%)")
    for s in cfg["services"]:
        ok, ms = check_service(s)
        with db() as con:
            old = con.execute("SELECT status FROM services WHERE name=?", (s["name"],)).fetchone()
            con.execute("INSERT OR REPLACE INTO services VALUES(?,?,?,?)", (s["name"], "UP" if ok else "DOWN",
                                                                           now(), round(ms, 1)))
        if not ok and (not old or old["status"] == "UP"):
            alert("critical", "service", f"{s['name']} is DOWN")
        if ok and old and old["status"] == "DOWN":
            alert("info", "service", f"{s['name']} recovered")
    with db() as con:
        last = con.execute("SELECT created FROM versions WHERE status='ok' ORDER BY id DESC LIMIT 1").fetchone()
    if last:
        age = (dt.datetime.now() - dt.datetime.strptime(last["created"], "%Y-%m-%d %H:%M:%S")).total_seconds() / 60
        if age > cfg["rpo_minutes"]:
            alert("warning", "rpo", f"last good backup is {age:.0f} min old (RPO {cfg['rpo_minutes']} min)")
    return m
