"""KanoShield: governance-first backup for Bayero University Kano.

* Backups live inside one SQLite "vault" database as AES-256-GCM encrypted rows.
* WORM retention: each backup has retain_until. SQLite triggers refuse UPDATE or DELETE
  on a locked backup, so even the application code cannot erase it early.
* Four-eyes rule: a restore over live data or an early release needs one admin to
  request it and a DIFFERENT admin to approve it.
* Admin sign-in needs a password AND a 6-digit TOTP code (RFC 6238, works with
  Google Authenticator or Microsoft Authenticator).
"""
import base64
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import shutil
import socket
import sqlite3
import struct
import time
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")


def cfg():
    return json.load(open(os.path.join(BASE, "config.json")))


def p(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ops():
    """Operational database: users, requests, alerts, monitoring."""
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "operations.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt TEXT, hash TEXT, role TEXT, totp TEXT);
    CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, at TEXT, kind TEXT, backup_id INT, requested_by TEXT,
        reason TEXT, status TEXT, decided_by TEXT, decided_at TEXT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, at TEXT, sev TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS logins(at REAL, user TEXT, ok INT, ip TEXT);
    CREATE TABLE IF NOT EXISTS status(name TEXT PRIMARY KEY, up INT, at TEXT);
    CREATE TABLE IF NOT EXISTS host(at TEXT, cpu REAL, mem REAL, disk REAL);
    """)
    return con


def vault():
    """The backup vault. Triggers enforce write-once-read-many retention."""
    os.makedirs(os.path.dirname(p(cfg()["vault_db"])), exist_ok=True)
    con = sqlite3.connect(p(cfg()["vault_db"]))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS backups(id INTEGER PRIMARY KEY, at TEXT, files INT, bytes INT, seconds REAL,
        retain_until TEXT, released INT DEFAULT 0, manifest BLOB, digest TEXT);
    CREATE TABLE IF NOT EXISTS blobs(backup_id INT, path TEXT, nonce BLOB, data BLOB, sha TEXT,
        PRIMARY KEY(backup_id, path));
    CREATE TRIGGER IF NOT EXISTS worm_no_update BEFORE UPDATE OF manifest, digest, at, files, retain_until ON backups
        BEGIN SELECT RAISE(ABORT, 'WORM: backups are write-once'); END;
    CREATE TRIGGER IF NOT EXISTS worm_no_delete BEFORE DELETE ON backups
        WHEN OLD.retain_until > datetime('now','localtime') AND OLD.released = 0
        BEGIN SELECT RAISE(ABORT, 'WORM: retention lock still active'); END;
    CREATE TRIGGER IF NOT EXISTS worm_blob_update BEFORE UPDATE ON blobs
        BEGIN SELECT RAISE(ABORT, 'WORM: blobs are write-once'); END;
    CREATE TRIGGER IF NOT EXISTS worm_blob_delete BEFORE DELETE ON blobs
        WHEN (SELECT retain_until > datetime('now','localtime') AND released = 0 FROM backups WHERE id = OLD.backup_id)
        BEGIN SELECT RAISE(ABORT, 'WORM: retention lock still active'); END;
    """)
    return con


def alert(sev, text):
    with ops() as con:
        con.execute("INSERT INTO alerts(at,sev,text) VALUES(?,?,?)", (now(), sev, text))
    print(f"[{sev}] {text}")


def key():
    return open(os.path.join(DATA, "keys", "vault.key"), "rb").read()


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    open(os.path.join(DATA, "keys", "vault.key"), "wb").write(os.urandom(32))
    vault().close()


# ----------------------------------------------------------------- TOTP (RFC 6238)
def new_totp_secret():
    return base64.b32encode(os.urandom(20)).decode()


def totp(secret, at=None, step=30, digits=6):
    counter = int((at or time.time()) // step)
    mac = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return f"{code:0{digits}d}"


def totp_ok(secret, code):
    return any(hmac.compare_digest(totp(secret, time.time() + d * 30), str(code).strip()) for d in (-1, 0, 1))


def otpauth_uri(user, secret):
    return f"otpauth://totp/KanoShield:{user}?secret={secret}&issuer=KanoShield"


# ----------------------------------------------------------------- users
def add_user(name, pw, role):
    salt = os.urandom(16).hex()
    h = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1).hex()
    secret = new_totp_secret() if role == "admin" else None
    with ops() as con:
        con.execute("INSERT OR REPLACE INTO users VALUES(?,?,?,?,?)", (name, salt, h, role, secret))
    return secret


def authenticate(name, pw, code, ip="local"):
    """Return the role, or None. Records every attempt and raises a brute-force alert."""
    with ops() as con:
        u = con.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
        recent = con.execute("SELECT COUNT(*) n FROM logins WHERE ok=0 AND at>? AND (user=? OR ip=?)",
                             (time.time() - 900, name, ip)).fetchone()["n"]
    if recent >= cfg()["max_failed_logins"]:
        return None
    ok = False
    if u:
        h = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(u["salt"]), n=2 ** 14, r=8, p=1).hex()
        ok = hmac.compare_digest(h, u["hash"]) and (u["totp"] is None or totp_ok(u["totp"], code))
    with ops() as con:
        con.execute("INSERT INTO logins VALUES(?,?,?,?)", (time.time(), name, int(ok), ip))
    if not ok and recent + 1 >= cfg()["max_failed_logins"]:
        alert("critical", f"possible brute force on '{name}' from {ip}: login locked for 15 minutes")
    return u["role"] if ok else None


# ----------------------------------------------------------------- backup
def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in (b.count(bytes([i])) for i in range(256)) if c)


def gather():
    src = p(cfg()["source"])
    out = {}
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            full = os.path.join(root, f)
            out[os.path.relpath(full, src).replace("\\", "/")] = open(full, "rb").read()
    return out


def backup(actor="scheduler"):
    t0 = time.time()
    files = gather()
    c = cfg()
    hot = [r for r, d in files.items() if len(d) > 1024 and entropy(d[:8192]) > c["entropy_limit"]
           and not r.lower().endswith((".zip", ".jpg", ".png", ".pdf", ".docx", ".xlsx"))]
    ext = [r for r in files if r.lower().endswith(tuple(c["blocked_extensions"]))]
    if len(hot) + len(ext) >= c["suspicious_limit"]:
        alert("critical", f"backup BLOCKED: {len(hot)} high-entropy and {len(ext)} ransomware-named files")
        return {"status": "blocked", "high_entropy": len(hot), "bad_extension": len(ext)}
    aes = AESGCM(key())
    manifest = {r: hashlib.sha256(d).hexdigest() for r, d in files.items()}
    retain = (dt.datetime.now() + dt.timedelta(days=c["retention_days"])).strftime("%Y-%m-%d %H:%M:%S")
    raw_manifest = json.dumps(manifest, sort_keys=True).encode()
    with vault() as v:
        cur = v.execute("INSERT INTO backups(at,files,bytes,seconds,retain_until,manifest,digest) VALUES(?,?,?,?,?,?,?)",
                        (now(), len(files), sum(map(len, files.values())), 0, retain, raw_manifest,
                         hmac.new(key(), raw_manifest, "sha256").hexdigest()))
        bid = cur.lastrowid
        for rel, d in files.items():
            n = os.urandom(12)
            v.execute("INSERT INTO blobs VALUES(?,?,?,?,?)",
                      (bid, rel, n, aes.encrypt(n, d, f"{bid}:{rel}".encode()), manifest[rel]))
    secs = time.time() - t0
    alert("info", f"backup {bid} sealed by {actor}: {len(files)} files, locked until {retain}")
    return {"status": "ok", "id": bid, "files": len(files), "bytes": sum(map(len, files.values())),
            "seconds": round(secs, 3), "retain_until": retain}


def latest():
    with vault() as v:
        return v.execute("SELECT id FROM backups ORDER BY id DESC LIMIT 1").fetchone()["id"]


def restore(bid, target=None):
    t0 = time.time()
    aes = AESGCM(key())
    with vault() as v:
        b = v.execute("SELECT * FROM backups WHERE id=?", (bid,)).fetchone()
        if not hmac.compare_digest(hmac.new(key(), b["manifest"], "sha256").hexdigest(), b["digest"]):
            raise ValueError("manifest seal broken")
        manifest = json.loads(b["manifest"])
        rows = {r["path"]: r for r in v.execute("SELECT * FROM blobs WHERE backup_id=?", (bid,))}
    target = target or p(cfg()["source"])
    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), target).replace("\\", "/")
                if rel not in manifest:
                    os.remove(os.path.join(root, f))
    for rel, h in manifest.items():
        r = rows[rel]
        d = aes.decrypt(r["nonce"], r["data"], f"{bid}:{rel}".encode())
        if hashlib.sha256(d).hexdigest() != h:
            raise ValueError(f"{rel} failed SHA-256")
        out = os.path.join(target, *rel.split("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        open(out, "wb").write(d)
    return {"id": bid, "files": len(manifest), "seconds": round(time.time() - t0, 3)}


def verify():
    aes = AESGCM(key())
    bad, n = [], 0
    with vault() as v:
        for b in v.execute("SELECT * FROM backups"):
            if not hmac.compare_digest(hmac.new(key(), b["manifest"], "sha256").hexdigest(), b["digest"]):
                bad.append(f"backup {b['id']} manifest")
        for r in v.execute("SELECT * FROM blobs"):
            n += 1
            try:
                if hashlib.sha256(aes.decrypt(r["nonce"], r["data"], f"{r['backup_id']}:{r['path']}".encode())
                                  ).hexdigest() != r["sha"]:
                    bad.append(f"{r['backup_id']}:{r['path']}")
            except Exception:  # noqa: BLE001
                bad.append(f"{r['backup_id']}:{r['path']}")
    if bad:
        alert("critical", f"vault verification found {len(bad)} problems")
    return {"blobs_checked": n, "problems": bad}


def replicate():
    """Copy the vault database to the offline/offsite locations using SQLite's online backup API."""
    out = []
    for dest in cfg()["vault_copies"]:
        os.makedirs(os.path.dirname(p(dest)), exist_ok=True)
        with vault() as src, sqlite3.connect(p(dest)) as dst:
            src.backup(dst)
        out.append(dest)
    return out


# ----------------------------------------------------------------- four-eyes workflow
def request_action(kind, bid, who, reason):
    with ops() as con:
        cur = con.execute("INSERT INTO requests(at,kind,backup_id,requested_by,reason,status) VALUES(?,?,?,?,?,?)",
                          (now(), kind, bid, who, reason, "pending"))
    alert("warning", f"{who} requested {kind} of backup {bid}: {reason}. Needs a second admin.")
    return cur.lastrowid


def decide(req_id, who, approve):
    with ops() as con:
        r = con.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
        role = con.execute("SELECT role FROM users WHERE name=?", (who,)).fetchone()
    if not r or r["status"] != "pending":
        return {"error": "no such pending request"}
    if not role or role["role"] != "admin":
        return {"error": "only an admin can decide"}
    if who == r["requested_by"]:
        alert("critical", f"{who} tried to approve their own {r['kind']} request")
        return {"error": "four-eyes rule: the requester cannot approve"}
    with ops() as con:
        con.execute("UPDATE requests SET status=?, decided_by=?, decided_at=? WHERE id=?",
                    ("approved" if approve else "rejected", who, now(), req_id))
    if not approve:
        return {"status": "rejected"}
    if r["kind"] == "restore":
        res = restore(r["backup_id"])
    else:  # early release of a retention lock (for example a court order or a data-subject erasure)
        with vault() as v:
            v.execute("UPDATE backups SET released=1 WHERE id=?", (r["backup_id"],))
        res = {"released": r["backup_id"]}
    alert("info", f"{r['kind']} of backup {r['backup_id']} approved by {who} (requested by {r['requested_by']})")
    return {"status": "approved", "result": res}


def try_delete(bid):
    try:
        with vault() as v:
            v.execute("DELETE FROM blobs WHERE backup_id=?", (bid,))
            v.execute("DELETE FROM backups WHERE id=?", (bid,))
        return "deleted"
    except sqlite3.DatabaseError as exc:
        return str(exc)


# ----------------------------------------------------------------- monitoring
def watch():
    c = cfg()
    try:
        import psutil
        cpu, mem = psutil.cpu_percent(interval=0.3), psutil.virtual_memory().percent
    except ImportError:
        cpu = mem = 0.0
    du = shutil.disk_usage(BASE)
    with ops() as con:
        con.execute("INSERT INTO host VALUES(?,?,?,?)", (now(), cpu, mem, round(du.used / du.total * 100, 1)))
    for name, target in c["services"].items():
        try:
            if target.startswith("http"):
                urllib.request.urlopen(target, timeout=3).close()
            else:
                hst, port = target.split(":")
                socket.create_connection((hst, int(port)), timeout=3).close()
            up = 1
        except Exception:  # noqa: BLE001
            up = 0
        with ops() as con:
            old = con.execute("SELECT up FROM status WHERE name=?", (name,)).fetchone()
            con.execute("INSERT OR REPLACE INTO status VALUES(?,?,?)", (name, up, now()))
        if (old is None and not up) or (old is not None and old["up"] != up):
            alert("critical" if not up else "info", f"{name} {'DOWN' if not up else 'UP'}")
