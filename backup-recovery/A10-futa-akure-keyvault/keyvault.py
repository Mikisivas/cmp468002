"""AkureKeyVault: split-key, envelope-encrypted backups for FUTA.

Key design
* Recovery key pair (X25519). Backups need only the PUBLIC key, so the scheduler runs
  unattended and a stolen backup server cannot decrypt anything.
* Each backup gets a fresh 256-bit data key (DEK). The archive is sealed with AES-256-GCM
  under the DEK. The DEK is wrapped for the recovery public key (ephemeral X25519 ECDH +
  HKDF-SHA256 + AES-GCM), which is the "envelope".
* The recovery PRIVATE key is never stored whole. It is split with Shamir's Secret Sharing
  (2 of 3) into shares for the Registrar, the Bursar and the ICT Director. Any two can unlock
  a restore. One share alone reveals nothing.
* Key rotation re-wraps every DEK for a new key pair without touching the archives.
* Crypto-shredding: destroying one backup's wrapped DEK makes that backup unreadable forever
  (useful for an NDPA erasure request), without rewriting any storage media.
"""
import datetime as dt
import hashlib
import io
import json
import math
import os
import secrets
import shutil
import socket
import sqlite3
import time
import urllib.request
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
PRIME = 2 ** 521 - 1  # Mersenne prime, larger than any 32-byte secret
CUSTODIANS = ["registrar", "bursar", "ict_director"]


def cfg():
    return json.load(open(os.path.join(BASE, "config.json")))


def p(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "keyvault.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS keys(version INTEGER PRIMARY KEY, created TEXT, public TEXT, fingerprint TEXT, active INT);
    CREATE TABLE IF NOT EXISTS backups(id INTEGER PRIMARY KEY, at TEXT, files INT, plain INT, stored INT, seconds REAL,
        file TEXT, sha TEXT, wrapped TEXT, key_version INT, shredded INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS ceremonies(id INTEGER PRIMARY KEY, at TEXT, custodians TEXT, purpose TEXT, ok INT);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, at TEXT, sev TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS health(name TEXT PRIMARY KEY, up INT, at TEXT);
    CREATE TABLE IF NOT EXISTS host(at TEXT, cpu REAL, mem REAL, disk REAL);
    CREATE TABLE IF NOT EXISTS operators(name TEXT PRIMARY KEY, salt TEXT, hash TEXT, role TEXT);
    """)
    return con


def event(sev, text):
    with db() as con:
        con.execute("INSERT INTO events(at,sev,text) VALUES(?,?,?)", (now(), sev, text))
    print(f"[{sev}] {text}")


# ----------------------------------------------------------------- Shamir secret sharing
def _eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % PRIME
    return acc


def split_secret(secret: bytes, n=3, k=2):
    s = int.from_bytes(secret, "big")
    coeffs = [s] + [secrets.randbelow(PRIME) for _ in range(k - 1)]
    return [(x, _eval(coeffs, x)) for x in range(1, n + 1)]


def combine(shares, length=32):
    """Lagrange interpolation at x = 0."""
    total = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = num * (-xj) % PRIME
                den = den * (xi - xj) % PRIME
        total = (total + yi * num * pow(den, -1, PRIME)) % PRIME
    if total >= 1 << (8 * length):
        raise ValueError("shares do not rebuild a valid key")
    return total.to_bytes(length, "big")


def encode_share(version, x, y):
    body = f"AKV{version}-{x}-{y:0132x}"
    return body + "-" + hashlib.sha256(body.encode()).hexdigest()[:6]


def decode_share(text):
    text = text.strip()
    body, chk = text.rsplit("-", 1)
    if hashlib.sha256(body.encode()).hexdigest()[:6] != chk:
        raise ValueError("share checksum wrong (typing mistake?)")
    tag, x, y = body.split("-")
    return int(tag[3:]), int(x), int(y, 16)


# ----------------------------------------------------------------- keys
def new_keypair(version):
    sk = X25519PrivateKey.generate()
    raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shares = {c: encode_share(version, x, y) for c, (x, y) in zip(CUSTODIANS, split_secret(raw))}
    with db() as con:
        con.execute("UPDATE keys SET active=0")
        con.execute("INSERT INTO keys VALUES(?,?,?,?,1)", (version, now(), pub.hex(), hashlib.sha256(pub).hexdigest()[:16]))
    # demo only: in real use print each share, hand it over in a sealed envelope, then delete these files
    os.makedirs(os.path.join(DATA, "shares_to_print"), exist_ok=True)
    for c, s in shares.items():
        open(os.path.join(DATA, "shares_to_print", f"{c}_v{version}.txt"), "w").write(s + "\n")
    return shares


def active_key():
    with db() as con:
        return con.execute("SELECT * FROM keys WHERE active=1").fetchone()


def unlock(share_texts, purpose):
    """Rebuild the private key from any 2 shares and check it against the stored public key."""
    parts = [decode_share(t) for t in share_texts]
    versions = {v for v, _, _ in parts}
    if len(parts) < 2 or len(versions) != 1 or len({x for _, x, _ in parts}) < 2:
        raise ValueError("need two different shares of the same key version")
    version = versions.pop()
    try:
        sk = X25519PrivateKey.from_private_bytes(combine([(x, y) for _, x, y in parts]))
        pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    except ValueError:
        pub = None
    with db() as con:
        row = con.execute("SELECT public FROM keys WHERE version=?", (version,)).fetchone()
        ok = bool(row) and row["public"] == pub
        con.execute("INSERT INTO ceremonies(at,custodians,purpose,ok) VALUES(?,?,?,?)",
                    (now(), ",".join(str(x) for _, x, _ in parts), purpose, int(ok)))
    if not ok:
        event("critical", "unlock ceremony failed: shares do not rebuild the recovery key")
        raise ValueError("shares do not match the recovery key")
    event("warning", f"recovery key v{version} unlocked by custodians {[x for _, x, _ in parts]} for: {purpose}")
    return version, sk


def wrap(dek, pub_hex):
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)))
    kek = HKDF(hashes.SHA256(), 32, None, b"AkureKeyVault wrap").derive(shared)
    n = os.urandom(12)
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return (eph_pub + n + AESGCM(kek).encrypt(n, dek, eph_pub)).hex()


def unwrap(wrapped_hex, sk):
    w = bytes.fromhex(wrapped_hex)
    eph_pub, n, ct = w[:32], w[32:44], w[44:]
    shared = sk.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    kek = HKDF(hashes.SHA256(), 32, None, b"AkureKeyVault wrap").derive(shared)
    return AESGCM(kek).decrypt(n, ct, eph_pub)


# ----------------------------------------------------------------- backup
def entropy(b):
    if not b:
        return 0.0
    counts = {}
    for x in b:
        counts[x] = counts.get(x, 0) + 1
    return -sum(c / len(b) * math.log2(c / len(b)) for c in counts.values())


def screen(files):
    c = cfg()
    bad = [r for r in files if r.lower().endswith(tuple(c["blocked_extensions"]))]
    hot = [r for r, d in files.items() if r.lower().endswith((".csv", ".txt")) and len(d) > 1024
           and entropy(d[:4096]) > c["entropy_limit"]]
    return bad, hot


def backup(who="scheduler"):
    t0 = time.time()
    src = p(cfg()["source"])
    files = {}
    for root, dirs, names in os.walk(src):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for n in names:
            full = os.path.join(root, n)
            files[os.path.relpath(full, src).replace("\\", "/")] = open(full, "rb").read()
    bad, hot = screen(files)
    if len(bad) + len(hot) >= cfg()["suspicious_limit"]:
        event("critical", f"backup stopped: {len(bad)} ransomware-named and {len(hot)} encrypted-looking files")
        return {"status": "stopped", "bad_ext": len(bad), "high_entropy": len(hot)}
    buf = io.BytesIO()
    manifest = {r: hashlib.sha256(d).hexdigest() for r, d in files.items()}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r, d in files.items():
            z.writestr(r, d)
        z.writestr("__manifest__.json", json.dumps(manifest))
    dek = AESGCM.generate_key(256)
    key = active_key()
    n = os.urandom(12)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    blob = n + AESGCM(dek).encrypt(n, buf.getvalue(), stamp.encode())
    name = f"{stamp}.akv"
    for d in [cfg()["store"]] + cfg()["copies"]:
        os.makedirs(p(d), exist_ok=True)
        open(os.path.join(p(d), name), "wb").write(blob)
    secs = time.time() - t0
    with db() as con:
        cur = con.execute("INSERT INTO backups(at,files,plain,stored,seconds,file,sha,wrapped,key_version) "
                          "VALUES(?,?,?,?,?,?,?,?,?)", (now(), len(files), sum(map(len, files.values())), len(blob),
                                                        secs, name, hashlib.sha256(blob).hexdigest(),
                                                        wrap(dek, key["public"]), key["version"]))
    del dek
    event("info", f"backup {cur.lastrowid} sealed for key v{key['version']} ({len(files)} files)")
    return {"status": "ok", "id": cur.lastrowid, "files": len(files), "plain_bytes": sum(map(len, files.values())),
            "stored_bytes": len(blob), "seconds": round(secs, 3), "key_version": key["version"]}


def _archive(b):
    for d in [cfg()["store"]] + cfg()["copies"]:
        path = os.path.join(p(d), b["file"])
        if os.path.exists(path):
            blob = open(path, "rb").read()
            if hashlib.sha256(blob).hexdigest() == b["sha"]:
                return blob
    raise ValueError(f"no intact copy of backup {b['id']}")


def restore(share_texts, bid=None, target=None):
    t0 = time.time()
    with db() as con:
        b = (con.execute("SELECT * FROM backups WHERE id=?", (bid,)).fetchone() if bid else
             con.execute("SELECT * FROM backups WHERE shredded=0 ORDER BY id DESC LIMIT 1").fetchone())
    if b["shredded"]:
        raise ValueError(f"backup {b['id']} was crypto-shredded and can never be read again")
    version, sk = unlock(share_texts, f"restore backup {b['id']}")
    if version != b["key_version"]:
        raise ValueError(f"backup {b['id']} is wrapped for key v{b['key_version']}, shares are for v{version}")
    dek = unwrap(b["wrapped"], sk)
    blob = _archive(b)
    stamp = b["file"].rsplit(".", 1)[0]
    with zipfile.ZipFile(io.BytesIO(AESGCM(dek).decrypt(blob[:12], blob[12:], stamp.encode()))) as z:
        manifest = json.loads(z.read("__manifest__.json"))
        target = target or p(cfg()["source"])
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
    event("info", f"backup {b['id']} restored in {secs:.2f}s")
    return {"id": b["id"], "files": len(manifest), "seconds": round(secs, 3)}


def rotate(share_texts):
    """New key pair and new shares. Every DEK is re-wrapped. Archives are not touched."""
    version, sk = unlock(share_texts, "key rotation")
    new_version = version + 1
    shares = new_keypair(new_version)
    pub = active_key()["public"]
    n = 0
    with db() as con:
        for b in con.execute("SELECT * FROM backups WHERE shredded=0 AND key_version=?", (version,)).fetchall():
            con.execute("UPDATE backups SET wrapped=?, key_version=? WHERE id=?",
                        (wrap(unwrap(b["wrapped"], sk), pub), new_version, b["id"]))
            n += 1
    event("warning", f"recovery key rotated v{version} -> v{new_version}; {n} data keys re-wrapped; old shares void")
    return {"new_version": new_version, "rewrapped": n, "shares": shares}


def shred(bid, reason):
    with db() as con:
        con.execute("UPDATE backups SET wrapped='', shredded=1 WHERE id=?", (bid,))
    event("warning", f"backup {bid} crypto-shredded: {reason}")
    return {"shredded": bid}


def verify():
    out = {"ok": 0, "bad": []}
    with db() as con:
        rows = con.execute("SELECT * FROM backups").fetchall()
    for b in rows:
        try:
            _archive(b)
            out["ok"] += 1
        except ValueError:
            out["bad"].append(b["id"])
    return out


def watch():
    try:
        import psutil
        cpu, mem = psutil.cpu_percent(interval=0.3), psutil.virtual_memory().percent
    except ImportError:
        cpu = mem = 0.0
    du = shutil.disk_usage(BASE)
    with db() as con:
        con.execute("INSERT INTO host VALUES(?,?,?,?)", (now(), cpu, mem, round(du.used / du.total * 100, 1)))
    for name, target in cfg()["services"].items():
        try:
            if target.startswith("http"):
                urllib.request.urlopen(target, timeout=3).close()
            else:
                h, port = target.split(":")
                socket.create_connection((h, int(port)), timeout=3).close()
            up = 1
        except Exception:  # noqa: BLE001
            up = 0
        with db() as con:
            old = con.execute("SELECT up FROM health WHERE name=?", (name,)).fetchone()
            con.execute("INSERT OR REPLACE INTO health VALUES(?,?,?)", (name, up, now()))
        if (old is None and not up) or (old is not None and old["up"] != up):
            event("critical" if not up else "info", f"{name} {'DOWN' if not up else 'UP'}")
