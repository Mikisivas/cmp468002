"""HarmonyVault: Git-style backup history with Ed25519-signed commits.

Objects (all AES-256-GCM encrypted, stored under their keyed hash):
    blob   = file content
    tree   = {path: blob_id}
    commit = {tree, parent, time, author, message, stats}
Each commit is signed with the backup server's Ed25519 private key. Verifying the chain
from HEAD to the first commit proves no backup was inserted, removed or edited.
Detection: change-rate anomaly (z-score of changed files against past commits) and
honey directories full of attractive decoy files.
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import sqlite3
import statistics
import time
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
HONEY = {"Exam_Questions_2026_CONFIDENTIAL": ["CSC468_exam_paper.txt", "marking_scheme.txt"],
         "Senate_Approved_Results": ["final_results_all_faculties.txt"]}


def cfg():
    return json.load(open(os.path.join(BASE, "config.json")))


def p(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "harmony.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS refs(name TEXT PRIMARY KEY, commit_id TEXT);
    CREATE TABLE IF NOT EXISTS commits(id TEXT PRIMARY KEY, parent TEXT, at TEXT, author TEXT, message TEXT,
        files INT, added INT, changed INT, removed INT, new_blobs INT, seconds REAL);
    CREATE TABLE IF NOT EXISTS refused(id INTEGER PRIMARY KEY, at TEXT, reason TEXT);
    CREATE TABLE IF NOT EXISTS alarms(id INTEGER PRIMARY KEY, at TEXT, level TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS services(name TEXT PRIMARY KEY, up INT, at TEXT);
    CREATE TABLE IF NOT EXISTS members(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    """)
    return con


def alarm(level, text):
    with db() as con:
        con.execute("INSERT INTO alarms(at,level,text) VALUES(?,?,?)", (now(), level, text))
    print(f"[{level}] {text}")


# ----------------------------------------------------------------- keys
def kdir():
    return os.path.join(DATA, "keys")


def init():
    os.makedirs(kdir(), exist_ok=True)
    open(os.path.join(kdir(), "objects.key"), "wb").write(os.urandom(32))
    sk = Ed25519PrivateKey.generate()
    open(os.path.join(kdir(), "signing.pem"), "wb").write(sk.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub = sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    open(os.path.join(kdir(), "signing_public.pem"), "wb").write(pub)
    os.makedirs(os.path.join(p(cfg()["repo"]), "objects"), exist_ok=True)


def okey():
    return open(os.path.join(kdir(), "objects.key"), "rb").read()


def signer():
    return serialization.load_pem_private_key(open(os.path.join(kdir(), "signing.pem"), "rb").read(), None)


def verifier():
    pub = serialization.load_pem_public_key(open(os.path.join(kdir(), "signing_public.pem"), "rb").read())
    assert isinstance(pub, Ed25519PublicKey)
    return pub


def fingerprint_pub():
    return hashlib.sha256(open(os.path.join(kdir(), "signing_public.pem"), "rb").read()).hexdigest()[:20]


# ----------------------------------------------------------------- object store
def oid(kind, raw):
    return hmac.new(okey(), kind.encode() + b"\0" + raw, hashlib.sha256).hexdigest()


def opath(i):
    return os.path.join(p(cfg()["repo"]), "objects", i[:2], i[2:])


def put(kind, raw):
    i = oid(kind, raw)
    path = opath(i)
    if os.path.exists(path):
        return i, False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    n = os.urandom(12)
    open(path, "wb").write(n + AESGCM(okey()).encrypt(n, raw, (kind + i).encode()))
    return i, True


def get(kind, i):
    blob = open(opath(i), "rb").read()
    raw = AESGCM(okey()).decrypt(blob[:12], blob[12:], (kind + i).encode())
    if oid(kind, raw) != i:
        raise ValueError(f"{kind} {i[:10]} content does not match its id")
    return raw


def head():
    with db() as con:
        r = con.execute("SELECT commit_id FROM refs WHERE name='main'").fetchone()
    return r["commit_id"] if r else None


def read_commit(cid):
    c = json.loads(get("commit", cid))
    body = json.dumps(c["body"], sort_keys=True).encode()
    verifier().verify(bytes.fromhex(c["sig"]), body)  # raises InvalidSignature if edited
    return c["body"]


def read_tree(cid):
    return json.loads(get("tree", read_commit(cid)["tree"]))


# ----------------------------------------------------------------- honey dirs
def plant_honey():
    src = p(cfg()["source"])
    hashes = {}
    for d, files in HONEY.items():
        os.makedirs(os.path.join(src, d), exist_ok=True)
        for f in files:
            pth = os.path.join(src, d, f)
            open(pth, "w").write(f"{f}\nRestricted document. Access is logged.\n" + "x" * 200)
            hashes[f"{d}/{f}"] = hashlib.sha256(open(pth, "rb").read()).hexdigest()
    json.dump(hashes, open(os.path.join(DATA, "honey.json"), "w"))


def honey_intact(files):
    want = json.load(open(os.path.join(DATA, "honey.json")))
    bad = [rel for rel, h in want.items() if rel not in files or hashlib.sha256(files[rel]).hexdigest() != h]
    return bad


# ----------------------------------------------------------------- commit
def read_source():
    src = p(cfg()["source"])
    out = {}
    for root, dirs, names in os.walk(src):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for n in names:
            full = os.path.join(root, n)
            out[os.path.relpath(full, src).replace("\\", "/")] = open(full, "rb").read()
    return out


def change_anomaly(n_changed, n_files):
    """z-score of this run's changed-file count against the last 30 incremental commits.
    With too little history, fall back to a simple share-of-files rule."""
    with db() as con:
        hist = [r["changed"] + r["removed"] for r in con.execute(
            "SELECT changed, removed FROM commits WHERE parent IS NOT NULL ORDER BY rowid DESC LIMIT 30")]
    if len(hist) < cfg()["anomaly_min_history"]:
        share = n_changed / max(1, n_files)
        return 99.0 if share >= cfg()["fallback_share"] else None
    mu = statistics.mean(hist)
    sd = max(statistics.pstdev(hist), 1.0)
    z = (n_changed - mu) / sd
    return z if z > cfg()["anomaly_z"] else None


def commit(message="scheduled backup", author="scheduler"):
    t0 = time.time()
    files = read_source()
    parent = head()
    old = read_tree(parent) if parent else {}
    bad_honey = honey_intact(files)
    tree, new_blobs = {}, 0
    for rel, data in files.items():
        i, new = put("blob", data) if not bad_honey else (oid("blob", data), False)
        tree[rel] = i
        new_blobs += new
    added = [r for r in tree if r not in old]
    changed = [r for r in tree if r in old and old[r] != tree[r]]
    removed = [r for r in old if r not in tree]
    reasons = []
    if bad_honey:
        reasons.append(f"honey file touched: {bad_honey[0]}")
    if any(r.lower().endswith(tuple(cfg()["blocked_extensions"])) for r in added):
        reasons.append("ransomware extensions among new files")
    z = change_anomaly(len(changed) + len(removed), len(old)) if parent else None
    if z:
        reasons.append(f"{len(changed) + len(removed)} files changed/removed " +
                       ("(over the share limit)" if z == 99.0 else f"(z = {z:.1f} against history)"))
    if reasons:
        with db() as con:
            con.execute("INSERT INTO refused(at,reason) VALUES(?,?)", (now(), "; ".join(reasons)))
        alarm("critical", "Commit refused, HEAD left on last clean backup: " + "; ".join(reasons))
        return {"status": "refused", "reasons": reasons}
    tid, _ = put("tree", json.dumps(tree, sort_keys=True).encode())
    body = {"tree": tid, "parent": parent, "at": now(), "author": author, "message": message,
            "stats": {"files": len(tree), "added": len(added), "changed": len(changed), "removed": len(removed)}}
    raw_body = json.dumps(body, sort_keys=True).encode()
    sig = signer().sign(raw_body).hex()
    cid, _ = put("commit", json.dumps({"body": body, "sig": sig}).encode())
    secs = time.time() - t0
    with db() as con:
        con.execute("INSERT INTO commits VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (cid, parent, body["at"], author, message, len(tree), len(added), len(changed), len(removed),
                     new_blobs, secs))
        con.execute("INSERT OR REPLACE INTO refs VALUES('main',?)", (cid,))
    return {"status": "ok", "commit": cid[:12], "files": len(tree), "added": len(added), "changed": len(changed),
            "removed": len(removed), "new_blobs": new_blobs, "seconds": round(secs, 3)}


def verify_chain():
    """Walk HEAD -> root, checking every signature, tree and blob."""
    cid, n, blobs = head(), 0, 0
    try:
        while cid:
            c = read_commit(cid)
            tree = json.loads(get("tree", c["tree"]))
            for rel, b in tree.items():
                get("blob", b)
                blobs += 1
            n += 1
            cid = c["parent"]
        return {"ok": True, "commits": n, "blob_checks": blobs}
    except Exception as exc:  # noqa: BLE001
        alarm("critical", f"history verification failed at commit {str(cid)[:12]}: {type(exc).__name__}")
        return {"ok": False, "commits": n, "failed_at": str(cid)[:12], "error": type(exc).__name__}


def diff(a, b):
    ta, tb = read_tree(a), read_tree(b)
    return {"added": sorted(set(tb) - set(ta)), "removed": sorted(set(ta) - set(tb)),
            "changed": sorted(r for r in ta if r in tb and ta[r] != tb[r])}


def file_history(rel):
    out, cid, last = [], head(), None
    while cid:
        c = read_commit(cid)
        b = json.loads(get("tree", c["tree"])).get(rel)
        if b != last:
            out.append({"commit": cid[:12], "at": c["at"], "present": b is not None})
            last = b
        cid = c["parent"]
    return out


def checkout(cid=None, target=None, who="admin"):
    t0 = time.time()
    with db() as con:
        if cid and len(cid) < 64:
            cid = con.execute("SELECT id FROM commits WHERE id LIKE ?", (cid + "%",)).fetchone()["id"]
    cid = cid or head()
    tree = read_tree(cid)
    target = target or p(cfg()["source"])
    if os.path.isdir(target):
        for root, dirs, names in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for n in names:
                rel = os.path.relpath(os.path.join(root, n), target).replace("\\", "/")
                if rel not in tree:
                    os.remove(os.path.join(root, n))
    for rel, b in tree.items():
        out = os.path.join(target, *rel.split("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        open(out, "wb").write(get("blob", b))
    secs = time.time() - t0
    alarm("info", f"{who} restored commit {cid[:12]} ({len(tree)} files) in {secs:.2f}s")
    return {"commit": cid[:12], "files": len(tree), "seconds": round(secs, 3)}


def probe():
    for name, url in cfg()["services"].items():
        try:
            urllib.request.urlopen(url, timeout=3).close()
            up = 1
        except Exception:  # noqa: BLE001
            up = 0
        with db() as con:
            old = con.execute("SELECT up FROM services WHERE name=?", (name,)).fetchone()
            con.execute("INSERT OR REPLACE INTO services VALUES(?,?,?)", (name, up, now()))
        if (old is None and not up) or (old is not None and old["up"] != up):
            alarm("critical" if not up else "info", f"{name} {'DOWN' if not up else 'UP'}")
