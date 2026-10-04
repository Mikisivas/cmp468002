"""PremierGuard engine: content-defined chunking (CDC) with de-duplication,
ChaCha20-Poly1305 encryption, Merkle-tree snapshots and a compressibility-based
ransomware detector.

Why CDC: a fixed-size block store loses de-duplication when one byte is inserted at
the start of a file, because every later block shifts. A rolling "Gear" hash cuts
chunks where the content says so, so an insertion only changes one or two chunks.
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import random
import shutil
import sqlite3
import time
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
_rng = random.Random(20210601)
GEAR = [_rng.getrandbits(32) for _ in range(256)]  # fixed table so chunk cuts are reproducible
MIN_CHUNK, MAX_CHUNK = 2048, 65536
AVG_MASK = ((1 << 13) - 1) << 19  # top 13 bits of the 32-bit hash: average about 8 KiB
COMPRESSIBLE = {".csv", ".txt", ".sql", ".json", ".html", ".xml", ".md", ".log"}


def cfg():
    with open(os.path.join(BASE, "config.json")) as fh:
        return json.load(fh)


def p(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "premierguard.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY, created TEXT, files INT, chunks_total INT,
        chunks_new INT, bytes_in INT, bytes_new INT, seconds REAL, merkle_root TEXT, status TEXT, note TEXT);
    CREATE TABLE IF NOT EXISTS chunks(cid TEXT PRIMARY KEY, size INT, stored INT, refs INT);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT, kind TEXT, level TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS samples(ts TEXT, cpu REAL, mem REAL, disk REAL, cpu_ewma REAL, cpu_dev REAL);
    CREATE TABLE IF NOT EXISTS probes(name TEXT PRIMARY KEY, up INT, at TEXT);
    CREATE TABLE IF NOT EXISTS accounts(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    """)
    return con


def event(kind, level, text):
    with db() as con:
        con.execute("INSERT INTO events(ts,kind,level,text) VALUES(?,?,?,?)", (now(), kind, level, text))
    print(f"[{level}] {kind}: {text}")


# ----------------------------------------------------------------- keys
def root_key():
    with open(os.path.join(DATA, "keys", "root.key"), "rb") as fh:
        return fh.read()


def derive(label):
    return HKDF(hashes.SHA256(), 32, salt=b"PremierGuard-UI", info=label.encode()).derive(root_key())


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    with open(os.path.join(DATA, "keys", "root.key"), "wb") as fh:
        fh.write(os.urandom(32))
    for d in [cfg()["chunk_store"], cfg()["anchor_dir"], *cfg()["mirrors"]]:
        os.makedirs(p(d), exist_ok=True)


# ----------------------------------------------------------------- chunking
def chunk(data):
    """Gear-hash content-defined chunking. Returns a list of byte strings."""
    out, start, h, n = [], 0, 0, len(data)
    i = 0
    while i < n:
        h = ((h << 1) + GEAR[data[i]]) & 0xFFFFFFFF
        size = i - start + 1
        if (size >= MIN_CHUNK and (h & AVG_MASK) == 0) or size >= MAX_CHUNK:
            out.append(data[start:i + 1])
            start, h = i + 1, 0
        i += 1
    if start < n:
        out.append(data[start:])
    return out


def chunk_id(data):
    """Keyed hash, so someone holding the store cannot test whether a known file is inside."""
    return hmac.new(derive("chunk-id"), data, hashlib.sha256).hexdigest()


def chunk_path(cid, base=None):
    return os.path.join(base or p(cfg()["chunk_store"]), cid[:2], cid)


def put_chunk(cid, data):
    path = chunk_path(cid)
    if os.path.exists(path):
        return 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    nonce = os.urandom(12)
    blob = nonce + ChaCha20Poly1305(derive("chunk-enc")).encrypt(nonce, zlib.compress(data, 6), cid.encode())
    with open(path, "wb") as fh:
        fh.write(blob)
    return len(blob)


def get_chunk(cid, base=None):
    with open(chunk_path(cid, base), "rb") as fh:
        blob = fh.read()
    data = zlib.decompress(ChaCha20Poly1305(derive("chunk-enc")).decrypt(blob[:12], blob[12:], cid.encode()))
    if chunk_id(data) != cid:
        raise ValueError("chunk content does not match its id")
    return data


# ----------------------------------------------------------------- merkle
def merkle_root(leaves):
    level = [hashlib.sha256(x.encode()).digest() for x in sorted(leaves)] or [hashlib.sha256(b"").digest()]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def leaves_of(tree):
    return [f"{path}:{':'.join(meta['chunks'])}" for path, meta in tree.items()]


# ----------------------------------------------------------------- detector
def looks_encrypted(rel, data):
    """Text-type files compress well (CSV usually below 40%). Ciphertext does not compress at all."""
    ext = os.path.splitext(rel)[1].lower()
    if ext not in COMPRESSIBLE or len(data) < 1024:
        return False
    ratio = len(zlib.compress(data, 1)) / len(data)
    return ratio > cfg()["incompressible_ratio"]


# ----------------------------------------------------------------- snapshots
def tree_path(sid, base=None):
    return os.path.join(base or p(cfg()["chunk_store"]), "trees", f"{sid:06d}.json")


def save_tree(sid, tree):
    raw = json.dumps(tree, sort_keys=True).encode()
    nonce = os.urandom(12)
    os.makedirs(os.path.dirname(tree_path(sid)), exist_ok=True)
    with open(tree_path(sid), "wb") as fh:
        fh.write(nonce + ChaCha20Poly1305(derive("tree")).encrypt(nonce, raw, str(sid).encode()))


def load_tree(sid, base=None):
    with open(tree_path(sid, base), "rb") as fh:
        blob = fh.read()
    return json.loads(ChaCha20Poly1305(derive("tree")).decrypt(blob[:12], blob[12:], str(sid).encode()))


def latest(status="ok"):
    with db() as con:
        r = con.execute("SELECT * FROM snapshots WHERE status=? ORDER BY id DESC LIMIT 1", (status,)).fetchone()
    return r


def snapshot(note="scheduled"):
    c = cfg()
    src = p(c["source"])
    t0 = time.time()
    tree, suspects, new_bytes, new_chunks, total_chunks, bytes_in = {}, [], 0, 0, 0, 0
    blocked = tuple(c["blocked_extensions"])
    pending = []
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in sorted(files):
            full = os.path.join(root, f)
            rel = os.path.relpath(full, src).replace("\\", "/")
            with open(full, "rb") as fh:
                data = fh.read()
            if rel.lower().endswith(blocked) or looks_encrypted(rel, data):
                suspects.append(rel)
            pending.append((rel, data))
    if len(suspects) >= c["max_suspects"]:
        with db() as con:
            con.execute("INSERT INTO snapshots(created,files,status,note,seconds) VALUES(?,?,?,?,?)",
                        (now(), len(pending), "blocked", f"{len(suspects)} encrypted-looking files", time.time() - t0))
        event("ransomware", "critical", f"Snapshot blocked: {len(suspects)} files look encrypted, e.g. {suspects[0]}")
        return {"status": "blocked", "suspects": len(suspects)}
    for rel, data in pending:
        ids = []
        for piece in chunk(data):
            cid = chunk_id(piece)
            stored = put_chunk(cid, piece)
            with db() as con:
                if stored:
                    con.execute("INSERT INTO chunks VALUES(?,?,?,1)", (cid, len(piece), stored))
                    new_chunks += 1
                    new_bytes += stored
                else:
                    con.execute("UPDATE chunks SET refs=refs+1 WHERE cid=?", (cid,))
            ids.append(cid)
        total_chunks += len(ids)
        bytes_in += len(data)
        tree[rel] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "chunks": ids}
    root_hash = merkle_root(leaves_of(tree))
    with db() as con:
        cur = con.execute("INSERT INTO snapshots(created,files,chunks_total,chunks_new,bytes_in,bytes_new,seconds,"
                          "merkle_root,status,note) VALUES(?,?,?,?,?,?,?,?,?,?)",
                          (now(), len(tree), total_chunks, new_chunks, bytes_in, new_bytes, 0, root_hash, "ok", note))
        sid = cur.lastrowid
    save_tree(sid, tree)
    # publish the Merkle root to a separate "anchor" location (another server, printed report, email)
    with open(os.path.join(p(c["anchor_dir"]), "anchors.log"), "a") as fh:
        fh.write(f"{sid} {now()} {root_hash}\n")
    mirror()
    secs = time.time() - t0
    with db() as con:
        con.execute("UPDATE snapshots SET seconds=? WHERE id=?", (secs, sid))
    return {"status": "ok", "id": sid, "files": len(tree), "chunks": total_chunks, "new_chunks": new_chunks,
            "bytes_in": bytes_in, "bytes_new": new_bytes, "seconds": round(secs, 3), "merkle_root": root_hash[:16]}


def mirror():
    store = p(cfg()["chunk_store"])
    for m in cfg()["mirrors"]:
        for root, _, files in os.walk(store):
            for f in files:
                s = os.path.join(root, f)
                d = os.path.join(p(m), os.path.relpath(s, store))
                if not os.path.exists(d):
                    os.makedirs(os.path.dirname(d), exist_ok=True)
                    shutil.copyfile(s, d)


def anchored_root(sid):
    with open(os.path.join(p(cfg()["anchor_dir"]), "anchors.log")) as fh:
        for line in fh:
            parts = line.split()
            if parts and int(parts[0]) == sid:
                return parts[-1]
    return None


def verify():
    """For each snapshot: decrypt tree, recompute Merkle root and compare with the anchor,
    then decrypt and re-hash every chunk. Repair bad chunks from a mirror."""
    out = {"snapshots": 0, "chunks": 0, "repaired": [], "bad": [], "root_mismatch": []}
    seen = set()
    with db() as con:
        sids = [r["id"] for r in con.execute("SELECT id FROM snapshots WHERE status='ok'")]
    for sid in sids:
        tree = load_tree(sid)
        if merkle_root(leaves_of(tree)) != anchored_root(sid):
            out["root_mismatch"].append(sid)
        out["snapshots"] += 1
        for meta in tree.values():
            for cid in meta["chunks"]:
                if cid in seen:
                    continue
                seen.add(cid)
                out["chunks"] += 1
                try:
                    get_chunk(cid)
                except Exception:  # noqa: BLE001
                    fixed = False
                    for m in cfg()["mirrors"]:
                        try:
                            get_chunk(cid, p(m))
                            shutil.copyfile(chunk_path(cid, p(m)), chunk_path(cid))
                            fixed = True
                            break
                        except Exception:  # noqa: BLE001
                            continue
                    (out["repaired"] if fixed else out["bad"]).append(cid[:12])
    if out["bad"] or out["root_mismatch"]:
        event("verify", "critical", f"verification problems: {out}")
    else:
        event("verify", "info", f"{out['snapshots']} snapshots, {out['chunks']} chunks verified")
    return out


def restore(sid=None, target=None):
    c = cfg()
    t0 = time.time()
    sid = sid or latest()["id"]
    tree = load_tree(sid)
    if merkle_root(leaves_of(tree)) != anchored_root(sid):
        raise ValueError("snapshot tree does not match its anchored Merkle root")
    target = target or p(c["source"])
    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), target).replace("\\", "/")
                if rel not in tree:
                    os.remove(os.path.join(root, f))
    for rel, meta in tree.items():
        data = b"".join(get_chunk(cid) for cid in meta["chunks"])
        if hashlib.sha256(data).hexdigest() != meta["sha256"]:
            raise ValueError(f"restored {rel} fails its SHA-256 check")
        out = os.path.join(target, *rel.split("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(data)
    secs = time.time() - t0
    event("restore", "info", f"snapshot {sid} restored ({len(tree)} files) in {secs:.2f}s")
    return {"snapshot": sid, "files": len(tree), "seconds": round(secs, 3)}


def garbage_collect(keep):
    """Drop old snapshots and delete chunks that no kept snapshot references."""
    with db() as con:
        ids = [r["id"] for r in con.execute("SELECT id FROM snapshots WHERE status='ok' ORDER BY id DESC")]
    kept, dropped = ids[:keep], ids[keep:]
    live = set()
    for sid in kept:
        for meta in load_tree(sid).values():
            live.update(meta["chunks"])
    removed = 0
    with db() as con:
        for r in con.execute("SELECT cid FROM chunks").fetchall():
            if r["cid"] not in live:
                os.remove(chunk_path(r["cid"]))
                con.execute("DELETE FROM chunks WHERE cid=?", (r["cid"],))
                removed += 1
        for sid in dropped:
            os.remove(tree_path(sid))
            con.execute("UPDATE snapshots SET status='expired' WHERE id=?", (sid,))
    return {"snapshots_dropped": len(dropped), "chunks_removed": removed}


# ----------------------------------------------------------------- monitoring
def sample():
    """CPU anomaly with an exponentially weighted moving average (EWMA) and deviation."""
    import urllib.request
    import socket
    c = cfg()
    try:
        import psutil
        cpu, mem = psutil.cpu_percent(interval=0.3), psutil.virtual_memory().percent
    except ImportError:
        cpu = mem = 0.0
    du = shutil.disk_usage(BASE)
    disk = round(du.used / du.total * 100, 1)
    with db() as con:
        prev = con.execute("SELECT cpu_ewma, cpu_dev FROM samples ORDER BY rowid DESC LIMIT 1").fetchone()
    a = c["ewma_alpha"]
    ew = cpu if not prev else a * cpu + (1 - a) * prev["cpu_ewma"]
    dev = 5.0 if not prev else a * abs(cpu - prev["cpu_ewma"]) + (1 - a) * prev["cpu_dev"]
    if prev and cpu > prev["cpu_ewma"] + c["ewma_k"] * max(prev["cpu_dev"], 2.0) and cpu > 50:
        event("host", "warning", f"CPU {cpu}% is far above its normal level ({prev['cpu_ewma']:.0f}%)")
    with db() as con:
        con.execute("INSERT INTO samples VALUES(?,?,?,?,?,?)", (now(), cpu, mem, disk, ew, dev))
    for name, target in c["probes"].items():
        try:
            if target.startswith("http"):
                urllib.request.urlopen(target, timeout=3).close()
            else:
                host, port = target.split(":")
                socket.create_connection((host, int(port)), timeout=3).close()
            up = 1
        except Exception:  # noqa: BLE001
            up = 0
        with db() as con:
            old = con.execute("SELECT up FROM probes WHERE name=?", (name,)).fetchone()
            con.execute("INSERT OR REPLACE INTO probes VALUES(?,?,?)", (name, up, now()))
        if old and old["up"] != up:
            event("service", "critical" if not up else "info", f"{name} is {'UP' if up else 'DOWN'}")
        elif not old and not up:
            event("service", "critical", f"{name} is DOWN")
    return {"cpu": cpu, "mem": mem, "disk": disk, "cpu_ewma": round(ew, 1)}
