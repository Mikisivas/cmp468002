"""SahelStore: backup and recovery for a campus with weak internet and unstable power.

1. Local store: content-addressed objects (SHA-256 of plaintext), LZMA-compressed and
   sealed with AES-256-GCM. Snapshots are small JSON manifests.
2. Offsite sync: an rsync-style delta. For a changed file, only the byte ranges that differ
   from the copy already offsite are sent (weak rolling checksum + SHA-256 per 2 KiB block).
   A daily megabyte budget and an off-peak window protect the campus internet link.
3. Power-aware scheduler: on battery below a limit, heavy jobs wait. At a critical level
   it runs one quick emergency snapshot before the inverter dies.
"""
import datetime as dt
import hashlib
import json
import lzma
import os
import shutil
import socket
import sqlite3
import time
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
BLOCK = 2048
MOD = 1 << 16


def cfg():
    return json.load(open(os.path.join(BASE, "config.json")))


def p(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def ts():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "sahel.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS snaps(id INTEGER PRIMARY KEY, at TEXT, files INT, new_objects INT, bytes_in INT,
        bytes_stored INT, secs REAL, kind TEXT, ok INT, why TEXT);
    CREATE TABLE IF NOT EXISTS offsite(path TEXT PRIMARY KEY, sha TEXT, chain INT, synced TEXT);
    CREATE TABLE IF NOT EXISTS transfers(at TEXT, path TEXT, mode TEXT, file_bytes INT, sent_bytes INT);
    CREATE TABLE IF NOT EXISTS queue(path TEXT PRIMARY KEY, added TEXT);
    CREATE TABLE IF NOT EXISTS power(at TEXT, percent REAL, plugged INT, action TEXT);
    CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY, at TEXT, level TEXT, msg TEXT, chain TEXT);
    CREATE TABLE IF NOT EXISTS health(name TEXT PRIMARY KEY, up INT, at TEXT);
    CREATE TABLE IF NOT EXISTS viewers(name TEXT PRIMARY KEY, salt TEXT, hash TEXT);
    """)
    return con


def log(level, msg):
    with db() as con:
        prev = con.execute("SELECT chain FROM log ORDER BY id DESC LIMIT 1").fetchone()
        at = ts()
        chain = hashlib.sha256(f"{prev['chain'] if prev else ''}{at}{level}{msg}".encode()).hexdigest()
        con.execute("INSERT INTO log(at,level,msg,chain) VALUES(?,?,?,?)", (at, level, msg, chain))
    print(f"[{level}] {msg}")


def log_ok():
    prev = ""
    with db() as con:
        for r in con.execute("SELECT * FROM log ORDER BY id"):
            if hashlib.sha256(f"{prev}{r['at']}{r['level']}{r['msg']}".encode()).hexdigest() != r["chain"]:
                return False
            prev = r["chain"]
    return True


def key():
    return open(os.path.join(DATA, "keys", "store.key"), "rb").read()


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    open(os.path.join(DATA, "keys", "store.key"), "wb").write(os.urandom(32))
    for d in (cfg()["local_store"], cfg()["offsite_store"]):
        os.makedirs(os.path.join(p(d), "objects"), exist_ok=True)
        os.makedirs(os.path.join(p(d), "snaps"), exist_ok=True)


def seal(data, label):
    n = os.urandom(12)
    return n + AESGCM(key()).encrypt(n, lzma.compress(data, preset=6), label.encode())


def unseal(blob, label):
    return lzma.decompress(AESGCM(key()).decrypt(blob[:12], blob[12:], label.encode()))


# ----------------------------------------------------------------- local snapshots
def walk():
    src = p(cfg()["source"])
    out = {}
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            full = os.path.join(root, f)
            out[os.path.relpath(full, src).replace("\\", "/")] = full
    return out


def burst_check(files):
    """Ransomware edits many files within seconds. Count files modified in the last window."""
    c = cfg()["burst"]
    with db() as con:
        has_prev = con.execute("SELECT 1 FROM snaps WHERE ok=1").fetchone()
    known = set(manifest(last_snap())) if has_prev else set()
    recent = [r for r, full in files.items()
              if r in known and time.time() - os.path.getmtime(full) < c["window_seconds"]]
    bad_ext = [r for r in files if r.lower().endswith(tuple(cfg()["blocked_extensions"]))]
    why = []
    if len(recent) >= c["max_files"] and len(recent) / max(1, len(files)) >= c["min_share"]:
        why.append(f"{len(recent)} files modified within {c['window_seconds']} s")
    if bad_ext:
        why.append(f"{len(bad_ext)} files carry a ransomware extension")
    return why


def snapshot(kind="scheduled"):
    t0 = time.time()
    files = walk()
    why = burst_check(files)
    if why and kind != "emergency-forced":
        with db() as con:
            con.execute("INSERT INTO snaps(at,files,kind,ok,why,secs) VALUES(?,?,?,?,?,?)",
                        (ts(), len(files), kind, 0, "; ".join(why), time.time() - t0))
        log("critical", "Snapshot refused: " + "; ".join(why))
        return {"ok": False, "why": why}
    store = p(cfg()["local_store"])
    manifest, new, bytes_in, stored = {}, 0, 0, 0
    for rel, full in files.items():
        data = open(full, "rb").read()
        h = hashlib.sha256(data).hexdigest()
        manifest[rel] = h
        bytes_in += len(data)
        obj = os.path.join(store, "objects", h)
        if not os.path.exists(obj):
            blob = seal(data, h)
            open(obj, "wb").write(blob)
            new += 1
            stored += len(blob)
            with db() as con:
                con.execute("INSERT OR REPLACE INTO queue VALUES(?,?)", (rel, ts()))
    with db() as con:
        cur = con.execute("INSERT INTO snaps(at,files,new_objects,bytes_in,bytes_stored,secs,kind,ok,why) "
                          "VALUES(?,?,?,?,?,?,?,1,'')", (ts(), len(files), new, bytes_in, stored, 0, kind))
        sid = cur.lastrowid
    open(os.path.join(store, "snaps", f"{sid}.snap"), "wb").write(seal(json.dumps(manifest).encode(), f"snap{sid}"))
    secs = time.time() - t0
    with db() as con:
        con.execute("UPDATE snaps SET secs=? WHERE id=?", (secs, sid))
    log("info", f"snapshot {sid} ({kind}): {len(files)} files, {new} new objects")
    return {"ok": True, "id": sid, "files": len(files), "new_objects": new, "bytes_in": bytes_in,
            "bytes_stored": stored, "secs": round(secs, 3)}


def last_snap():
    with db() as con:
        return con.execute("SELECT id FROM snaps WHERE ok=1 ORDER BY id DESC LIMIT 1").fetchone()["id"]


def manifest(sid, store=None):
    return json.loads(unseal(open(os.path.join(store or p(cfg()["local_store"]), "snaps", f"{sid}.snap"), "rb").read(),
                             f"snap{sid}"))


def restore(sid=None, target=None):
    t0 = time.time()
    sid = sid or last_snap()
    m = manifest(sid)
    target = target or p(cfg()["source"])
    _clean(target, m)
    for rel, h in m.items():
        data = unseal(open(os.path.join(p(cfg()["local_store"]), "objects", h), "rb").read(), h)
        _write(target, rel, data, h)
    secs = time.time() - t0
    log("info", f"local restore of snapshot {sid} in {secs:.2f}s")
    return {"source": "local", "snapshot": sid, "files": len(m), "secs": round(secs, 3)}


def _clean(target, m):
    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), target).replace("\\", "/")
                if rel not in m:
                    os.remove(os.path.join(root, f))


def _write(target, rel, data, h):
    if hashlib.sha256(data).hexdigest() != h:
        raise ValueError(f"{rel} failed its SHA-256 check")
    out = os.path.join(target, *rel.split("/"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, "wb").write(data)


# ----------------------------------------------------------------- rsync-style delta
def weak(block):
    a = sum(block) % MOD
    b = sum((len(block) - i) * x for i, x in enumerate(block)) % MOD
    return a, b


def signature(old):
    sig = {}
    for i in range(0, len(old), BLOCK):
        blk = old[i:i + BLOCK]
        a, b = weak(blk)
        sig.setdefault((a, b), []).append((i // BLOCK, hashlib.sha256(blk).digest()[:8]))
    return sig


def delta(old, new):
    """Return a list of ops: ("C", block_index) to copy from old, or ("L", bytes) literal."""
    sig = signature(old)
    ops, lit, i, n = [], bytearray(), 0, len(new)
    if n < BLOCK:
        return [("L", bytes(new))]
    a, b = weak(new[0:BLOCK])
    while i <= n - BLOCK:
        hit = None
        for idx, strong in sig.get((a, b), []):
            if hashlib.sha256(new[i:i + BLOCK]).digest()[:8] == strong:
                hit = idx
                break
        if hit is not None:
            if lit:
                ops.append(("L", bytes(lit)))
                lit = bytearray()
            ops.append(("C", hit))
            i += BLOCK
            if i <= n - BLOCK:
                a, b = weak(new[i:i + BLOCK])
            continue
        lit.append(new[i])
        if i + BLOCK < n:  # roll the weak checksum one byte forward
            out_b, in_b = new[i], new[i + BLOCK]
            a = (a - out_b + in_b) % MOD
            b = (b - BLOCK * out_b + a) % MOD
        i += 1
    lit.extend(new[i:])
    if lit:
        ops.append(("L", bytes(lit)))
    return ops


def patch(old, ops):
    out = bytearray()
    for kind, v in ops:
        out.extend(old[v * BLOCK:(v + 1) * BLOCK] if kind == "C" else v)
    return bytes(out)


def encode_ops(ops):
    return json.dumps([[k, v if k == "C" else v.hex()] for k, v in ops]).encode()


def decode_ops(raw):
    return [(k, v if k == "C" else bytes.fromhex(v)) for k, v in json.loads(raw)]


# ----------------------------------------------------------------- offsite sync
def offsite_dir():
    return p(cfg()["offsite_store"])


def offsite_file(rel):
    """Rebuild a file from the offsite base + deltas."""
    d = os.path.join(offsite_dir(), "files", hashlib.sha256(rel.encode()).hexdigest()[:24])
    with db() as con:
        row = con.execute("SELECT * FROM offsite WHERE path=?", (rel,)).fetchone()
    data = unseal(open(os.path.join(d, "base"), "rb").read(), rel + "#base")
    for k in range(1, row["chain"] + 1):
        data = patch(data, decode_ops(unseal(open(os.path.join(d, f"delta{k}"), "rb").read(), f"{rel}#d{k}")))
    return data


def in_window(now=None):
    start, end = cfg()["offsite_window"].split("-")
    hm = (now or dt.datetime.now()).strftime("%H:%M")
    return start <= hm <= end if start <= end else (hm >= start or hm <= end)


def sent_today():
    with db() as con:
        r = con.execute("SELECT SUM(sent_bytes) s FROM transfers WHERE at LIKE ?", (dt.date.today().isoformat() + "%",)
                        ).fetchone()
    return r["s"] or 0


def sync(force=False):
    """Send queued files offsite within the window and the daily budget."""
    c = cfg()
    if not force and not in_window():
        return {"skipped": "outside off-peak window " + c["offsite_window"]}
    budget = c["daily_budget_mb"] * 1024 * 1024 - sent_today()
    src = p(c["source"])
    done, sent_total, full_total = 0, 0, 0
    with db() as con:
        queue = [r["path"] for r in con.execute("SELECT path FROM queue ORDER BY added")]
    for rel in queue:
        full = os.path.join(src, *rel.split("/"))
        if not os.path.exists(full):
            with db() as con:
                con.execute("DELETE FROM queue WHERE path=?", (rel,))
            continue
        new = open(full, "rb").read()
        d = os.path.join(offsite_dir(), "files", hashlib.sha256(rel.encode()).hexdigest()[:24])
        os.makedirs(d, exist_ok=True)
        with db() as con:
            row = con.execute("SELECT * FROM offsite WHERE path=?", (rel,)).fetchone()
        if row and row["chain"] < c["max_delta_chain"]:
            ops = delta(offsite_file(rel), new)
            blob = seal(encode_ops(ops), f"{rel}#d{row['chain'] + 1}")
            name, mode, chain = f"delta{row['chain'] + 1}", "delta", row["chain"] + 1
        else:
            blob = seal(new, rel + "#base")
            name, mode, chain = "base", "full", 0
        if len(blob) > budget:
            log("warning", f"daily offsite budget reached; {rel} waits for tomorrow")
            break
        open(os.path.join(d, name), "wb").write(blob)
        if mode == "full":
            for f in os.listdir(d):
                if f.startswith("delta"):
                    os.remove(os.path.join(d, f))
        budget -= len(blob)
        sent_total += len(blob)
        full_total += len(new)
        with db() as con:
            con.execute("INSERT OR REPLACE INTO offsite VALUES(?,?,?,?)", (rel, hashlib.sha256(new).hexdigest(),
                                                                          chain, ts()))
            con.execute("INSERT INTO transfers VALUES(?,?,?,?,?)", (ts(), rel, mode, len(new), len(blob)))
            con.execute("DELETE FROM queue WHERE path=?", (rel,))
        done += 1
    with db() as con:
        snap_files = {r["path"]: r["sha"] for r in con.execute("SELECT path, sha FROM offsite")}
    open(os.path.join(offsite_dir(), "catalogue.enc"), "wb").write(seal(json.dumps(snap_files).encode(), "catalogue"))
    if done:
        log("info", f"offsite sync: {done} files, {sent_total} bytes sent for {full_total} bytes of data")
    return {"files": done, "sent_bytes": sent_total, "file_bytes": full_total}


def restore_offsite(target=None):
    """Disaster recovery when the local server is gone: rebuild from the offsite copy."""
    t0 = time.time()
    cat = json.loads(unseal(open(os.path.join(offsite_dir(), "catalogue.enc"), "rb").read(), "catalogue"))
    target = target or p(cfg()["source"])
    _clean(target, cat)
    for rel, h in cat.items():
        _write(target, rel, offsite_file(rel), h)
    secs = time.time() - t0
    log("info", f"offsite restore of {len(cat)} files in {secs:.2f}s")
    return {"source": "offsite", "files": len(cat), "secs": round(secs, 3)}


# ----------------------------------------------------------------- power and services
def power_state():
    """Battery from the laptop/UPS if available; data/ups_override.json lets the demo simulate one."""
    ov = os.path.join(DATA, "ups_override.json")
    if os.path.exists(ov):
        d = json.load(open(ov))
        return d["percent"], d["plugged"]
    try:
        import psutil
        b = psutil.sensors_battery()
        if b:
            return b.percent, bool(b.power_plugged)
    except Exception:  # noqa: BLE001
        pass
    return 100.0, True


def power_decision():
    c = cfg()["power"]
    pct, plugged = power_state()
    if plugged:
        action = "normal"
    elif pct <= c["critical_percent"]:
        action = "emergency"
    elif pct <= c["defer_percent"]:
        action = "defer"
    else:
        action = "normal"
    with db() as con:
        con.execute("INSERT INTO power VALUES(?,?,?,?)", (ts(), pct, int(plugged), action))
    return action, pct, plugged


def check_health():
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
            con.execute("INSERT OR REPLACE INTO health VALUES(?,?,?)", (name, up, ts()))
        if (old is None and not up) or (old is not None and old["up"] != up):
            log("critical" if not up else "info", f"{name} {'DOWN' if not up else 'UP again'}")


def tick(state):
    """One scheduler step. `state` holds last-run times between ticks."""
    c = cfg()
    check_health()
    action, pct, plugged = power_decision()
    if action == "emergency" and not state.get("emergency_done"):
        log("critical", f"battery {pct:.0f}% on inverter: emergency snapshot before shutdown")
        snapshot("emergency")
        state["emergency_done"] = True
        return "emergency"
    if action == "emergency":
        return "halted"  # emergency snapshot already taken: stay idle until mains power returns
    if plugged:
        state["emergency_done"] = False
    if action == "defer":
        if not state.get("deferred_logged"):
            log("warning", f"battery {pct:.0f}% and no mains power: heavy jobs deferred")
            state["deferred_logged"] = True
        return "deferred"
    state["deferred_logged"] = False
    if time.time() - state.get("snap", 0) > c["snapshot_minutes"] * 60:
        snapshot()
        state["snap"] = time.time()
    if time.time() - state.get("sync", 0) > c["sync_minutes"] * 60:
        sync()
        state["sync"] = time.time()
    return "normal"
