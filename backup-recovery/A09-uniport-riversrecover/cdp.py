"""RiversRecover: continuous data protection (CDP) for the UNIPORT results database.

Live database (the system being protected): students and results tables.
1. SQLite triggers copy every INSERT, UPDATE and DELETE into a change journal.
2. A shipper moves new journal rows to the recovery store every few seconds as
   encrypted, hash-chained segments (AES-256-GCM, previous segment hash bound as AAD).
3. Encrypted base snapshots are taken with SQLite's online backup API.
4. Point-in-time recovery (PITR) = newest base before time T + replay of the journal up to T.
Security rules inside the database:
   - Senate-approved results cannot be edited unless an amendment window is opened (logged).
   - A mass-change detector can FREEZE the database (all writes refused) within seconds.
"""
import datetime as dt
import hashlib
import json
import os
import random
import shutil
import sqlite3
import time
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
TABLES = {"students": "matric", "results": "id"}


def cfg():
    return json.load(open(os.path.join(BASE, "config.json")))


def p(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def now(precise=False):
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f" if precise else "%Y-%m-%d %H:%M:%S")


def live_path():
    return p(cfg()["live_db"])


def live():
    con = sqlite3.connect(live_path(), timeout=5)
    con.row_factory = sqlite3.Row
    return con


def rec():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "recovery_catalogue.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS bases(id INTEGER PRIMARY KEY, at TEXT, upto_seq INT, bytes INT, file TEXT, sha TEXT,
        abandoned INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS abandoned(from_seq INT, to_seq INT, at TEXT);
    CREATE TABLE IF NOT EXISTS segments(id INTEGER PRIMARY KEY, at TEXT, first_seq INT, last_seq INT, last_ts TEXT,
        rows INT, file TEXT, sha TEXT, prev_sha TEXT);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, at TEXT, sev TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS recoveries(at TEXT, target_time TEXT, base_id INT, replayed INT, seconds REAL);
    CREATE TABLE IF NOT EXISTS probes(name TEXT PRIMARY KEY, up INT, at TEXT);
    CREATE TABLE IF NOT EXISTS staff(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    """)
    return con


def event(sev, text):
    with rec() as con:
        con.execute("INSERT INTO events(at,sev,text) VALUES(?,?,?)", (now(), sev, text))
    print(f"[{sev}] {text}")


def key():
    return open(os.path.join(DATA, "keys", "recovery.key"), "rb").read()


def store():
    return p(cfg()["recovery_store"])


# ----------------------------------------------------------------- schema and triggers
SCHEMA = """
CREATE TABLE IF NOT EXISTS students(matric TEXT PRIMARY KEY, surname TEXT, first_name TEXT, department TEXT, level INT);
CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY, matric TEXT, course TEXT, session TEXT, ca INT, exam INT,
    total INT, grade TEXT, approved INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS journal(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, tbl TEXT, op TEXT, pk TEXT, row TEXT);
CREATE TABLE IF NOT EXISTS control(id INTEGER PRIMARY KEY CHECK(id = 1), frozen INT, amend_until TEXT, reason TEXT);
INSERT OR IGNORE INTO control VALUES(1, 0, '1970-01-01 00:00:00', '');
"""


def trigger_sql():
    ts = "strftime('%Y-%m-%d %H:%M:%f','now','localtime')"
    cols = {"students": ["matric", "surname", "first_name", "department", "level"],
            "results": ["id", "matric", "course", "session", "ca", "exam", "total", "grade", "approved"]}
    out = []
    for t, pk in TABLES.items():
        obj = lambda alias: "json_object(" + ",".join(f"'{c}',{alias}.{c}" for c in cols[t]) + ")"  # noqa: E731
        for op in ("INSERT", "UPDATE", "DELETE"):
            out.append(f"""CREATE TRIGGER IF NOT EXISTS freeze_{t}_{op.lower()} BEFORE {op} ON {t}
                WHEN (SELECT frozen FROM control WHERE id=1) = 1
                BEGIN SELECT RAISE(ABORT, 'DATABASE FROZEN by RiversRecover: suspected attack'); END;""")
        out.append(f"""CREATE TRIGGER IF NOT EXISTS j_{t}_ins AFTER INSERT ON {t} BEGIN
            INSERT INTO journal(ts,tbl,op,pk,row) VALUES({ts},'{t}','I',NEW.{pk},{obj('NEW')}); END;""")
        out.append(f"""CREATE TRIGGER IF NOT EXISTS j_{t}_upd AFTER UPDATE ON {t} BEGIN
            INSERT INTO journal(ts,tbl,op,pk,row) VALUES({ts},'{t}','U',NEW.{pk},{obj('NEW')}); END;""")
        out.append(f"""CREATE TRIGGER IF NOT EXISTS j_{t}_del AFTER DELETE ON {t} BEGIN
            INSERT INTO journal(ts,tbl,op,pk,row) VALUES({ts},'{t}','D',OLD.{pk},NULL); END;""")
    out.append("""CREATE TRIGGER IF NOT EXISTS senate_lock BEFORE UPDATE ON results
        WHEN OLD.approved = 1 AND (SELECT amend_until FROM control WHERE id=1) < datetime('now','localtime')
        BEGIN SELECT RAISE(ABORT, 'Senate-approved result: open an amendment window first'); END;""")
    out.append("""CREATE TRIGGER IF NOT EXISTS senate_lock_del BEFORE DELETE ON results
        WHEN OLD.approved = 1 AND (SELECT amend_until FROM control WHERE id=1) < datetime('now','localtime')
        BEGIN SELECT RAISE(ABORT, 'Senate-approved result: open an amendment window first'); END;""")
    return "\n".join(out)


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    open(os.path.join(DATA, "keys", "recovery.key"), "wb").write(os.urandom(32))
    os.makedirs(os.path.dirname(live_path()), exist_ok=True)
    os.makedirs(os.path.join(store(), "bases"), exist_ok=True)
    os.makedirs(os.path.join(store(), "journal"), exist_ok=True)
    with live() as con:
        con.executescript(SCHEMA)
        con.executescript(trigger_sql())
    rec().close()


def seed(n=400):
    inst = cfg()["institution"]
    rnd = random.Random(468)
    first = ["Ebi", "Tamuno", "Ibiso", "Soye", "Data", "Chioma", "Tari", "Ere", "Boma", "Nkem", "Ifeoma", "Owaji"]
    last = ["Amadi", "Wokoma", "Briggs", "George", "Jumbo", "Horsfall", "Okoro", "Ikiriko", "Dappa", "Opara"]
    with live() as con:
        for i in range(n):
            m = inst["matric_format"].format(year=2021 + i % 5, n=1000 + i)
            con.execute("INSERT INTO students VALUES(?,?,?,?,?)", (m, rnd.choice(last), rnd.choice(first),
                                                                   rnd.choice(inst["departments"]), rnd.choice([100, 200, 300, 400])))
            for course in inst["courses"]:
                if rnd.random() < 0.5:
                    continue
                ca, ex = rnd.randint(10, 40), rnd.randint(20, 60)
                t = ca + ex
                g = "A" if t >= 70 else "B" if t >= 60 else "C" if t >= 50 else "D" if t >= 45 else "E" if t >= 40 else "F"
                sess = rnd.choice(["2024/2025", "2025/2026"])
                con.execute("INSERT INTO results(matric,course,session,ca,exam,total,grade,approved) VALUES(?,?,?,?,?,?,?,?)",
                            (m, course, sess, ca, ex, t, g, 1 if sess == "2024/2025" else 0))


# ----------------------------------------------------------------- shipping and snapshots
def last_segment():
    with rec() as con:
        return con.execute("SELECT * FROM segments ORDER BY id DESC LIMIT 1").fetchone()


def ship():
    """Copy new journal rows to the recovery store and run the mass-change detector."""
    seg = last_segment()
    start = seg["last_seq"] if seg else 0
    with live() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM journal WHERE seq > ? ORDER BY seq", (start,))]
    if not rows:
        return {"rows": 0}
    raw = json.dumps(rows).encode()
    prev = seg["sha"] if seg else "GENESIS"
    n = os.urandom(12)
    blob = n + AESGCM(key()).encrypt(n, raw, prev.encode())
    name = f"seg_{rows[0]['seq']:09d}_{rows[-1]['seq']:09d}.enc"
    open(os.path.join(store(), "journal", name), "wb").write(blob)
    sha = hashlib.sha256(blob).hexdigest()
    with rec() as con:
        con.execute("INSERT INTO segments(at,first_seq,last_seq,last_ts,rows,file,sha,prev_sha) VALUES(?,?,?,?,?,?,?,?)",
                    (now(), rows[0]["seq"], rows[-1]["seq"], rows[-1]["ts"], len(rows), name, sha, prev))
    detect(rows)
    return {"rows": len(rows), "segment": name}


def detect(rows):
    c = cfg()["detector"]
    cutoff = (dt.datetime.now() - dt.timedelta(seconds=c["window_seconds"])).strftime("%Y-%m-%d %H:%M:%S")
    recent = [r for r in rows if r["ts"] >= cutoff and r["op"] in ("U", "D") and r["tbl"] == "results"]
    grade_flips = 0
    for r in recent:
        if r["op"] == "U" and r["row"]:
            if json.loads(r["row"]).get("grade") == "A":
                grade_flips += 1
    reasons = []
    if len(recent) >= c["max_changes"]:
        reasons.append(f"{len(recent)} result rows changed or deleted in {c['window_seconds']} s")
    if grade_flips >= c["max_grade_a_updates"]:
        reasons.append(f"{grade_flips} results updated to grade A in one burst")
    if reasons:
        freeze("; ".join(reasons))


def freeze(reason):
    with live() as con:
        con.execute("UPDATE control SET frozen=1, reason=? WHERE id=1", (reason[:300],))
    event("critical", f"DATABASE FROZEN: {reason}")


def unfreeze(who):
    with live() as con:
        con.execute("UPDATE control SET frozen=0, reason='' WHERE id=1")
    event("warning", f"database unfrozen by {who}")


def open_amendment(minutes, who, reason):
    until = (dt.datetime.now() + dt.timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    with live() as con:
        con.execute("UPDATE control SET amend_until=? WHERE id=1", (until,))
    event("warning", f"{who} opened a {minutes}-minute amendment window for approved results: {reason}")
    return until


def base_snapshot():
    """Encrypted copy of the whole live database (online backup API, no downtime)."""
    with live() as src:
        mem = sqlite3.connect(":memory:")
        src.backup(mem)
        upto = mem.execute("SELECT COALESCE(MAX(seq),0) FROM journal").fetchone()[0]
        raw = mem.serialize()
        mem.close()
    n = os.urandom(12)
    blob = n + AESGCM(key()).encrypt(n, raw, b"base")
    name = f"base_{upto:09d}_{int(time.time())}.enc"
    open(os.path.join(store(), "bases", name), "wb").write(blob)
    with rec() as con:
        con.execute("INSERT INTO bases(at,upto_seq,bytes,file,sha) VALUES(?,?,?,?,?)",
                    (now(True), upto, len(blob), name, hashlib.sha256(blob).hexdigest()))
    for r in cfg()["store_copies"]:
        shutil.copytree(store(), p(r), dirs_exist_ok=True)
    return {"base": name, "upto_seq": upto, "bytes": len(blob)}


def verify_store():
    problems = []
    prev = "GENESIS"
    with rec() as con:
        segs = con.execute("SELECT * FROM segments ORDER BY id").fetchall()
        bases = con.execute("SELECT * FROM bases").fetchall()
    for s in segs:
        blob = open(os.path.join(store(), "journal", s["file"]), "rb").read()
        if hashlib.sha256(blob).hexdigest() != s["sha"] or s["prev_sha"] != prev:
            problems.append(s["file"])
        else:
            try:
                AESGCM(key()).decrypt(blob[:12], blob[12:], prev.encode())
            except Exception:  # noqa: BLE001
                problems.append(s["file"])
        prev = s["sha"]
    for b in bases:
        blob = open(os.path.join(store(), "bases", b["file"]), "rb").read()
        if hashlib.sha256(blob).hexdigest() != b["sha"]:
            problems.append(b["file"])
    if problems:
        event("critical", f"recovery store problems: {problems[:3]}")
    return {"segments": len(segs), "bases": len(bases), "problems": problems}


# ----------------------------------------------------------------- point-in-time recovery
def journal_rows(after_seq, upto_ts):
    """Rows after a base, up to a time, skipping timelines abandoned by earlier recoveries."""
    out = []
    prev = "GENESIS"
    with rec() as con:
        segs = con.execute("SELECT * FROM segments ORDER BY id").fetchall()
        cuts = [(r["from_seq"], r["to_seq"]) for r in con.execute("SELECT * FROM abandoned")]
    for s in segs:
        blob = open(os.path.join(store(), "journal", s["file"]), "rb").read()
        rows = json.loads(AESGCM(key()).decrypt(blob[:12], blob[12:], prev.encode()))
        prev = s["sha"]
        out += [r for r in rows if r["seq"] > after_seq and r["ts"] <= upto_ts
                and not any(a <= r["seq"] <= b for a, b in cuts)]
    return out


def pitr(target_time=None, output=None):
    """Rebuild the database as it was at target_time ('YYYY-MM-DD HH:MM:SS[.ffffff]')."""
    t0 = time.time()
    target_time = target_time or now(True)
    with rec() as con:
        b = con.execute("SELECT * FROM bases WHERE at <= ? AND abandoned=0 ORDER BY id DESC LIMIT 1",
                        (target_time,)).fetchone()
    if not b:
        raise ValueError("no base snapshot older than the requested time")
    blob = open(os.path.join(store(), "bases", b["file"]), "rb").read()
    raw = AESGCM(key()).decrypt(blob[:12], blob[12:], b"base")
    output = output or live_path()
    tmp = output + ".rebuild"
    if os.path.exists(tmp):
        os.remove(tmp)
    db = sqlite3.connect(tmp)
    mem = sqlite3.connect(":memory:")
    mem.deserialize(raw)
    mem.backup(db)
    mem.close()
    triggers = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")]
    for t in triggers:
        db.execute(f"DROP TRIGGER {t}")
    rows = journal_rows(b["upto_seq"], target_time)
    for r in rows:
        pk = TABLES[r["tbl"]]
        if r["op"] == "D":
            db.execute(f"DELETE FROM {r['tbl']} WHERE {pk}=?", (r["pk"],))
        else:
            row = json.loads(r["row"])
            cols = ",".join(row)
            db.execute(f"INSERT OR REPLACE INTO {r['tbl']}({cols}) VALUES({','.join('?' * len(row))})",
                       list(row.values()))
        db.execute("INSERT OR REPLACE INTO journal(seq,ts,tbl,op,pk,row) VALUES(?,?,?,?,?,?)",
                   (r["seq"], r["ts"], r["tbl"], r["op"], r["pk"], r["row"]))
    db.execute("UPDATE control SET frozen=0, reason='' WHERE id=1")
    # start a new timeline: rows shipped after the recovery point are abandoned, never replayed again,
    # and new journal rows continue after the highest sequence number ever shipped
    last_kept = max([b["upto_seq"]] + [r["seq"] for r in rows])
    seg = last_segment()
    shipped_max = seg["last_seq"] if seg else last_kept
    db.execute("DELETE FROM journal WHERE seq > ?", (last_kept,))
    if shipped_max > last_kept:
        with rec() as con:
            con.execute("INSERT INTO abandoned VALUES(?,?,?)", (last_kept + 1, shipped_max, now()))
            con.execute("UPDATE bases SET abandoned=1 WHERE upto_seq > ?", (last_kept,))
    db.execute("UPDATE sqlite_sequence SET seq=? WHERE name='journal'", (max(shipped_max, last_kept),))
    db.commit()
    db.executescript(trigger_sql())
    db.close()
    for suffix in ("", "-wal", "-shm", "-journal"):
        if suffix and os.path.exists(output + suffix):
            os.remove(output + suffix)
    os.replace(tmp, output)
    secs = time.time() - t0
    with rec() as con:
        con.execute("INSERT INTO recoveries VALUES(?,?,?,?,?)", (now(), target_time, b["id"], len(rows), secs))
    event("info", f"point-in-time recovery to {target_time}: base {b['id']} + {len(rows)} journal rows in {secs:.2f}s")
    return {"target_time": target_time, "base": b["id"], "replayed_rows": len(rows), "seconds": round(secs, 3)}


def table_digest(path=None):
    con = sqlite3.connect(path or live_path())
    h = hashlib.sha256()
    for t, pk in TABLES.items():
        for row in con.execute(f"SELECT * FROM {t} ORDER BY {pk}"):
            h.update(repr(tuple(row)).encode())
    con.close()
    return h.hexdigest()


def probe():
    for name, url in cfg()["services"].items():
        try:
            if url.startswith("sqlite:"):
                c = sqlite3.connect(live_path())
                c.execute("SELECT COUNT(*) FROM results").fetchone()
                c.close()
            else:
                urllib.request.urlopen(url, timeout=3).close()
            up = 1
        except Exception:  # noqa: BLE001
            up = 0
        with rec() as con:
            old = con.execute("SELECT up FROM probes WHERE name=?", (name,)).fetchone()
            con.execute("INSERT OR REPLACE INTO probes VALUES(?,?,?)", (name, up, now()))
        if (old is None and not up) or (old is not None and old["up"] != up):
            event("critical" if not up else "info", f"{name} {'DOWN' if not up else 'UP'}")
