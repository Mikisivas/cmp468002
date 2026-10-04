"""YolaShield tamper-evident report ledger.

Reports are stored in two parts:
  * the record (phone, details) encrypted with Fernet in the `records` table; it can be erased
    on a valid data-protection request;
  * a SHA-256 fingerprint of the record in the ledger.
Every few reports (or every 10 minutes) the pending fingerprints are sealed into a block:
  block = {height, time, previous block hash, Merkle root of the fingerprints, fingerprints}
  block hash = SHA-256(block), and the block is signed with the ledger's Ed25519 key.
Each new block hash is also written to a "witness" file kept by an outside party (here: the
Adamawa State Peace Commission). Anyone with the public key can re-check the whole chain, and
nobody can quietly delete or edit a report, even a database administrator.
"""
import hashlib
import json
import os
import sqlite3
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import geo

DATA = os.path.join(geo.BASE, "data")
TYPE_CODES = ["crop_destruction", "cattle_rustling", "armed_attack", "threat", "blocked_route"]


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "yolashield.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS records(ref TEXT PRIMARY KEY, ts REAL, channel TEXT, session TEXT UNIQUE, enc TEXT, lga TEXT,
        type TEXT, urgent INT, fingerprint TEXT, block INT, erased INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, ts REAL, prev TEXT, merkle TEXT, items TEXT, hash TEXT, sig TEXT);
    CREATE TABLE IF NOT EXISTS history(ts REAL, lga TEXT, type TEXT, severity INT);
    CREATE TABLE IF NOT EXISTS mediation(ref TEXT PRIMARY KEY, ts REAL, lga TEXT, enc TEXT, status TEXT);
    CREATE TABLE IF NOT EXISTS admins(name TEXT PRIMARY KEY, salt TEXT, hash TEXT);
    """)
    return con


def kpath(name):
    return os.path.join(DATA, "keys", name)


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    open(kpath("records.key"), "wb").write(Fernet.generate_key())
    sk = Ed25519PrivateKey.generate()
    open(kpath("ledger_signing.pem"), "wb").write(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                   serialization.NoEncryption()))
    open(kpath("ledger_public.pem"), "wb").write(sk.public_key().public_bytes(serialization.Encoding.PEM,
                                                                              serialization.PublicFormat.SubjectPublicKeyInfo))
    open(kpath("gateway.token"), "w").write(os.urandom(18).hex())
    os.makedirs(os.path.join(DATA, "witness_peace_commission"), exist_ok=True)


def fernet():
    return Fernet(open(kpath("records.key"), "rb").read())


def fingerprint(rec):
    return hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()


def add(channel, session, phone, lga_name, type_code, urgent):
    """Store one report. A USSD session can submit only once (telcos retry requests)."""
    ts = time.time()
    with db() as con:
        old = con.execute("SELECT ref FROM records WHERE session=?", (session,)).fetchone()
        if old:
            return old["ref"]
        n = con.execute("SELECT COUNT(*) FROM records").fetchone()[0] + 1
    ref = f"YS{n:05d}"
    rec = {"ref": ref, "ts": round(ts, 3), "channel": channel, "lga": lga_name, "type": type_code, "urgent": bool(urgent),
           "phone": phone}
    with db() as con:
        con.execute("INSERT INTO records(ref,ts,channel,session,enc,lga,type,urgent,fingerprint) VALUES(?,?,?,?,?,?,?,?,?)",
                    (ref, ts, channel, session, fernet().encrypt(json.dumps(rec).encode()).decode(), lga_name, type_code,
                     int(urgent), fingerprint(rec)))
    seal_if_due()
    return ref


def merkle(leaves):
    level = [bytes.fromhex(x) for x in leaves] or [hashlib.sha256(b"").digest()]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def seal_if_due(force=False):
    c = geo.cfg()
    with db() as con:
        pending = con.execute("SELECT ref, ts, fingerprint FROM records WHERE block IS NULL ORDER BY ts").fetchall()
    if not pending:
        return None
    if not force and len(pending) < c["block_size"] and time.time() - pending[0]["ts"] < c["block_seconds"]:
        return None
    with db() as con:
        last = con.execute("SELECT * FROM blocks ORDER BY height DESC LIMIT 1").fetchone()
    height = (last["height"] + 1) if last else 0
    prev = last["hash"] if last else "0" * 64
    items = [r["fingerprint"] for r in pending]
    body = {"height": height, "ts": round(time.time(), 3), "prev": prev, "merkle": merkle(items), "items": items}
    raw = json.dumps(body, sort_keys=True).encode()
    h = hashlib.sha256(raw).hexdigest()
    sk = serialization.load_pem_private_key(open(kpath("ledger_signing.pem"), "rb").read(), None)
    sig = sk.sign(raw).hex()
    with db() as con:
        con.execute("INSERT INTO blocks VALUES(?,?,?,?,?,?,?)", (height, body["ts"], prev, body["merkle"], json.dumps(items), h, sig))
        con.executemany("UPDATE records SET block=? WHERE ref=?", [(height, r["ref"]) for r in pending])
    with open(os.path.join(DATA, "witness_peace_commission", "block_hashes.txt"), "a") as fh:
        fh.write(f"{height} {h}\n")
    return {"height": height, "hash": h, "items": len(items)}


def verify():
    """Check signatures, hash links, Merkle roots, the outside witness copy, and that every
    stored record (unless lawfully erased) still matches its fingerprint in the ledger."""
    pub = serialization.load_pem_public_key(open(kpath("ledger_public.pem"), "rb").read())
    witness = {}
    wf = os.path.join(DATA, "witness_peace_commission", "block_hashes.txt")
    if os.path.exists(wf):
        for line in open(wf):
            hgt, hh = line.split()
            witness[int(hgt)] = hh
    problems, prev, sealed = [], "0" * 64, {}
    with db() as con:
        blocks = con.execute("SELECT * FROM blocks ORDER BY height").fetchall()
        records = con.execute("SELECT * FROM records").fetchall()
    for i, b in enumerate(blocks):
        items = json.loads(b["items"])
        body = {"height": b["height"], "ts": b["ts"], "prev": b["prev"], "merkle": b["merkle"], "items": items}
        raw = json.dumps(body, sort_keys=True).encode()
        h = hashlib.sha256(raw).hexdigest()
        if b["height"] != i:
            problems.append(f"block {i} missing")
        if b["prev"] != prev:
            problems.append(f"block {b['height']}: broken link")
        if h != b["hash"] or witness.get(b["height"]) != h:
            problems.append(f"block {b['height']}: hash differs from witness copy")
        try:
            pub.verify(bytes.fromhex(b["sig"]), raw)
        except Exception:  # noqa: BLE001
            problems.append(f"block {b['height']}: bad signature")
        if merkle(items) != b["merkle"]:
            problems.append(f"block {b['height']}: Merkle root mismatch")
        for it in items:
            sealed[it] = b["height"]
        prev = b["hash"]
    if len(witness) > len(blocks):
        problems.append(f"{len(witness) - len(blocks)} block(s) deleted (witness has more)")
    for r in records:
        if r["block"] is None:
            continue
        if r["fingerprint"] not in sealed:
            problems.append(f"record {r['ref']}: fingerprint not in ledger")
        elif not r["erased"]:
            rec = json.loads(fernet().decrypt(r["enc"].encode()))
            if fingerprint(rec) != r["fingerprint"] or rec["lga"] != r["lga"] or rec["type"] != r["type"]:
                problems.append(f"record {r['ref']}: content changed after sealing")
    in_db = {r["fingerprint"] for r in records}
    missing = [f for f in sealed if f not in in_db]
    if missing:
        problems.append(f"{len(missing)} sealed report(s) deleted from the database")
    return {"blocks": len(blocks), "records": len(records), "ok": not problems, "problems": problems}


def erase(ref, reason):
    """Data-protection erasure: the personal record is destroyed, the fingerprint stays in the
    ledger, so the chain still verifies and the count of reports is preserved."""
    with db() as con:
        con.execute("UPDATE records SET enc='', erased=1 WHERE ref=?", (ref,))
    return {"erased": ref, "reason": reason}


def risk():
    """Per-LGA alert level from severity-weighted events in the last 30 days (14-day half-life)."""
    sev = {"crop_destruction": 2, "cattle_rustling": 3, "armed_attack": 4, "threat": 2, "blocked_route": 2}
    now = time.time()
    score = {g["name"]: 0.0 for g in geo.lgas()}
    with db() as con:
        for r in con.execute("SELECT ts, lga, type, urgent FROM records WHERE ts>?", (now - 30 * 86400,)):
            score[r["lga"]] += sev[r["type"]] * (1.5 if r["urgent"] else 1) * 0.5 ** ((now - r["ts"]) / (14 * 86400))
        for r in con.execute("SELECT ts, lga, severity FROM history WHERE ts>?", (now - 30 * 86400,)):
            score[r["lga"]] += r["severity"] * 0.5 ** ((now - r["ts"]) / (14 * 86400))
    out = {}
    for g, s in score.items():
        out[g] = {"score": round(s, 1), "level": "Severe" if s >= 20 else "High" if s >= 12 else "Moderate" if s >= 5 else "Low"}
    return out
