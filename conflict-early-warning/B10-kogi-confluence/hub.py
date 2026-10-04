"""ConfluenceEWS hub: storage, device registry, signed sync protocol and risk table.

Sync protocol (field tablet -> hub), designed for patchy 2G/3G in Ibaji, Omala and Bassa:
  body = {"device", "counter", "reports": [...], "since_risk"}; header X-Sig = HMAC-SHA256(device key, body)
  * counter must be higher than the last accepted one for that device -> a captured request cannot be replayed;
  * every report has a UUID created on the tablet -> a retried upload never creates duplicates;
  * a report edited offline carries a version number; the hub keeps the highest version
    (ties broken by the later edit time) -> conflict resolution is deterministic;
  * the reply carries the acknowledged UUIDs and the current LGA risk table, so tablets that are
    offline later still show recent risk levels.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import time

import geo
import model

DATA = os.path.join(geo.BASE, "data")
MODEL = os.path.join(DATA, "risk_model.json")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "hub.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, key TEXT, officer TEXT, lga TEXT, last_counter INT DEFAULT 0, last_sync REAL);
    CREATE TABLE IF NOT EXISTS reports(uuid TEXT PRIMARY KEY, device TEXT, created REAL, edited REAL, version INT, lga TEXT, type TEXT,
        severity INT, note TEXT, received REAL);
    CREATE TABLE IF NOT EXISTS history(ts REAL, lga TEXT, type TEXT, severity INT);
    CREATE TABLE IF NOT EXISTS sync_log(id INTEGER PRIMARY KEY, ts REAL, device TEXT, counter INT, result TEXT, new INT, updated INT,
        duplicates INT);
    CREATE TABLE IF NOT EXISTS risk(lga TEXT PRIMARY KEY, prob REAL, level TEXT, at REAL);
    CREATE TABLE IF NOT EXISTS admins(name TEXT PRIMARY KEY, salt TEXT, hash TEXT);
    """)
    return con


def register(device, officer, lga_name):
    key = os.urandom(32).hex()
    with db() as con:
        con.execute("INSERT OR REPLACE INTO devices(id,key,officer,lga) VALUES(?,?,?,?)", (device, key, officer, lga_name))
    return key


def sign(key, body):
    return hmac.new(bytes.fromhex(key), body, hashlib.sha256).hexdigest()


def incidents():
    with db() as con:
        rows = [dict(r) for r in con.execute("SELECT ts, lga, type, severity FROM history")]
        rows += [{"ts": r["created"], "lga": r["lga"], "type": r["type"], "severity": r["severity"]}
                 for r in con.execute("SELECT created, lga, type, severity FROM reports")]
    return rows


def sync(body, sig):
    try:
        d = json.loads(body)
        dev = str(d["device"])
        counter = int(d["counter"])
    except (ValueError, KeyError, TypeError):
        return 400, {"error": "malformed"}
    with db() as con:
        row = con.execute("SELECT * FROM devices WHERE id=?", (dev,)).fetchone()
    if not row:
        return 401, {"error": "unknown device"}

    def log(result, n=0, u=0, dup=0):
        with db() as con:
            con.execute("INSERT INTO sync_log(ts,device,counter,result,new,updated,duplicates) VALUES(?,?,?,?,?,?,?)",
                        (time.time(), dev, counter, result, n, u, dup))
    if not hmac.compare_digest(sign(row["key"], body), sig or ""):
        log("bad signature")
        return 401, {"error": "bad signature"}
    if counter <= row["last_counter"]:
        log("replay refused")
        return 409, {"error": "counter already used (replay)"}
    names = {g["name"] for g in geo.lgas()}
    new = upd = dup = 0
    acked = []
    with db() as con:
        for r in d.get("reports", [])[:500]:
            if r.get("lga") not in names or r.get("type") not in geo.TYPES or not 1 <= int(r.get("severity", 0)) <= 5:
                continue
            old = con.execute("SELECT version, edited FROM reports WHERE uuid=?", (r["uuid"],)).fetchone()
            if old is None:
                con.execute("INSERT INTO reports VALUES(?,?,?,?,?,?,?,?,?,?)", (r["uuid"], dev, float(r["created"]), float(r["edited"]),
                                                                              int(r["version"]), r["lga"], r["type"], int(r["severity"]),
                                                                              str(r.get("note", ""))[:300], time.time()))
                new += 1
            elif (int(r["version"]), float(r["edited"])) > (old["version"], old["edited"]):
                con.execute("UPDATE reports SET version=?, edited=?, lga=?, type=?, severity=?, note=? WHERE uuid=?",
                            (int(r["version"]), float(r["edited"]), r["lga"], r["type"], int(r["severity"]), str(r.get("note", ""))[:300],
                             r["uuid"]))
                upd += 1
            else:
                dup += 1
            acked.append(r["uuid"])
        con.execute("UPDATE devices SET last_counter=?, last_sync=? WHERE id=?", (counter, time.time(), dev))
    log("ok", new, upd, dup)
    if new or upd:
        score()  # rescore first, so the tablet takes home risk levels that include its own reports
    with db() as con:
        risk = {r["lga"]: {"prob": r["prob"], "level": r["level"]} for r in con.execute("SELECT * FROM risk")}
    return 200, {"acked": acked, "new": new, "updated": upd, "duplicates": dup, "risk": risk}


def level(p):
    return "Severe" if p >= 0.6 else "High" if p >= 0.4 else "Moderate" if p >= 0.2 else "Low"


def train():
    m, ev = model.train_and_evaluate(incidents(), time.time(), MODEL)
    return ev


def score(now=None):
    now = now or time.time()
    m = model.Logistic.from_dict(json.load(open(MODEL))["model"])
    inc = incidents()
    out = {}
    with db() as con:
        for g in geo.lgas():
            p = m.predict(model.features(inc, g["name"], now))
            out[g["name"]] = round(p, 3)
            con.execute("INSERT OR REPLACE INTO risk VALUES(?,?,?,?)", (g["name"], round(p, 3), level(p), now))
    return out
