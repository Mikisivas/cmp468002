"""KwaraHarmony: conflict response and mediation case management.

Workflow (only these moves are allowed, each by specific roles):
    reported -> verified -> assigned -> mediation -> agreement -> monitoring -> closed
    any open state -> escalated (handed to security agencies)
    reported -> rejected (false or duplicate report)
    monitoring -> mediation (relapse: new incident in the same community)
Service-level targets: verify within 24 h, assign a mediator within 48 h, first meeting within 7 days.

Access control is attribute-based (ABAC): a decision uses the user's role, the LGAs they cover,
the case's LGA and whether the user is the assigned mediator. Field notes are encrypted per case
with AES-256-GCM (key derived by HKDF from a master key and the case number).
"""
import datetime as dt
import json
import math
import os
import sqlite3
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import geo

DATA = os.path.join(geo.BASE, "data")
OPEN = ("reported", "verified", "assigned", "mediation", "agreement", "monitoring", "escalated")
MOVES = {
    ("reported", "verified"): {"officer", "supervisor"},
    ("reported", "rejected"): {"officer", "supervisor"},
    ("verified", "assigned"): {"supervisor"},
    ("assigned", "mediation"): {"mediator"},
    ("mediation", "agreement"): {"mediator"},
    ("agreement", "monitoring"): {"mediator", "supervisor"},
    ("monitoring", "closed"): {"supervisor"},
    ("monitoring", "mediation"): {"mediator", "supervisor", "system"},
}
for s in OPEN[:-1]:
    MOVES[(s, "escalated")] = {"officer", "supervisor", "mediator"}


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "harmony.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, hash TEXT, role TEXT, lgas TEXT);
    CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, created REAL, lga TEXT, lat REAL, lon REAL, type TEXT, severity INT,
        state TEXT, mediator TEXT, parties TEXT, terms TEXT, compensation_ngn REAL, updated REAL, state_since REAL);
    CREATE TABLE IF NOT EXISTS steps(id INTEGER PRIMARY KEY, case_id INT, ts REAL, who TEXT, from_state TEXT, to_state TEXT, note TEXT);
    CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, case_id INT, ts REAL, who TEXT, nonce BLOB, body BLOB);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, lga TEXT, case_id INT, text TEXT);
    CREATE TABLE IF NOT EXISTS denied(ts REAL, who TEXT, action TEXT, case_id INT);
    """)
    return con


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    open(os.path.join(DATA, "keys", "notes_master.key"), "wb").write(os.urandom(32))


def case_key(case_id):
    master = open(os.path.join(DATA, "keys", "notes_master.key"), "rb").read()
    return HKDF(hashes.SHA256(), 32, salt=b"KwaraHarmony", info=f"case-{case_id}".encode()).derive(master)


# ----------------------------------------------------------------- ABAC
def user(name):
    with db() as con:
        u = con.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
    return {"name": u["name"], "role": u["role"], "lgas": json.loads(u["lgas"])} if u else None


def can(u, action, case=None):
    """Attribute-based access decision. Returns True or False and records every denial."""
    if u is None:
        return False
    r, mine = u["role"], (case is None or "*" in u["lgas"] or case["lga"] in u["lgas"])
    if action == "view":
        ok = r in ("supervisor", "auditor") or (r == "officer" and mine) or (r == "mediator" and case and case["mediator"] == u["name"])
    elif action == "read_notes":
        ok = r == "supervisor" or (r == "mediator" and case and case["mediator"] == u["name"]) or (r == "officer" and mine)
    elif action == "add_note":
        ok = r in ("officer", "mediator") and can(u, "read_notes", case)
    elif action == "create":
        ok = r in ("officer", "supervisor") and mine
    elif action == "export_public":
        ok = r in ("supervisor", "auditor")
    elif action.startswith("move:"):
        to = action[5:]
        roles = MOVES.get((case["state"], to), set())
        ok = r in roles and (r in ("supervisor", "system") or (r == "officer" and mine) or
                             (r == "mediator" and case["mediator"] == u["name"]))
    else:
        ok = False
    if not ok:
        with db() as con:
            con.execute("INSERT INTO denied VALUES(?,?,?,?)", (time.time(), u["name"], action, case.get("id") if case else None))
    return ok


# ----------------------------------------------------------------- cases
def get(case_id):
    with db() as con:
        r = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    return dict(r) if r else None


def create(who, lga_name, kind, severity, parties, lat=None, lon=None, ts=None, check_relapse=True):
    u = user(who) if isinstance(who, str) else who
    if not can(u, "create", {"lga": lga_name}):
        raise PermissionError("not allowed to open cases in this LGA")
    g = geo.lga(lga_name)
    ts = ts or time.time()
    with db() as con:
        cur = con.execute("INSERT INTO cases(created,lga,lat,lon,type,severity,state,parties,updated,state_since) "
                          "VALUES(?,?,?,?,?,?,?,?,?,?)", (ts, lga_name, lat or g["lat"], lon or g["lon"], kind, severity,
                                                         "reported", parties[:200], ts, ts))
        cid = cur.lastrowid
        con.execute("INSERT INTO steps(case_id,ts,who,from_state,to_state,note) VALUES(?,?,?,?,?,?)",
                    (cid, ts, u["name"], None, "reported", "case opened"))
    if check_relapse:
        relapse_check(lga_name, cid, ts)
    return cid


def move(who, case_id, to, note="", mediator=None, terms=None, compensation=None, ts=None):
    u = user(who) if isinstance(who, str) else who
    c = get(case_id)
    if not can(u, f"move:{to}", c):
        raise PermissionError(f"{u['name']} ({u['role']}) may not move case {case_id} from {c['state']} to {to}")
    ts = ts or time.time()
    if to == "assigned":
        m = user(mediator or "")
        if not m or m["role"] != "mediator":
            raise ValueError("choose a registered mediator")
    if to == "agreement" and (not terms or compensation is None):
        raise ValueError("an agreement needs written terms and a compensation amount (0 if none)")
    if to == "closed" and ts - c["state_since"] < geo.cfg()["monitoring_days"] * 86400:
        raise ValueError(f"a case must stay in monitoring for {geo.cfg()['monitoring_days']} days without relapse")
    with db() as con:
        con.execute("UPDATE cases SET state=?, updated=?, state_since=?, mediator=COALESCE(?, mediator), terms=COALESCE(?, terms), "
                    "compensation_ngn=COALESCE(?, compensation_ngn) WHERE id=?", (to, ts, ts, mediator, terms, compensation, case_id))
        con.execute("INSERT INTO steps(case_id,ts,who,from_state,to_state,note) VALUES(?,?,?,?,?,?)",
                    (case_id, ts, u["name"], c["state"], to, note[:300]))
    return get(case_id)


def add_note(who, case_id, text):
    u = user(who) if isinstance(who, str) else who
    c = get(case_id)
    if not can(u, "add_note", c):
        raise PermissionError("not allowed to write notes on this case")
    n = os.urandom(12)
    with db() as con:
        con.execute("INSERT INTO notes(case_id,ts,who,nonce,body) VALUES(?,?,?,?,?)",
                    (case_id, time.time(), u["name"], n, AESGCM(case_key(case_id)).encrypt(n, text.encode(), str(case_id).encode())))


def read_notes(who, case_id):
    u = user(who) if isinstance(who, str) else who
    c = get(case_id)
    if not can(u, "read_notes", c):
        return None
    with db() as con:
        rows = con.execute("SELECT * FROM notes WHERE case_id=? ORDER BY ts", (case_id,)).fetchall()
    return [{"ts": r["ts"], "who": r["who"], "text": AESGCM(case_key(case_id)).decrypt(r["nonce"], r["body"], str(case_id).encode()).decode()}
            for r in rows]


def visible(who):
    u = user(who) if isinstance(who, str) else who
    with db() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM cases ORDER BY updated DESC")]
    out = []
    for r in rows:
        r_ok = u["role"] in ("supervisor", "auditor") or (u["role"] == "officer" and ("*" in u["lgas"] or r["lga"] in u["lgas"])) \
            or (u["role"] == "mediator" and r["mediator"] == u["name"])
        if r_ok:
            out.append(r)
    return out


# ----------------------------------------------------------------- early warning
def relapse_check(lga_name, new_case, ts):
    """A new incident in an LGA where a settled case is being monitored means the agreement
    may be failing: reopen mediation and alert the supervisor."""
    with db() as con:
        mon = con.execute("SELECT id FROM cases WHERE lga=? AND state='monitoring' AND id<>?", (lga_name, new_case)).fetchall()
    for m in mon:
        move("system", m["id"], "mediation", f"relapse: new case {new_case} in {lga_name}", ts=ts)
        with db() as con:
            con.execute("INSERT INTO alerts(ts,lga,case_id,text) VALUES(?,?,?,?)", (ts, lga_name, m["id"],
                        f"RELAPSE in {lga_name}: new incident (case {new_case}) while agreement of case {m['id']} was being "
                        f"monitored. Mediation reopened; call both parties within 24 hours."))


def sla_breaches(now=None):
    now = now or time.time()
    h = geo.cfg()["sla_hours"]
    limits = {"reported": ("verify", h["verify"]), "verified": ("assign", h["assign"]), "assigned": ("first meeting", h["first_meeting"])}
    out = []
    with db() as con:
        for c in con.execute("SELECT * FROM cases WHERE state IN ('reported','verified','assigned')"):
            label, hrs = limits[c["state"]]
            late = (now - c["state_since"]) / 3600 - hrs
            if late > 0:
                out.append({"case": c["id"], "lga": c["lga"], "state": c["state"], "target": label, "hours_late": round(late, 1)})
    return out


def lga_risk(now=None):
    now = now or time.time()
    out = {}
    with db() as con:
        for g in geo.lgas():
            open_cases = con.execute("SELECT severity FROM cases WHERE lga=? AND state IN ('reported','verified','assigned','mediation',"
                                     "'escalated')", (g["name"],)).fetchall()
            recent = con.execute("SELECT COUNT(*) FROM cases WHERE lga=? AND created>?", (g["name"], now - 30 * 86400)).fetchone()[0]
            relapses = con.execute("SELECT COUNT(*) FROM alerts WHERE lga=? AND ts>?", (g["name"], now - 90 * 86400)).fetchone()[0]
            score = sum(r["severity"] for r in open_cases) * 2 + recent * 3 + relapses * 8
            out[g["name"]] = {"open": len(open_cases), "recent_30d": recent, "relapses_90d": relapses, "score": score,
                              "level": "Severe" if score >= 40 else "High" if score >= 25 else "Moderate" if score >= 10 else "Low"}
    return out


def kpis():
    with db() as con:
        closed = con.execute("SELECT created, updated FROM cases WHERE state='closed'").fetchall()
        total = con.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        states = {r["state"]: r["n"] for r in con.execute("SELECT state, COUNT(*) n FROM cases GROUP BY state")}
    days = sorted((c["updated"] - c["created"]) / 86400 for c in closed)
    med = days[len(days) // 2] if days else None
    return {"cases": total, "by_state": states, "median_days_to_close": round(med, 1) if med else None,
            "sla_breaches": len(sla_breaches())}


# ----------------------------------------------------------------- privacy-preserving export
def public_geojson():
    """Locations snapped to a 5 km grid; cells with fewer than k=3 cases are suppressed (k-anonymity)."""
    c = geo.cfg()
    step_lat = c["export_grid_km"] / 110.57
    cells = {}
    with db() as con:
        for r in con.execute("SELECT lat, lon, type, state FROM cases"):
            step_lon = c["export_grid_km"] / (111.32 * math.cos(math.radians(r["lat"])))
            key = (round(math.floor(r["lat"] / step_lat) * step_lat + step_lat / 2, 4),
                   round(math.floor(r["lon"] / step_lon) * step_lon + step_lon / 2, 4))
            cells.setdefault(key, []).append(r)
    feats, suppressed = [], 0
    for (la, lo), rows in cells.items():
        if len(rows) < c["export_k"]:
            suppressed += len(rows)
            continue
        feats.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [lo, la]},
                      "properties": {"cases": len(rows), "open": sum(r["state"] in OPEN for r in rows),
                                     "types": sorted({r["type"] for r in rows})}})
    return {"type": "FeatureCollection", "features": feats,
            "metadata": {"grid_km": c["export_grid_km"], "k": c["export_k"], "suppressed_cases": suppressed,
                         "generated": dt.datetime.now().isoformat(timespec="seconds")}}
