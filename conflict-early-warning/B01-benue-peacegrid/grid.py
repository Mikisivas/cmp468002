"""BenuePeaceGrid engine: hexagonal risk grid scored with AHP weights.

1. The state is covered with pointy-top hexagons (default 9 km across).
2. Five factors are measured for every hexagon and scaled 0..1.
3. Factor weights come from the Analytic Hierarchy Process (Saaty): a pairwise comparison
   matrix agreed with stakeholders (police, farmers' and herders' associations, SEMA) is
   turned into weights with the principal eigenvector, and its consistency ratio must be
   below 0.10 or the matrix is rejected.
4. Score = 100 x sum(weight x factor) x season multiplier, capped at 100.
"""
import base64
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import sqlite3
import time

from cryptography.fernet import Fernet

import geo

BASE = geo.BASE
DATA = os.path.join(BASE, "data")
RANDOM_INDEX = {1: 0.0, 2: 0.0, 3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45}


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "peacegrid.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS hexes(id TEXT PRIMARY KEY, lat REAL, lon REAL, lga TEXT, ring TEXT);
    CREATE TABLE IF NOT EXISTS scores(hex TEXT, at REAL, score REAL, level TEXT, factors TEXT);
    CREATE INDEX IF NOT EXISTS sc ON scores(hex, at);
    CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, ts REAL, lga TEXT, lat REAL, lon REAL, type TEXT,
        severity INT, fatalities INT, source TEXT, reporter TEXT, phone_enc TEXT, note TEXT, verified INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS pings(id INTEGER PRIMARY KEY, ts REAL, device TEXT, lat REAL, lon REAL, heads INT);
    CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, secret TEXT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, hex TEXT, lga TEXT, level TEXT, message TEXT,
        recipients TEXT);
    CREATE TABLE IF NOT EXISTS contacts(lga TEXT, role TEXT, name TEXT, phone_enc TEXT);
    CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, who TEXT, what TEXT, h TEXT);
    """)
    return con


def audit(who, what):
    with db() as con:
        prev = con.execute("SELECT h FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        ts = time.time()
        h = hashlib.sha256(f"{prev['h'] if prev else ''}|{ts}|{who}|{what}".encode()).hexdigest()
        con.execute("INSERT INTO audit(ts,who,what,h) VALUES(?,?,?,?)", (ts, who, what, h))


# ----------------------------------------------------------------- secrets
def keyfile():
    return os.path.join(DATA, "keys", "data.key")


def fernet():
    return Fernet(open(keyfile(), "rb").read())


def pepper():
    return open(os.path.join(DATA, "keys", "pepper.bin"), "rb").read()


def init_keys():
    os.makedirs(os.path.dirname(keyfile()), exist_ok=True)
    open(keyfile(), "wb").write(Fernet.generate_key())
    open(os.path.join(DATA, "keys", "pepper.bin"), "wb").write(os.urandom(32))


def reporter_id(phone):
    """Pseudonymous reporter ID: HMAC of the phone number, so analysts can count repeat reporters
    without seeing the number. The number itself is stored only encrypted."""
    return hmac.new(pepper(), phone.strip().encode(), hashlib.sha256).hexdigest()[:16]


# ----------------------------------------------------------------- AHP
def ahp():
    m = geo.cfg()["ahp"]["pairwise"]
    n = len(m)
    w = [1.0 / n] * n
    for _ in range(100):  # power iteration for the principal eigenvector
        nw = [sum(m[i][j] * w[j] for j in range(n)) for i in range(n)]
        s = sum(nw)
        nw = [x / s for x in nw]
        if max(abs(a - b) for a, b in zip(w, nw)) < 1e-12:
            break
        w = nw
    lam = sum(sum(m[i][j] * w[j] for j in range(n)) / w[i] for i in range(n)) / n
    ci = (lam - n) / (n - 1)
    cr = ci / RANDOM_INDEX[n] if RANDOM_INDEX[n] else 0.0
    return {"factors": geo.cfg()["ahp"]["factors"], "weights": [round(x, 4) for x in w], "lambda_max": round(lam, 4),
            "ci": round(ci, 4), "cr": round(cr, 4), "consistent": cr < 0.10}


# ----------------------------------------------------------------- hex grid
def hex_ring(lat, lon, size_km):
    kx = 111.32 * math.cos(math.radians(lat))
    ring = []
    for k in range(7):
        ang = math.radians(60 * (k % 6) - 30)
        ring.append([round(lon + size_km * math.cos(ang) / kx, 5), round(lat + size_km * math.sin(ang) / 110.57, 5)])
    return ring


def build_grid():
    size = geo.cfg()["hex_km"] / 2  # centre to corner
    s, w, n, e = geo.bbox(0.2)
    lat0 = (s + n) / 2
    kx = 111.32 * math.cos(math.radians(lat0))
    dx = math.sqrt(3) * size / kx
    dy = 1.5 * size / 110.57
    cells, row, lat = [], 0, s
    while lat <= n:
        lon = w + (dx / 2 if row % 2 else 0)
        while lon <= e:
            near = geo.nearest_lga(lat, lon)
            g = geo.lga(near)
            if geo.km(lat, lon, g["lat"], g["lon"]) <= 32:  # keep cells within reach of an LGA HQ
                cells.append((f"H{row:03d}-{int((lon - w) / dx):03d}", round(lat, 5), round(lon, 5), near,
                              json.dumps(hex_ring(lat, lon, size))))
            lon += dx
        lat += dy
        row += 1
    with db() as con:
        con.execute("DELETE FROM hexes")
        con.executemany("INSERT INTO hexes VALUES(?,?,?,?,?)", cells)
    return len(cells)


# ----------------------------------------------------------------- factors
def factors(at=None):
    at = at or time.time()
    c = geo.cfg()
    with db() as con:
        hexes = con.execute("SELECT * FROM hexes").fetchall()
        inc = con.execute("SELECT * FROM incidents WHERE ts BETWEEN ? AND ?", (at - 90 * 86400, at)).fetchall()
        pings = con.execute("SELECT * FROM pings WHERE ts BETWEEN ? AND ?", (at - 86400, at)).fetchall()
    farms = geo.farmland()
    farm_pts = [(sum(p[1] for p in f["ring"][:4]) / 4, sum(p[0] for p in f["ring"][:4]) / 4) for f in farms]
    raw = {}
    for h in hexes:
        la, lo = h["lat"], h["lon"]
        heat = 0.0
        for i in inc:
            d = geo.km(la, lo, i["lat"], i["lon"])
            if d < 15:
                age_days = (at - i["ts"]) / 86400
                heat += i["severity"] * 0.5 ** (age_days / 21) * math.exp(-d / 6)
        herds = sum(p["heads"] for p in pings if geo.km(la, lo, p["lat"], p["lon"]) < 10)
        route = min(geo.dist_to_polyline(la, lo, r) for r in c["routes"].values())
        water = min(geo.km(la, lo, w[1], w[2]) for w in c["water"])
        farm = sum(1 for fl, fo in farm_pts if geo.km(la, lo, fl, fo) < 8)
        raw[h["id"]] = [heat, herds, math.exp(-route / 10), farm, math.exp(-water / 15)]
    # scale incidents, herds and farms to 0..1 by the state maximum (min-max)
    for k in (0, 1, 3):
        top = max((v[k] for v in raw.values()), default=0) or 1
        for v in raw.values():
            v[k] = v[k] / top
    return hexes, raw


def level(score):
    for limit, name in geo.cfg()["levels"]:
        if score < limit:
            return name
    return "Severe"


def score_all(at=None, store=True):
    at = at or time.time()
    w = ahp()
    if not w["consistent"]:
        raise ValueError(f"AHP matrix inconsistent (CR = {w['cr']}); fix the pairwise comparisons")
    season = geo.season_factor(dt.datetime.fromtimestamp(at).month)
    hexes, raw = factors(at)
    out = []
    for h in hexes:
        f = raw[h["id"]]
        s = min(100.0, 100 * sum(a * b for a, b in zip(w["weights"], f)) * (0.6 + 0.4 * season))
        out.append({"hex": h["id"], "lga": h["lga"], "lat": h["lat"], "lon": h["lon"], "score": round(s, 1),
                    "level": level(s), "factors": dict(zip(w["factors"], [round(x, 3) for x in f]))})
    if store:
        with db() as con:
            con.executemany("INSERT INTO scores VALUES(?,?,?,?,?)",
                            [(o["hex"], at, o["score"], o["level"], json.dumps(o["factors"])) for o in out])
        dispatch(out, at)
    return out


def latest_scores():
    with db() as con:
        t = con.execute("SELECT MAX(at) t FROM scores").fetchone()["t"]
        rows = con.execute("SELECT s.*, h.lga, h.ring FROM scores s JOIN hexes h ON h.id=s.hex WHERE s.at=?",
                           (t,)).fetchall() if t else []
    return t, rows


# ----------------------------------------------------------------- alerts
def dispatch(scores, at):
    c = geo.cfg()
    hot = {}
    for s in scores:
        if s["score"] >= c["alert_score"]:
            hot.setdefault(s["lga"], []).append(s)
    sent = []
    for lga_name, cells in hot.items():
        worst = max(cells, key=lambda x: x["score"])
        with db() as con:
            recent = con.execute("SELECT 1 FROM alerts WHERE lga=? AND ts>?",
                                 (lga_name, at - c["alert_cooldown_hours"] * 3600)).fetchone()
            contacts = con.execute("SELECT role, name FROM contacts WHERE lga=?", (lga_name,)).fetchall()
        if recent:
            continue
        top = max(worst["factors"], key=worst["factors"].get).replace("_", " ")
        msg = (f"BenuePeaceGrid {worst['level'].upper()} risk in {lga_name}: {len(cells)} grid cell(s) at or above "
               f"{c['alert_score']}. Main driver: {top}. Deploy patrol and call peace committee.")
        with db() as con:
            con.execute("INSERT INTO alerts(ts,hex,lga,level,message,recipients) VALUES(?,?,?,?,?,?)",
                        (at, worst["hex"], lga_name, worst["level"], msg, ", ".join(f"{r['role']} {r['name']}" for r in contacts)))
        sent.append(lga_name)
    return sent


# ----------------------------------------------------------------- devices
def register_device(dev_id):
    secret = base64.b16encode(os.urandom(24)).decode().lower()
    with db() as con:
        con.execute("INSERT OR REPLACE INTO devices VALUES(?,?)", (dev_id, secret))
    return secret


def verify_ping(dev_id, ts, body, sig):
    with db() as con:
        d = con.execute("SELECT secret FROM devices WHERE id=?", (dev_id,)).fetchone()
    if not d or abs(time.time() - float(ts)) > 300:
        return False
    exp = hmac.new(d["secret"].encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(exp, sig)


def in_state(lat, lon):
    s, w, n, e = geo.bbox(0.3)
    return s <= lat <= n and w <= lon <= e


# ----------------------------------------------------------------- evaluation
def backtest(split_days=60, horizon_days=30, top_share=0.2):
    """Score the grid as it looked `split_days` ago, then check how many of the incidents in the
    following `horizon_days` fell inside the top 20% riskiest cells (hit rate) compared with
    the 20% expected by chance."""
    at = time.time() - split_days * 86400
    scores = sorted(score_all(at, store=False), key=lambda x: -x["score"])
    top = {s["hex"] for s in scores[:max(1, int(len(scores) * top_share))]}
    with db() as con:
        hexes = con.execute("SELECT id, lat, lon FROM hexes").fetchall()
        future = con.execute("SELECT * FROM incidents WHERE ts BETWEEN ? AND ?",
                             (at, at + horizon_days * 86400)).fetchall()
    hits = 0
    for i in future:
        cell = min(hexes, key=lambda h: geo.km(i["lat"], i["lon"], h["lat"], h["lon"]))
        hits += cell["id"] in top
    rate = hits / len(future) if future else 0
    return {"cells": len(scores), "top_cells": len(top), "future_incidents": len(future), "captured": hits,
            "hit_rate": round(rate, 3), "chance_rate": top_share, "lift": round(rate / top_share, 2) if future else None}
