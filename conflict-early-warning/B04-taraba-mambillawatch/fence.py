"""MambillaWatch geofencing engine.

Each GPS collar has its own key and a message counter. A ping is accepted only if
HMAC-SHA256(key, device|counter|lat|lon|battery) matches AND the counter is higher than
the last one seen, so a recorded ping cannot be replayed (no clock needed on the collar).
A ping that implies a speed above 12 km/h (cattle walk 2-5 km/h) is flagged as a possible
spoofed or tampered collar and is not used for geofencing.

Rules (checked for every accepted ping):
  BREACH    herd inside farmland whose crop is in the field this month
  APPROACH  herd within 2 km of such farmland and moving toward it (ETA from velocity)
  DEVIATION herd more than 3 km outside every corridor and every grazing reserve
  RESTRICTED herd inside a protected area
Every alert goes to BOTH the farmers' leader and the herders' leader of the LGA, so both
communities hear the same warning at the same time.
"""
import datetime as dt
import hashlib
import hmac
import math
import os
import sqlite3
import time

import geo

DATA = os.path.join(geo.BASE, "data")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "mambilla.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS collars(id TEXT PRIMARY KEY, herd TEXT, owner_group TEXT, heads INT, key TEXT, last_counter INT,
        last_ts REAL, last_lat REAL, last_lon REAL, battery INT, state TEXT);
    CREATE TABLE IF NOT EXISTS pings(id INTEGER PRIMARY KEY, ts REAL, collar TEXT, counter INT, lat REAL, lon REAL,
        speed REAL, accepted INT, reason TEXT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, collar TEXT, kind TEXT, lga TEXT, zone TEXT,
        eta_min REAL, text TEXT, sent_to TEXT);
    CREATE TABLE IF NOT EXISTS leaders(lga TEXT, community TEXT, name TEXT);
    CREATE TABLE IF NOT EXISTS staff(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    """)
    return con


def farms():
    """Farmland from geo.farmland() with the crop calendar attached."""
    cal = geo.cfg()["crop_calendar"]
    out = []
    for f in geo.farmland(seed=21):
        start, end = cal.get(f["crop"], [5, 10])
        out.append({**f, "season": (start, end)})
    return out


def in_season(farm, month):
    a, b = farm["season"]
    return a <= month <= b if a <= b else (month >= a or month <= b)


def circle_zone(name, lat, lon, radius_km):
    return {"name": name, "lat": lat, "lon": lon, "r": radius_km}


def register(collar_id, herd, group, heads):
    key = os.urandom(32).hex()
    with db() as con:
        con.execute("INSERT OR REPLACE INTO collars VALUES(?,?,?,?,?,0,NULL,NULL,NULL,100,'new')",
                    (collar_id, herd, group, heads, key))
    return key


def sign(key, collar_id, counter, lat, lon, battery):
    msg = f"{collar_id}|{counter}|{lat:.5f}|{lon:.5f}|{battery}".encode()
    return hmac.new(bytes.fromhex(key), msg, hashlib.sha256).hexdigest()


def accept(collar_id, counter, lat, lon, battery, sig, now=None):
    """Validate one ping. Returns (accepted, reason, alerts)."""
    now = now or time.time()
    with db() as con:
        c = con.execute("SELECT * FROM collars WHERE id=?", (collar_id,)).fetchone()
    if not c:
        return False, "unknown collar", []
    if not hmac.compare_digest(sign(c["key"], collar_id, counter, lat, lon, battery), sig):
        return _log(now, collar_id, counter, lat, lon, None, 0, "bad signature")
    if counter <= c["last_counter"]:
        return _log(now, collar_id, counter, lat, lon, None, 0, "replayed or out-of-order counter")
    s, w, n, e = geo.bbox(0.5)
    if not (s <= lat <= n and w <= lon <= e):
        return _log(now, collar_id, counter, lat, lon, None, 0, "outside Taraba State")
    speed = None
    if c["last_ts"]:
        hours = max((now - c["last_ts"]) / 3600, 1 / 3600)
        speed = geo.km(c["last_lat"], c["last_lon"], lat, lon) / hours
        if speed > geo.cfg()["max_speed_kmh"]:
            with db() as con:
                con.execute("UPDATE collars SET last_counter=?, state='suspect' WHERE id=?", (counter, collar_id))
            _alert(now, collar_id, "SPOOF", geo.nearest_lga(lat, lon), "-", None,
                   f"Collar {collar_id} jumped at {speed:.0f} km/h: possible GPS spoofing or a collar moved by vehicle. "
                   f"Position ignored; send a ranger to check.", to_staff_only=True)
            return _log(now, collar_id, counter, lat, lon, speed, 0, "impossible speed")
    with db() as con:
        con.execute("UPDATE collars SET last_counter=?, last_ts=?, last_lat=?, last_lon=?, battery=?, state='ok' WHERE id=?",
                    (counter, now, lat, lon, battery, collar_id))
    if battery < 15:
        _alert(now, collar_id, "BATTERY", geo.nearest_lga(lat, lon), "-", None,
               f"Collar {collar_id} battery {battery}%. Replace within 48 hours.", to_staff_only=True)
    prev = (c["last_lat"], c["last_lon"], c["last_ts"]) if c["last_ts"] else None
    alerts = evaluate(collar_id, c, lat, lon, prev, now)
    _log(now, collar_id, counter, lat, lon, speed, 1, "ok")
    return True, "ok", alerts


def _log(now, collar_id, counter, lat, lon, speed, ok, reason):
    with db() as con:
        con.execute("INSERT INTO pings(ts,collar,counter,lat,lon,speed,accepted,reason) VALUES(?,?,?,?,?,?,?,?)",
                    (now, collar_id, counter, lat, lon, speed, ok, reason))
    return bool(ok), reason, []


def centroid(ring):
    return sum(p[1] for p in ring[:-1]) / (len(ring) - 1), sum(p[0] for p in ring[:-1]) / (len(ring) - 1)


def edge_km(lat, lon, ring):
    return geo.dist_to_polyline(lat, lon, [(p[1], p[0]) for p in ring])


def evaluate(collar_id, collar, lat, lon, prev, now):
    c = geo.cfg()
    month = dt.datetime.fromtimestamp(now).month
    out = []
    lga_name = geo.nearest_lga(lat, lon)
    for f in farms():
        if not in_season(f, month):
            continue
        if geo.point_in_polygon(lat, lon, f["ring"]):
            out.append(_alert(now, collar_id, "BREACH", f["lga"], f["name"], 0,
                              f"BREACH: herd {collar['herd']} ({collar['heads']} cattle) is inside {f['name']} while "
                              f"{f['crop']} is in the field. Herder leader: move the herd now. Farmer leader: do not confront; "
                              f"mediator is on the way."))
            continue
        d = edge_km(lat, lon, f["ring"])
        if d <= c["approach_km"] and prev:
            flat, flon = centroid(f["ring"])
            d_before = geo.km(prev[0], prev[1], flat, flon)
            d_now = geo.km(lat, lon, flat, flon)
            hours = max((now - prev[2]) / 3600, 1e-6)
            closing = (d_before - d_now) / hours  # km per hour toward the farm
            if closing > 0.3:
                eta = 60 * d / closing
                out.append(_alert(now, collar_id, "APPROACH", f["lga"], f["name"], eta,
                                  f"APPROACH: herd {collar['herd']} is {d:.1f} km from {f['name']} ({f['crop']} in season) "
                                  f"and closing at {closing:.1f} km/h, arrival in about {eta:.0f} minutes. Herder leader: turn "
                                  f"the herd to the corridor."))
    for name, lat0, lon0, r in c["restricted"]:
        if geo.km(lat, lon, lat0, lon0) <= r:
            out.append(_alert(now, collar_id, "RESTRICTED", lga_name, name, None,
                              f"RESTRICTED: herd {collar['herd']} entered {name}. Park rangers informed."))
    on_corridor = min(geo.dist_to_polyline(lat, lon, r) for r in c["routes"].values()) <= c["corridor_km"]
    in_reserve = any(geo.km(lat, lon, la, lo) <= r for _, la, lo, r in c["reserves"])
    if not on_corridor and not in_reserve:
        out.append(_alert(now, collar_id, "DEVIATION", lga_name, "-", None,
                          f"DEVIATION: herd {collar['herd']} is outside the agreed corridor and reserves near {lga_name}."))
    return [a for a in out if a]


def _alert(now, collar_id, kind, lga_name, zone, eta, text, to_staff_only=False):
    cool = geo.cfg()["alert_cooldown_minutes"] * 60
    with db() as con:
        if con.execute("SELECT 1 FROM alerts WHERE collar=? AND kind=? AND zone=? AND ts>?",
                       (collar_id, kind, zone, now - cool)).fetchone():
            return None
        leaders = [] if to_staff_only else con.execute("SELECT community, name FROM leaders WHERE lga=?",
                                                       (lga_name,)).fetchall()
        to = ", ".join(f"{r['community']}: {r['name']}" for r in leaders) or "control room"
        con.execute("INSERT INTO alerts(ts,collar,kind,lga,zone,eta_min,text,sent_to) VALUES(?,?,?,?,?,?,?,?)",
                    (now, collar_id, kind, lga_name, zone, eta, text, to))
    return {"kind": kind, "lga": lga_name, "zone": zone, "eta_min": None if eta is None else round(eta, 1), "text": text}
