"""PlateauWatch hotspot engine: kernel density estimation (KDE) on a 3 km raster.

density(cell) = sum over incidents of severity x K(distance / h)
with a Gaussian kernel K and bandwidth h chosen by Silverman's rule of thumb for two
dimensions, h = 1.06 x sigma x n^(-1/5), where sigma is the average spread of incident
locations in km. Hotspots are local maxima above the 90th percentile. Comparing the
last 30 days with the 30 days before labels each hotspot emerging (new, or at least
three times denser), persistent, or fading.
"""
import datetime as dt
import hashlib
import math
import os
import sqlite3
import statistics
import time

import geo

DATA = os.path.join(geo.BASE, "data")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "plateauwatch.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, ts REAL, lga TEXT, lat REAL, lon REAL, type TEXT,
        severity INT, fatalities INT, source TEXT, added_by TEXT);
    CREATE TABLE IF NOT EXISTS hotspots(id INTEGER PRIMARY KEY, at REAL, lat REAL, lon REAL, lga TEXT, density REAL,
        status TEXT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, at REAL, lga TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt TEXT, hash TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at REAL, who TEXT, what TEXT, h TEXT);
    """)
    return con


def audit(who, what):
    with db() as con:
        prev = con.execute("SELECT h FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        at = time.time()
        con.execute("INSERT INTO audit(at,who,what,h) VALUES(?,?,?,?)", (at, who, what, hashlib.sha256(
            f"{prev['h'] if prev else ''}|{at}|{who}|{what}".encode()).hexdigest()))


def incidents(t0, t1):
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM incidents WHERE ts BETWEEN ? AND ?", (t0, t1))]


def silverman(points):
    if len(points) < 3:
        return 10.0
    lat0 = statistics.mean(p["lat"] for p in points)
    sx = statistics.pstdev(p["lon"] for p in points) * 111.32 * math.cos(math.radians(lat0))
    sy = statistics.pstdev(p["lat"] for p in points) * 110.57
    sigma = math.sqrt((sx ** 2 + sy ** 2) / 2)
    # Silverman assumes one cluster; conflict data has many, so it over-smooths. Cap it (config).
    return min(geo.cfg()["max_bandwidth_km"], max(2.0, 1.06 * sigma * len(points) ** -0.2))


def raster():
    s, w, n, e = geo.bbox(0.15)
    step = geo.cfg()["cell_km"]
    dlat = step / 110.57
    dlon = step / (111.32 * math.cos(math.radians((s + n) / 2)))
    rows = int((n - s) / dlat) + 1
    cols = int((e - w) / dlon) + 1
    return s, w, dlat, dlon, rows, cols


def density(points, h=None):
    """Return (grid, h) where grid[r][c] is the KDE value (events per km^2, severity-weighted)."""
    h = h or (silverman(points) if geo.cfg()["bandwidth_km"] == "silverman" else float(geo.cfg()["bandwidth_km"]))
    s, w, dlat, dlon, rows, cols = raster()
    grid = [[0.0] * cols for _ in range(rows)]
    norm = 1.0 / (2 * math.pi * h * h)
    reach = 3 * h
    for p in points:
        r0, c0 = int((p["lat"] - s) / dlat), int((p["lon"] - w) / dlon)
        span_r, span_c = int(reach / (dlat * 110.57)) + 1, int(reach / (dlon * 111.32 * math.cos(math.radians(p["lat"])))) + 1
        for r in range(max(0, r0 - span_r), min(rows, r0 + span_r + 1)):
            for c in range(max(0, c0 - span_c), min(cols, c0 + span_c + 1)):
                d = geo.km(p["lat"], p["lon"], s + (r + .5) * dlat, w + (c + .5) * dlon)
                if d <= reach:
                    grid[r][c] += p["severity"] * norm * math.exp(-0.5 * (d / h) ** 2)
    return grid, h


def threshold(grid, q):
    vals = sorted(v for row in grid for v in row if v > 0)
    return vals[int(q * (len(vals) - 1))] if vals else float("inf")


def peaks(grid, q=None):
    q = q or geo.cfg()["hotspot_quantile"]
    s, w, dlat, dlon, rows, cols = raster()
    t = threshold(grid, q)
    out = []
    for r in range(rows):
        for c in range(cols):
            v = grid[r][c]
            if v < t or v <= 0:
                continue
            if all(v >= grid[rr][cc] for rr in range(max(0, r - 2), min(rows, r + 3))
                   for cc in range(max(0, c - 2), min(cols, c + 3))):
                la, lo = s + (r + .5) * dlat, w + (c + .5) * dlon
                out.append({"lat": round(la, 4), "lon": round(lo, 4), "lga": geo.nearest_lga(la, lo), "density": v})
    return out


def analyse(now=None, window_days=30):
    """Emerging hotspot analysis for the last window against the window before it."""
    now = now or time.time()
    cur_pts = incidents(now - window_days * 86400, now)
    prev_pts = incidents(now - 2 * window_days * 86400, now - window_days * 86400)
    cur, h = density(cur_pts)
    prev, _ = density(prev_pts, h)
    t_prev = threshold(prev, geo.cfg()["hotspot_quantile"])
    s, w, dlat, dlon, rows, cols = raster()
    result = []
    for pk in peaks(cur):
        r, c = int((pk["lat"] - s) / dlat), int((pk["lon"] - w) / dlon)
        before = prev[r][c]
        if before < t_prev * 0.5 or pk["density"] >= 3 * before:
            status = "emerging"  # new, or at least three times denser than the previous window
        elif pk["density"] >= before:
            status = "persistent (intensifying)"
        else:
            status = "persistent (cooling)"
        result.append({**pk, "status": status, "before": before})
    fading = [p for p in peaks(prev) if cur[int((p["lat"] - s) / dlat)][int((p["lon"] - w) / dlon)] < threshold(cur, geo.cfg()["hotspot_quantile"]) * 0.5]
    with db() as con:
        con.execute("DELETE FROM hotspots")
        for x in result:
            con.execute("INSERT INTO hotspots(at,lat,lon,lga,density,status) VALUES(?,?,?,?,?,?)",
                        (now, x["lat"], x["lon"], x["lga"], x["density"], x["status"]))
        for x in fading:
            con.execute("INSERT INTO hotspots(at,lat,lon,lga,density,status) VALUES(?,?,?,?,?,?)",
                        (now, x["lat"], x["lon"], x["lga"], x["density"], "fading"))
        for x in result:
            if x["status"] == "emerging" and not con.execute("SELECT 1 FROM alerts WHERE lga=? AND at>?",
                                                              (x["lga"], now - 86400)).fetchone():
                con.execute("INSERT INTO alerts(at,lga,text) VALUES(?,?,?)", (now, x["lga"],
                            f"EMERGING HOTSPOT near {x['lga']} ({x['lat']}, {x['lon']}): new or at least 3x denser than "
                            f"the previous {window_days} days. Send an assessment team."))
    return {"bandwidth_km": round(h, 2), "incidents_now": len(cur_pts), "incidents_before": len(prev_pts),
            "hotspots": result, "fading": fading}


def pai(train_end=None, train_days=60, test_days=30, area_share=0.10):
    """Predictive Accuracy Index (Chainey et al. style): share of future incidents inside the top
    10% density area, divided by 10%. PAI above 1 means better than random placement."""
    train_end = train_end or time.time() - test_days * 86400
    grid, h = density(incidents(train_end - train_days * 86400, train_end))
    s, w, dlat, dlon, rows, cols = raster()
    t = threshold(grid, 1 - area_share)
    hot = {(r, c) for r in range(rows) for c in range(cols) if grid[r][c] >= t and grid[r][c] > 0}
    test = incidents(train_end, train_end + test_days * 86400)
    hits = sum((int((p["lat"] - s) / dlat), int((p["lon"] - w) / dlon)) in hot for p in test)
    share = len(hot) / (rows * cols)
    hr = hits / len(test) if test else 0
    return {"bandwidth_km": round(h, 2), "cells": rows * cols, "hot_cells": len(hot), "area_share": round(share, 3),
            "test_incidents": len(test), "captured": hits, "hit_rate": round(hr, 3),
            "pai": round(hr / share, 2) if share and test else None}


def import_csv(text, who):
    """Accept rows: date(YYYY-MM-DD),lga,type,severity[,lat,lon]. Bad rows are reported, not imported."""
    ok, bad = 0, []
    names = {g["name"].lower(): g for g in geo.lgas()}
    for i, line in enumerate(text.strip().splitlines(), 1):
        parts = [x.strip() for x in line.split(",")]
        if i == 1 and parts[0].lower() == "date":
            continue
        try:
            when = dt.datetime.strptime(parts[0], "%Y-%m-%d").timestamp() + 43200
            g = names[parts[1].lower()]
            kind = parts[2]
            if kind not in geo.TYPES:
                raise ValueError("unknown type")
            sev = int(parts[3])
            if not 1 <= sev <= 5:
                raise ValueError("severity must be 1-5")
            lat, lon = (float(parts[4]), float(parts[5])) if len(parts) >= 6 else (g["lat"], g["lon"])
            s, w, n, e = geo.bbox(0.3)
            if not (s <= lat <= n and w <= lon <= e):
                raise ValueError("location outside Plateau State")
            with db() as con:
                con.execute("INSERT INTO incidents(ts,lga,lat,lon,type,severity,fatalities,source,added_by) "
                            "VALUES(?,?,?,?,?,?,0,'csv import',?)", (when, g["name"], lat, lon, kind, sev, who))
            ok += 1
        except (ValueError, KeyError, IndexError) as exc:
            bad.append(f"line {i}: {exc}")
    audit(who, f"CSV import: {ok} rows accepted, {len(bad)} rejected")
    return {"imported": ok, "rejected": bad}
