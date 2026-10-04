"""NigerBasinWatch: Transhumance Pressure Index (TPI) and an 8-week seasonal risk calendar.

Idea: herds leave the Sahel when pasture there fails, and they head for places that still have
grass and water. Conflict risk in a Niger State LGA is high when (a) the north is dry, (b) the LGA
is attractive to herds (green, near water, on a route), and (c) crops are standing in the fields.

    north_push  = clip(1 - NDVI_north / greenest-week NDVI_north, 0, 1)  (dry season, made worse by drought)
    pull        = 0.5 * NDVI_local/max + 0.3 * water closeness + 0.2 * route closeness
    exposure    = share of crops in the field that month
    TPI         = north_push^0.5 * pull * exposure * 1.8, clipped to 0..1

Herds move south every dry season; a northern drought pushes harder and earlier. The product
peaks at the start (planting) and end (harvest) of the rains, when herds and standing crops meet.
Forecast: the current NDVI anomaly decays toward normal by a persistence factor each week,
and the crop calendar moves forward, giving TPI for the next 8 weeks.
Environmental data come as CSV; each dataset version is fingerprinted (SHA-256) and the
fingerprint is sealed with HMAC so a changed file is detected before use.
"""
import csv
import datetime as dt
import hashlib
import hmac
import io
import math
import os
import random
import sqlite3
import time

import geo

DATA = os.path.join(geo.BASE, "data")
NORTH = "NORTH"


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "basinwatch.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS env(area TEXT, week TEXT, ndvi REAL, rain_mm REAL, version INT, PRIMARY KEY(area, week));
    CREATE TABLE IF NOT EXISTS versions(id INTEGER PRIMARY KEY, at REAL, name TEXT, rows INT, sha256 TEXT, seal TEXT, by TEXT);
    CREATE TABLE IF NOT EXISTS incidents(ts REAL, lga TEXT, type TEXT, severity INT);
    CREATE TABLE IF NOT EXISTS calendar(lga TEXT, week TEXT, tpi REAL, level TEXT, PRIMARY KEY(lga, week));
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, at REAL, lga TEXT, week TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS staff(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    """)
    return con


def data_key():
    return (os.environ.get(geo.cfg()["data_key_env"]) or open(os.path.join(DATA, "keys", "data.key")).read()).encode()


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    os.makedirs(os.path.join(DATA, "datasets"), exist_ok=True)
    open(os.path.join(DATA, "keys", "data.key"), "w").write(os.urandom(24).hex())


def monday(d):
    return (d - dt.timedelta(days=d.weekday())).strftime("%Y-%m-%d")


def clim_ndvi(week_of_year, lat):
    """Seasonal NDVI shape: green-up with the rains (peak late August), browner further north."""
    phase = math.cos(2 * math.pi * (week_of_year - 34) / 52)
    base = 0.42 - 0.04 * (lat - 9.5)
    return max(0.08, base + 0.22 * phase)


def synthetic_csv(weeks=156, drought_weeks=(100, 125), seed=12):
    """Three years of weekly NDVI and rainfall for every LGA plus the northern source zone,
    with a drought spell in the north (synthetic, for demonstration)."""
    rnd = random.Random(seed)
    start = dt.date.today() - dt.timedelta(weeks=weeks)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["area", "week", "ndvi", "rain_mm"])
    areas = [(g["name"], g["lat"]) for g in geo.lgas()] + [(NORTH, 12.5)]
    for k in range(weeks):
        d = start + dt.timedelta(weeks=k)
        woy = d.isocalendar()[1]
        drought = drought_weeks[0] <= k <= drought_weeks[1]
        for area, lat in areas:
            nd = clim_ndvi(woy, lat) + rnd.gauss(0, 0.02)
            if area == NORTH and drought:
                nd *= 0.55
            rain = max(0.0, 60 * math.cos(2 * math.pi * (woy - 32) / 52) + rnd.gauss(10, 8))
            w.writerow([area, monday(d), round(max(0.05, nd), 3), round(rain, 1)])
    return out.getvalue()


def seal(sha):
    return hmac.new(data_key(), sha.encode(), hashlib.sha256).hexdigest()


def import_csv(text, name, who):
    """Validate, fingerprint and load an environmental dataset."""
    rows, errors = [], []
    areas = {g["name"] for g in geo.lgas()} | {NORTH}
    for i, r in enumerate(csv.DictReader(io.StringIO(text)), 2):
        try:
            if r["area"] not in areas:
                raise ValueError(f"unknown area {r['area']!r}")
            dt.datetime.strptime(r["week"], "%Y-%m-%d")
            nd, rain = float(r["ndvi"]), float(r["rain_mm"])
            if not -0.2 <= nd <= 1.0:
                raise ValueError("NDVI must be between -0.2 and 1")
            if not 0 <= rain <= 600:
                raise ValueError("weekly rainfall must be 0-600 mm")
            rows.append((r["area"], r["week"], nd, rain))
        except (KeyError, ValueError) as exc:
            errors.append(f"row {i}: {exc}")
    if errors and len(errors) > 0.05 * max(1, len(rows)):
        return {"accepted": False, "errors": errors[:10], "error_count": len(errors)}
    sha = hashlib.sha256(text.encode()).hexdigest()
    with db() as con:
        cur = con.execute("INSERT INTO versions(at,name,rows,sha256,seal,by) VALUES(?,?,?,?,?,?)",
                          (time.time(), name, len(rows), sha, seal(sha), who))
        vid = cur.lastrowid
        con.executemany("INSERT OR REPLACE INTO env VALUES(?,?,?,?,?)", [(a, wk, n, r, vid) for a, wk, n, r in rows])
    with open(os.path.join(DATA, "datasets", f"v{vid}_{os.path.basename(name)}"), "w", encoding="utf-8", newline="") as fh:
        fh.write(text)  # newline="" keeps the exact bytes, so the fingerprint stays valid on Windows too
    return {"accepted": True, "version": vid, "rows": len(rows), "sha256": sha, "skipped": errors[:10]}


def verify_datasets():
    """Re-hash every stored dataset file and check its HMAC seal."""
    problems = []
    with db() as con:
        vers = con.execute("SELECT * FROM versions").fetchall()
    for v in vers:
        path = os.path.join(DATA, "datasets", f"v{v['id']}_{os.path.basename(v['name'])}")
        try:
            with open(path, encoding="utf-8", newline="") as fh:
                sha = hashlib.sha256(fh.read().encode()).hexdigest()
        except FileNotFoundError:
            problems.append(f"version {v['id']}: file missing")
            continue
        if sha != v["sha256"]:
            problems.append(f"version {v['id']}: file changed after import")
        if not hmac.compare_digest(seal(v["sha256"]), v["seal"]):
            problems.append(f"version {v['id']}: fingerprint record forged")
    return {"versions": len(vers), "ok": not problems, "problems": problems}


def series(area):
    with db() as con:
        return [(r["week"], r["ndvi"], r["rain_mm"]) for r in con.execute("SELECT * FROM env WHERE area=? ORDER BY week", (area,))]


def climatology(area):
    """Mean NDVI per week-of-year from all loaded years."""
    acc = {}
    for wk, nd, _ in series(area):
        woy = dt.datetime.strptime(wk, "%Y-%m-%d").isocalendar()[1]
        acc.setdefault(woy, []).append(nd)
    return {k: sum(v) / len(v) for k, v in acc.items()}


def pull_static():
    c = geo.cfg()
    out = {}
    for g in geo.lgas():
        water = min(geo.km(g["lat"], g["lon"], w[1], w[2]) for w in c["water"])
        route = min(geo.dist_to_polyline(g["lat"], g["lon"], r) for r in c["routes"].values())
        out[g["name"]] = (math.exp(-water / 40), math.exp(-route / 25))
    return out


def tpi_value(north_nd, north_peak, local_nd, local_max, month, static):
    push = min(1.0, max(0.0, 1 - north_nd / north_peak)) if north_peak else 0
    pull = 0.5 * local_nd / local_max + 0.3 * static[0] + 0.2 * static[1]
    expo = geo.cfg()["crop_share_in_field"][str(month)]
    return min(1.0, max(0.0, (push ** 0.5) * pull * expo * 1.8))


def level(t):
    return "Severe" if t >= 0.7 else "High" if t >= 0.55 else "Moderate" if t >= 0.35 else "Low"


def history_tpi():
    """TPI for every LGA and loaded week (used for validation)."""
    north = dict((w, n) for w, n, _ in series(NORTH))
    npeak = max(climatology(NORTH).values())
    static = pull_static()
    out = {}
    for g in geo.lgas():
        s = series(g["name"])
        mx = max(n for _, n, _ in s)
        for wk, nd, _ in s:
            d = dt.datetime.strptime(wk, "%Y-%m-%d")
            if wk in north:
                out[(g["name"], wk)] = tpi_value(north[wk], npeak, nd, mx, d.month, static[g["name"]])
    return out


def forecast():
    """8-week risk calendar from the latest week, with anomalies decaying toward climatology."""
    c = geo.cfg()
    north = series(NORTH)
    ncl = climatology(NORTH)
    last_wk = dt.datetime.strptime(north[-1][0], "%Y-%m-%d")
    north_anom = north[-1][1] - ncl[last_wk.isocalendar()[1]]
    static = pull_static()
    rows = []
    for g in geo.lgas():
        s = series(g["name"])
        cl = climatology(g["name"])
        mx = max(n for _, n, _ in s)
        anom = s[-1][1] - cl[last_wk.isocalendar()[1]]
        for k in range(1, c["forecast_weeks"] + 1):
            d = last_wk + dt.timedelta(weeks=k)
            woy = d.isocalendar()[1]
            decay = c["anomaly_persistence"] ** k
            n_nd = ncl.get(woy, north[-1][1]) + north_anom * decay
            l_nd = cl.get(woy, s[-1][1]) + anom * decay
            t = tpi_value(n_nd, max(ncl.values()), l_nd, mx, d.month, static[g["name"]])
            rows.append((g["name"], d.strftime("%Y-%m-%d"), round(t, 3), level(t)))
    with db() as con:
        con.execute("DELETE FROM calendar")
        con.executemany("INSERT INTO calendar VALUES(?,?,?,?)", rows)
        for lga_name, wk, t, lv in rows:
            if t >= c["alert_tpi"] and not con.execute("SELECT 1 FROM alerts WHERE lga=? AND week=?", (lga_name, wk)).fetchone():
                con.execute("INSERT INTO alerts(at,lga,week,text) VALUES(?,?,?,?)", (time.time(), lga_name, wk,
                            f"SEASONAL WARNING {lga_name}, week of {wk}: transhumance pressure {t:.2f} ({lv}). Pre-position "
                            f"mediators, open the stock route, agree water-point timetables before herds arrive."))
    return rows


def spearman(xs, ys):
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(v):
            j = i
            while j + 1 < len(v) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for k in range(i, j + 1):
                r[order[k]] = (i + j) / 2
            i = j + 1
        return r
    rx, ry = ranks(xs), ranks(ys)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    return cov / math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))


def validate():
    """Does monthly mean TPI move with monthly incident counts? (Spearman rank correlation)"""
    h = history_tpi()
    month_tpi, month_inc = {}, {}
    for (lga_name, wk), t in h.items():
        key = (lga_name, wk[:7])
        month_tpi.setdefault(key, []).append(t)
    with db() as con:
        for r in con.execute("SELECT ts, lga FROM incidents"):
            key = (r["lga"], dt.datetime.fromtimestamp(r["ts"]).strftime("%Y-%m"))
            month_inc[key] = month_inc.get(key, 0) + 1
    keys = [k for k in month_tpi if len(month_tpi[k]) >= 3]
    xs = [sum(month_tpi[k]) / len(month_tpi[k]) for k in keys]
    ys = [month_inc.get(k, 0) for k in keys]
    return {"lga_months": len(keys), "spearman_rho": round(spearman(xs, ys), 3)}
