"""Geography helpers and a SYNTHETIC incident history generator.

Coordinates in config.json are approximate LGA headquarters positions for demonstration.
For a real deployment load official boundaries (for example GRID3 Nigeria or OCHA
administrative boundaries) and real incident data (state security reports, ACLED, NEMA).
The history generator is synthetic: it follows the documented seasonal pattern of
farmer-herder conflict (dry-season movement south, planting-season crop damage) and
adds retaliation, where one attack raises the chance of another nearby within days.
"""
import datetime as dt
import json
import math
import os
import random

BASE = os.path.dirname(os.path.abspath(__file__))

TYPES = {
    # code: (label, severity 1-5, share of incidents)
    "crop_destruction": ("Crop destruction by cattle", 2, 0.26),
    "cattle_rustling": ("Cattle rustling", 3, 0.16),
    "cattle_killing": ("Killing or maiming of cattle", 3, 0.10),
    "threat": ("Threat, ultimatum or hate speech", 2, 0.14),
    "blocked_route": ("Blocked stock route or water point", 2, 0.08),
    "armed_attack": ("Armed attack", 4, 0.13),
    "killing": ("Killing of persons", 5, 0.08),
    "displacement": ("Displacement of people", 4, 0.05),
}


def cfg():
    with open(os.path.join(BASE, "config.json"), encoding="utf-8") as fh:
        return json.load(fh)


def lgas():
    return [{"name": n, "lat": la, "lon": lo, "baseline": b} for n, la, lo, b in cfg()["lgas"]]


def lga(name):
    return next(x for x in lgas() if x["name"] == name)


def km(lat1, lon1, lat2, lon2):
    """Great-circle distance (haversine) in kilometres."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def nearest_lga(lat, lon):
    return min(lgas(), key=lambda g: km(lat, lon, g["lat"], g["lon"]))["name"]


def dist_to_polyline(lat, lon, line):
    """Approximate distance (km) from a point to a polyline of (lat, lon) using a local flat projection."""
    kx = 111.32 * math.cos(math.radians(lat))
    best = float("inf")
    for (a1, o1), (a2, o2) in zip(line, line[1:]):
        ax, ay = (o1 - lon) * kx, (a1 - lat) * 110.57
        bx, by = (o2 - lon) * kx, (a2 - lat) * 110.57
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, -(ax * dx + ay * dy) / (dx * dx + dy * dy or 1e-9)))
        best = min(best, math.hypot(ax + t * dx, ay + t * dy))
    return best


def square(lat, lon, half_km):
    dlat = half_km / 110.57
    dlon = half_km / (111.32 * math.cos(math.radians(lat)))
    return [[lon - dlon, lat - dlat], [lon + dlon, lat - dlat], [lon + dlon, lat + dlat], [lon - dlon, lat + dlat],
            [lon - dlon, lat - dlat]]


def point_in_polygon(lat, lon, ring):
    """Ray casting. ring is a list of [lon, lat] pairs (GeoJSON order)."""
    inside = False
    j = len(ring) - 1
    for i in range(len(ring)):
        xi, yi = ring[i]
        xj, yj = ring[j]
        if (yi > lat) != (yj > lat) and lon < (xj - xi) * (lat - yi) / (yj - yi + 1e-12) + xi:
            inside = not inside
        j = i
    return inside


def farmland(seed=11):
    rnd = random.Random(seed)
    out = []
    for g in lgas():
        for i in range(3):
            la, lo = g["lat"] + rnd.uniform(-0.07, 0.07), g["lon"] + rnd.uniform(-0.07, 0.07)
            crop = rnd.choice(["yam", "maize", "rice", "cassava", "sorghum", "soybean", "millet"])
            out.append({"name": f"{g['name']} {crop} farms #{i + 1}", "lga": g["name"], "crop": crop,
                        "ring": square(la, lo, rnd.uniform(1.0, 2.5))})
    return out


def season_factor(month):
    """Dry season (Jan-Apr) herds move south and pressure peaks; planting (May-Jun) brings crop damage;
    full rains (Jul-Sep) are calmer; harvest and early dry season (Oct-Dec) rise again."""
    return {1: 1.6, 2: 1.7, 3: 1.6, 4: 1.4, 5: 1.3, 6: 1.1, 7: 0.7, 8: 0.6, 9: 0.7, 10: 1.0, 11: 1.2, 12: 1.4}[month]


def history(days=365, seed=468, end=None, daily_rate=0.035, retaliation=0.35):
    """Synthetic incidents for the last `days` days. Returns a list of dicts sorted by time."""
    rnd = random.Random(seed)
    end = end or dt.datetime.now()
    start = end - dt.timedelta(days=days)
    codes = list(TYPES)
    weights = [TYPES[c][2] for c in codes]
    out = []
    for d in range(days):
        day = start + dt.timedelta(days=d)
        for g in lgas():
            lam = daily_rate * (0.3 + 1.7 * g["baseline"]) * season_factor(day.month)
            k = 0
            # Poisson draw by inversion (lam is small)
            u, pk, cum = rnd.random(), math.exp(-lam), math.exp(-lam)
            while u > cum and k < 6:
                k += 1
                pk *= lam / k
                cum += pk
            for _ in range(k):
                out.append(_incident(rnd, g, day + dt.timedelta(seconds=rnd.randint(0, 86399)), codes, weights))
    spawned = []
    for inc in out:
        if TYPES[inc["type"]][1] >= 3 and rnd.random() < retaliation:
            t = dt.datetime.fromtimestamp(inc["ts"]) + dt.timedelta(hours=rnd.uniform(12, 120))
            if t < end:
                g = lga(inc["lga"]) if rnd.random() < 0.7 else rnd.choice(lgas())
                spawned.append(_incident(rnd, g, t, ["armed_attack", "killing", "cattle_killing", "threat"],
                                         [0.35, 0.2, 0.3, 0.15], retaliation_of=inc))
    out += spawned
    out.sort(key=lambda r: r["ts"])
    return out


def _incident(rnd, g, when, codes, weights, retaliation_of=None):
    t = rnd.choices(codes, weights)[0]
    sev = TYPES[t][1]
    return {"ts": when.timestamp(), "lga": g["name"], "lat": round(g["lat"] + rnd.gauss(0, 0.04), 5),
            "lon": round(g["lon"] + rnd.gauss(0, 0.04), 5), "type": t, "severity": sev,
            "fatalities": rnd.randint(1, 8) if t == "killing" else (rnd.randint(0, 3) if sev == 4 else 0),
            "retaliation": retaliation_of is not None}


def bbox(pad=0.25):
    la = [g["lat"] for g in lgas()]
    lo = [g["lon"] for g in lgas()]
    return min(la) - pad, min(lo) - pad, max(la) + pad, max(lo) + pad
