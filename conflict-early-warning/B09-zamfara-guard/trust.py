"""ZamfaraGuard: trust-weighted verification of crowdsourced reports.

* Reporter reputation: Beta(1 + confirmed, 1 + false) per pseudonymous reporter. Trust is the mean,
  (1 + confirmed) / (2 + confirmed + false). A new reporter starts at 0.5.
* Clustering: DBSCAN on space-time (a report is a neighbour of another if it is within 5 km AND
  6 hours), so several people describing one event form one cluster.
* Cluster credibility: noisy-OR over DISTINCT reporters, 1 - product(1 - trust_i). Many reports by
  the same person count once. Brand-new reporters together can add at most 0.60, so a burst of fresh
  SIM cards cannot push an event to "probable" on its own (Sybil resistance).
* Two-source rule: "probable" (dispatch) needs credibility >= 0.80 AND at least two independent reporters.
* Coordinated false reports: when most reports in a cluster are near copies of each other
  (word-set Jaccard similarity >= 0.8) and come from new reporters, the cluster is flagged and
  its credibility halved.
* Verification feedback: a field verifier marks a cluster true or false; every reporter in it
  gains a confirmed or a false count. Reputation therefore learns who is reliable.
"""
import hashlib
import hmac
import math
import os
import re
import sqlite3
import time

import geo

DATA = os.path.join(geo.BASE, "data")


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "zamfaraguard.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS reporters(id TEXT PRIMARY KEY, confirmed INT DEFAULT 0, false_reports INT DEFAULT 0, first_seen REAL);
    CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, ts REAL, reporter TEXT, lat REAL, lon REAL, lga TEXT, type TEXT,
        text TEXT, cluster INT);
    CREATE TABLE IF NOT EXISTS clusters(id INTEGER PRIMARY KEY, created REAL, lat REAL, lon REAL, lga TEXT, type TEXT, reports INT,
        reporters INT, credibility REAL, status TEXT, flag TEXT, verdict TEXT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, cluster INT, lga TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS staff(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    """)
    return con


def pepper():
    return (os.environ.get(geo.cfg()["pepper_env"]) or open(os.path.join(DATA, "keys", "pepper.txt")).read()).encode()


def init():
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    open(os.path.join(DATA, "keys", "pepper.txt"), "w").write(os.urandom(24).hex())


def pseudonym(phone):
    return "R-" + hmac.new(pepper(), phone.strip().encode(), hashlib.sha256).hexdigest()[:10]


def trust(reporter_id):
    with db() as con:
        r = con.execute("SELECT * FROM reporters WHERE id=?", (reporter_id,)).fetchone()
    if not r:
        return 0.5, True
    a, b = 1 + r["confirmed"], 1 + r["false_reports"]
    return a / (a + b), (r["confirmed"] + r["false_reports"]) == 0


def submit(phone, lat, lon, kind, text, ts=None):
    """Store one report (rounded to about 100 m) and recompute the clusters around it."""
    ts = ts or time.time()
    c = geo.cfg()
    rid = pseudonym(phone)
    s, w, n, e = geo.bbox(0.3)
    if not (s <= lat <= n and w <= lon <= e):
        return {"accepted": False, "reason": "location outside Zamfara"}
    if kind not in geo.TYPES:
        return {"accepted": False, "reason": "unknown incident type"}
    with db() as con:
        recent = con.execute("SELECT COUNT(*) FROM reports WHERE reporter=? AND ts>?", (rid, ts - 3600)).fetchone()[0]
        if recent >= c["max_reports_per_hour"]:
            return {"accepted": False, "reason": "too many reports from this number in one hour"}
        con.execute("INSERT OR IGNORE INTO reporters(id, first_seen) VALUES(?,?)", (rid, ts))
        cur = con.execute("INSERT INTO reports(ts,reporter,lat,lon,lga,type,text) VALUES(?,?,?,?,?,?,?)",
                          (ts, rid, round(lat, 3), round(lon, 3), geo.nearest_lga(lat, lon), kind, text[:300]))
    recluster(ts)
    return {"accepted": True, "report": cur.lastrowid, "reporter": rid}


def words(t):
    return set(re.findall(r"[a-z]+", t.lower()))


def jaccard(a, b):
    a, b = words(a), words(b)
    return len(a & b) / len(a | b) if a | b else 0.0


def dbscan(points, eps_km, eps_h, min_pts):
    """Classic DBSCAN with a space-time neighbourhood. Returns a label per point (-1 = noise)."""
    n = len(points)
    labels = [None] * n

    def neigh(i):
        p = points[i]
        return [j for j in range(n) if abs(points[j]["ts"] - p["ts"]) <= eps_h * 3600
                and geo.km(p["lat"], p["lon"], points[j]["lat"], points[j]["lon"]) <= eps_km]
    cid = 0
    for i in range(n):
        if labels[i] is not None:
            continue
        nb = neigh(i)
        if len(nb) < min_pts:
            labels[i] = -1
            continue
        labels[i] = cid
        queue = [j for j in nb if j != i]
        while queue:
            j = queue.pop()
            if labels[j] == -1:
                labels[j] = cid
            if labels[j] is not None:
                continue
            labels[j] = cid
            nbj = neigh(j)
            if len(nbj) >= min_pts:
                queue += [k for k in nbj if labels[k] is None or labels[k] == -1]
        cid += 1
    return labels


def credibility(reps):
    """Noisy-OR over distinct reporters with a cap on the combined weight of new reporters."""
    c = geo.cfg()
    seen, miss_known, new_weight = set(), 1.0, 0.0
    for r in reps:
        if r["reporter"] in seen:
            continue
        seen.add(r["reporter"])
        t, is_new = trust(r["reporter"])
        if is_new:
            new_weight = 1 - (1 - new_weight) * (1 - t)
        else:
            miss_known *= 1 - t
    new_weight = min(new_weight, c["new_reporter_cap"])
    cred = 1 - miss_known * (1 - new_weight)
    flag = None
    if len(reps) >= 3:
        pairs = [(a, b) for i, a in enumerate(reps) for b in reps[i + 1:]]
        copies = sum(1 for a, b in pairs if jaccard(a["text"], b["text"]) >= c["copy_similarity"])
        fresh = sum(1 for r in reps if trust(r["reporter"])[1])
        if copies / len(pairs) >= 0.5 and fresh / len(reps) >= 0.6:
            flag = "possible coordinated false reports (near-identical texts from new numbers)"
            cred *= 0.5
    return round(cred, 3), len(seen), flag


def status_of(cred, n_reporters):
    """Two-source rule: one person, however trusted, can only trigger a check, never a dispatch."""
    c = geo.cfg()
    if cred >= c["probable"] and n_reporters >= 2:
        return "probable"
    return "verify" if cred >= c["needs_check"] else "watch"


def recluster(now=None):
    """Re-cluster the last 48 hours of reports and refresh cluster credibility (keeps verdicts)."""
    c = geo.cfg()
    now = now or time.time()
    with db() as con:
        pts = [dict(r) for r in con.execute("SELECT * FROM reports WHERE ts>? ORDER BY ts", (now - 48 * 3600,))]
        verdicts = {r["id"]: r["verdict"] for r in con.execute("SELECT id, verdict FROM clusters WHERE verdict IS NOT NULL")}
    labels = dbscan(pts, c["cluster_km"], c["cluster_hours"], c["min_points"])
    groups = {}
    for p, lab in zip(pts, labels):
        key = ("c", lab) if lab != -1 else ("s", p["id"])
        groups.setdefault(key, []).append(p)
    out = []
    for key, reps in groups.items():
        old = {r["cluster"] for r in reps if r["cluster"]}
        cid = min(old) if old else None
        cred, n_rep, flag = credibility(reps)
        lat = sum(r["lat"] for r in reps) / len(reps)
        lon = sum(r["lon"] for r in reps) / len(reps)
        kind = max({r["type"] for r in reps}, key=lambda t: sum(1 for r in reps if r["type"] == t))
        verdict = verdicts.get(cid)
        st = "confirmed" if verdict == "true" else "dismissed" if verdict == "false" else status_of(cred, n_rep)
        with db() as con:
            if cid is None:
                cid = con.execute("INSERT INTO clusters(created,lat,lon,lga,type,reports,reporters,credibility,status,flag) "
                                  "VALUES(?,?,?,?,?,?,?,?,?,?)", (reps[0]["ts"], lat, lon, reps[0]["lga"], kind, len(reps), n_rep,
                                                                 cred, st, flag)).lastrowid
                prev_status = None
            else:
                prev_status = con.execute("SELECT status FROM clusters WHERE id=?", (cid,)).fetchone()["status"]
                con.execute("UPDATE clusters SET lat=?,lon=?,type=?,reports=?,reporters=?,credibility=?,status=?,flag=? WHERE id=?",
                            (lat, lon, kind, len(reps), n_rep, cred, st, flag, cid))
            con.executemany("UPDATE reports SET cluster=? WHERE id=?", [(cid, r["id"]) for r in reps])
            if st == "probable" and prev_status != "probable":
                con.execute("INSERT INTO alerts(ts,cluster,lga,text) VALUES(?,?,?,?)", (now, cid, reps[0]["lga"],
                            f"PROBABLE {kind.replace('_', ' ')} near {reps[0]['lga']} ({lat:.3f}, {lon:.3f}): {n_rep} independent "
                            f"reporters, credibility {cred:.2f}. Dispatch response."))
        out.append({"cluster": cid, "reports": len(reps), "reporters": n_rep, "credibility": cred, "status": st, "flag": flag})
    with db() as con:  # clusters swallowed by a merge no longer own any report
        con.execute("DELETE FROM clusters WHERE verdict IS NULL AND id NOT IN (SELECT DISTINCT cluster FROM reports "
                    "WHERE cluster IS NOT NULL)")
    return out


def verify(cluster_id, truth, who):
    """Field verifier's verdict updates every involved reporter's reputation."""
    with db() as con:
        reps = {r["reporter"] for r in con.execute("SELECT reporter FROM reports WHERE cluster=?", (cluster_id,))}
        col = "confirmed" if truth else "false_reports"
        for r in reps:
            con.execute(f"UPDATE reporters SET {col}={col}+1 WHERE id=?", (r,))
        con.execute("UPDATE clusters SET verdict=?, status=? WHERE id=?", ("true" if truth else "false",
                                                                        "confirmed" if truth else "dismissed", cluster_id))
    return {"cluster": cluster_id, "verdict": truth, "reporters_updated": len(reps), "by": who}
