"""MambillaWatch end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import time

import fence
import geo
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    cli.setup()
    keys = json.load(open(os.path.join(fence.DATA, "collar_keys.json")))
    sq = [[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]]
    case("Point-in-polygon (ray casting) inside and outside", geo.point_in_polygon(0.5, 0.5, sq) and
         not geo.point_in_polygon(1.5, 0.5, sq))

    t = time.time() - 11 * 600
    paths = cli.scenario()
    counters = {k: 0 for k in keys}
    log = {k: [] for k in keys}
    t0 = time.time()
    n = 0
    for step in range(11):
        for cid, path in paths.items():
            counters[cid] += 1
            lat, lon = round(path[step][0], 5), round(path[step][1], 5)
            bat = 80 - step * (7 if cid == "TRB-003" else 1)
            ok, why, al = fence.accept(cid, counters[cid], lat, lon, bat,
                                       fence.sign(keys[cid], cid, counters[cid], lat, lon, bat), now=t + step * 600)
            log[cid].append((ok, why, [a["kind"] for a in al]))
            n += 1
    res["ms_per_ping"] = round((time.time() - t0) * 1000 / n, 2)
    kinds = {cid: {k for _, _, ks in v for k in ks} for cid, v in log.items()}
    res["alerts_by_collar"] = {k: sorted(v) for k, v in kinds.items()}
    with fence.db() as con:
        app_row = con.execute("SELECT * FROM alerts WHERE kind='APPROACH' ORDER BY id LIMIT 1").fetchone()
        breach = con.execute("SELECT * FROM alerts WHERE kind='BREACH' LIMIT 1").fetchone()
    case("Herd walking into an in-season farm: APPROACH with ETA, then BREACH",
         {"APPROACH", "BREACH"} <= kinds["TRB-001"] and app_row["eta_min"] > 0,
         f"ETA {app_row['eta_min']:.0f} min" if app_row else "")
    first_approach = next(i for i, (_, _, k) in enumerate(log["TRB-001"]) if "APPROACH" in k)
    first_breach = next(i for i, (_, _, k) in enumerate(log["TRB-001"]) if "BREACH" in k)
    res["lead_time_minutes"] = (first_breach - first_approach) * 10
    case("Warning came before the breach (lead time)", first_approach < first_breach, f"{res['lead_time_minutes']} minutes")
    case("Breach alert reaches both the farmers' and the herders' leader",
         "farmers" in breach["sent_to"] and "herders" in breach["sent_to"], breach["sent_to"])
    case("Herd on the agreed corridor raises no farm alerts", not ({"BREACH", "APPROACH", "DEVIATION"} & kinds["TRB-002"]),
         kinds["TRB-002"])
    case("Herd leaving the corridor raises DEVIATION", "DEVIATION" in kinds["TRB-003"])
    case("Low collar battery reported", "BATTERY" in kinds["TRB-003"] or any(
        "battery" in r["text"] for r in fence.db().execute("SELECT text FROM alerts WHERE collar='TRB-003'")))
    jumps = [w for ok, w, _ in log["TRB-004"] if not ok]
    case("Teleporting (spoofed) collar is flagged and its position ignored", "impossible speed" in jumps, jumps)

    cid = "TRB-002"
    lat, lon, bat = 7.5, 11.0, 70
    sig = fence.sign(keys[cid], cid, 5, lat, lon, bat)
    ok, why, _ = fence.accept(cid, 5, lat, lon, bat, sig)
    case("Replayed old ping (lower counter) refused", not ok and "replayed" in why, why)
    ok, why, _ = fence.accept(cid, 99, lat, lon, bat, sig)
    case("Ping with a forged signature refused", not ok and "signature" in why, why)
    ok, why, _ = fence.accept("TRB-999", 1, lat, lon, bat, sig)
    case("Unknown collar refused", not ok)
    sig2 = fence.sign(keys[cid], cid, 100, 4.0, 3.0, bat)
    ok, why, _ = fence.accept(cid, 100, 4.0, 3.0, bat, sig2)
    case("Position outside Taraba refused", not ok and "outside" in why)

    import app
    app.app.secret_key = "t"
    cl = app.app.test_client()
    r = cl.post("/api/ping", json={"collar": "TRB-001"})
    case("Malformed ping returns 400", r.status_code == 400)
    cl.post("/login", data={"u": "ranger", "p": "ChangeMe@468"})
    case("Ranger cannot register collars", cl.post("/collars", data={"id": "X", "herd": "x", "group": "x", "heads": 1,
                                                                      "csrf": "bad"}).status_code == 403)
    case("Live state API works for staff", cl.get("/api/state").status_code == 200)

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
