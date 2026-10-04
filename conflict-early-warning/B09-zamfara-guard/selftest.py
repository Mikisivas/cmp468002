"""ZamfaraGuard end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import time

import geo
import main as cli
import trust as tr

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def cl_of(report_id):
    with tr.db() as con:
        cid = con.execute("SELECT cluster FROM reports WHERE id=?", (report_id,)).fetchone()["cluster"]
        return dict(con.execute("SELECT * FROM clusters WHERE id=?", (cid,)).fetchone())


def run():
    res = {}
    s = cli.setup()
    rel = [tr.trust(tr.pseudonym(p))[0] for p in cli.RELIABLE]
    unrel = [tr.trust(tr.pseudonym(p))[0] for p in cli.UNRELIABLE]
    res["reputation"] = {"reliable_mean": round(sum(rel) / len(rel), 3), "unreliable_mean": round(sum(unrel) / len(unrel), 3)}
    case("Reputation learned from past verdicts separates reliable and unreliable informants",
         min(rel) > max(unrel), res["reputation"])
    pts = [{"ts": 0, "lat": 12.0, "lon": 6.0}, {"ts": 600, "lat": 12.01, "lon": 6.0}, {"ts": 900, "lat": 12.0, "lon": 6.01},
           {"ts": 0, "lat": 12.5, "lon": 6.5}, {"ts": 86400, "lat": 12.0, "lon": 6.0}]
    case("DBSCAN groups close-in-space-and-time points and leaves others as noise",
         tr.dbscan(pts, 5, 6, 2) == [0, 0, 0, -1, -1], tr.dbscan(pts, 5, 6, 2))
    case("Jaccard similarity spots copy-paste text", tr.jaccard("they killed many people share now", "they killed many people share this now") >= 0.8)

    t0 = time.time()
    sc = cli.scenario()
    res["scenario_ms"] = round((time.time() - t0) * 1000, 1)
    maru, gusau, anka = cl_of(sc[0]["report"]), cl_of(sc[3]["report"]), cl_of(sc[-1]["report"])
    res["scenario"] = {"maru": {k: maru[k] for k in ("reports", "reporters", "credibility", "status", "flag")},
                       "gusau": {k: gusau[k] for k in ("reports", "reporters", "credibility", "status", "flag")},
                       "anka": {k: anka[k] for k in ("reports", "reporters", "credibility", "status")}}
    case("Real attack, 3 trusted informants: PROBABLE and alert sent", maru["status"] == "probable", res["scenario"]["maru"])
    case("Six new numbers with copy-paste rumour: flagged, NOT probable", gusau["status"] != "probable" and gusau["flag"],
         res["scenario"]["gusau"])
    case("Single unknown reporter stays on WATCH", anka["status"] == "watch", res["scenario"]["anka"])
    with tr.db() as con:
        al = [r["lga"] for r in con.execute("SELECT lga FROM alerts WHERE ts>?", (time.time() - 3600,))]
    case("Only Maru triggered a dispatch alert", al == ["Maru"], al)

    g = geo.lga("Maru")
    for i in range(3):
        tr.submit(cli.RELIABLE[0], g["lat"], g["lon"], "armed_attack", f"still shooting {i}")
    m2 = cl_of(sc[0]["report"])
    case("The same informant sending repeats counts once", m2["reports"] == 6 and m2["reporters"] == 3, m2["reporters"])
    blocked = tr.submit(cli.RELIABLE[0], g["lat"], g["lon"], "armed_attack", "again")
    case("Per-number rate limit (5th report in one hour refused)", not blocked["accepted"], blocked)
    lone = tr.submit(cli.RELIABLE[7], geo.lga("Bakura")["lat"], geo.lga("Bakura")["lon"], "cattle_rustling", "cows taken")
    case("Two-source rule: one trusted informant alone gets VERIFY, not dispatch", cl_of(lone["report"])["status"] == "verify")
    case("Location outside Zamfara rejected", not tr.submit("0800", 6.5, 3.3, "threat", "x")["accepted"])

    before = tr.trust(tr.pseudonym("08165550000"))[0]
    tr.verify(gusau["id"], False, "test")
    after = tr.trust(tr.pseudonym("08165550000"))[0]
    case("Verdict 'false' lowers trust of the rumour numbers", after < before, f"{before} -> {after}")
    raw = open(os.path.join(tr.DATA, "zamfaraguard.db"), "rb").read()
    case("Phone numbers never stored", b"08031000000" not in raw and b"08165550000" not in raw)

    import app
    app.app.secret_key = "t"
    c = app.app.test_client()
    c.post("/login", data={"u": "analyst", "p": "ChangeMe@468"})
    case("Analyst cannot record verdicts", c.post("/verdict", data={"id": 1, "v": "1", "csrf": "x"}).status_code == 403)
    case("Cluster map data needs sign-in", app.app.test_client().get("/api/clusters").status_code == 302)

    res.update(setup=s, tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
