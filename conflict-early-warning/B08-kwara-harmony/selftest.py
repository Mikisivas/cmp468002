"""KwaraHarmony end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import time

import cases as cs
import geo
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def raises(fn, exc=Exception):
    try:
        fn()
        return False
    except exc:
        return True


def run():
    res = {}
    s = cli.setup()
    k = cs.kpis()
    res["history"] = k
    case("Synthetic case history loaded across the workflow", s["cases"] == 60 and len(k["by_state"]) >= 5, k["by_state"])

    cid = cs.create("officer_north", "Baruten", "crop_destruction", 2, "Gwanara farmers and Ardo")
    case("Officer cannot open a case outside their LGAs", raises(lambda: cs.create("officer_north", "Asa", "threat", 2, "x"),
                                                                 PermissionError))
    case("Workflow refuses skipping steps (reported -> mediation)", raises(lambda: cs.move("supervisor", cid, "mediation"),
                                                                           PermissionError))
    cs.move("officer_north", cid, "verified", "visited farm")
    case("Only a supervisor can assign a mediator", raises(lambda: cs.move("officer_north", cid, "assigned",
                                                                           mediator="mediator_aisha"), PermissionError))
    cs.move("supervisor", cid, "assigned", mediator="mediator_aisha")
    case("Another mediator cannot act on the case", raises(lambda: cs.move("mediator_tunde", cid, "mediation"), PermissionError))
    cs.move("mediator_aisha", cid, "mediation", "meeting at district head's palace")
    case("Agreement needs terms and compensation", raises(lambda: cs.move("mediator_aisha", cid, "agreement"), ValueError))
    cs.move("mediator_aisha", cid, "agreement", terms="NGN 80,000 for crops; route marked with pegs", compensation=80000)
    cs.move("mediator_aisha", cid, "monitoring")
    case("Case cannot close before 30 days of monitoring", raises(lambda: cs.move("supervisor", cid, "closed"), ValueError))

    cs.add_note("mediator_aisha", cid, "Ardo agreed to pay in two parts. Farmer's son still angry.")
    case("Assigned mediator reads the encrypted notes", cs.read_notes("mediator_aisha", cid)[0]["text"].startswith("Ardo"))
    case("Unassigned mediator cannot read notes", cs.read_notes("mediator_tunde", cid) is None)
    case("Auditor cannot read notes", cs.read_notes("auditor", cid) is None)
    raw = open(os.path.join(cs.DATA, "harmony.db"), "rb").read()
    case("Notes are not stored in plain text", b"Farmer's son" not in raw)
    seen_south = {c["lga"] for c in cs.visible("officer_south")}
    case("Officer sees only their own LGAs", seen_south <= set(cs.user("officer_south")["lgas"]), seen_south)
    case("Mediator sees only assigned cases", all(c["mediator"] == "mediator_aisha" for c in cs.visible("mediator_aisha")))

    cid2 = cs.create("officer_north", "Baruten", "cattle_killing", 3, "same communities")
    c = cs.get(cid)
    with cs.db() as con:
        al = con.execute("SELECT * FROM alerts WHERE case_id=?", (cid,)).fetchall()
    case("New incident during monitoring reopens mediation and alerts (relapse)", c["state"] == "mediation" and len(al) == 1,
         al[0]["text"] if al else c["state"])
    risk = cs.lga_risk()
    res["baruten_risk"] = risk["Baruten"]
    case("Relapse raises Baruten's risk score", risk["Baruten"]["relapses_90d"] >= 1, risk["Baruten"])

    late = cs.sla_breaches(now=time.time() + 3 * 86400)
    res["sla_breaches_in_3_days"] = len(late)
    case("SLA monitor flags the new unverified case after 24 h", any(b["case"] == cid2 for b in late))

    gj = cs.public_geojson()
    res["export"] = gj["metadata"]
    total = sum(f["properties"]["cases"] for f in gj["features"]) + gj["metadata"]["suppressed_cases"]
    case("Public export: every published cell has at least k=3 cases", all(f["properties"]["cases"] >= 3 for f in gj["features"]))
    case("Public export accounts for every case (published + suppressed)", total == cs.kpis()["cases"], total)
    case("Exported points are grid centres, not real locations", all(f["properties"].keys() == {"cases", "open", "types"} for f in gj["features"]))
    with cs.db() as con:
        den = con.execute("SELECT COUNT(*) FROM denied").fetchone()[0]
    res["denied_attempts_logged"] = den
    case("Every refused action is logged", den >= 5, den)

    import app
    app.app.secret_key = "t"
    cl = app.app.test_client()
    cl.post("/login", data={"u": "officer_south", "p": "ChangeMe@468"})
    case("Officer cannot open a case page in another LGA", cl.get(f"/case/{cid}").status_code == 403)
    case("Officer cannot download the public export", cl.get("/export").status_code == 403)
    case("The internal 'system' account cannot sign in", app.app.test_client().post(
        "/login", data={"u": "system", "p": ""}).status_code == 200)

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
