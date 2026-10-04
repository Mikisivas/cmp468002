"""KwaraHarmony command line. `python main.py -h` for help."""
import argparse
import json
import os
import random
import shutil
import time

import cases as cs
import geo

DAY = 86400


def reset():
    shutil.rmtree(cs.DATA, ignore_errors=True)


def setup():
    reset()
    cs.db().close()
    cs.init()
    import app
    pw = os.environ.get("KWARAHARMONY_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_user("supervisor", pw, "supervisor", ["*"])
    app.add_user("officer_north", pw, "officer", ["Baruten", "Kaiama", "Moro", "Edu", "Patigi", "Ifelodun"])
    app.add_user("officer_south", pw, "officer", ["Asa", "Ekiti", "Isin", "Ilorin South", "Oyun", "Ilorin East"])
    app.add_user("mediator_aisha", pw, "mediator", [])
    app.add_user("mediator_tunde", pw, "mediator", [])
    app.add_user("auditor", pw, "auditor", ["*"])
    app.add_user("system", None, "system", ["*"])
    return {"cases": history()}


def history(n=60, seed=6):
    """Synthetic case history spread over 120 days, at various stages of the workflow."""
    rnd = random.Random(seed)
    now = time.time()
    north = ["Baruten", "Kaiama", "Moro", "Edu", "Patigi", "Ifelodun"]
    made = 0
    for i in range(n):
        g = rnd.choice(geo.lgas())
        officer = "officer_north" if g["name"] in north else "officer_south"
        t = now - rnd.uniform(5, 120) * DAY
        kind = rnd.choice(list(geo.TYPES))
        cid = cs.create(officer, g["name"], kind, geo.TYPES[kind][1], rnd.choice(["farmers' association and Ardo", "two villages",
                                                                             "herders' camp and host community"]),
                        g["lat"] + rnd.gauss(0, .03), g["lon"] + rnd.gauss(0, .03), ts=t, check_relapse=False)
        made += 1
        stage = rnd.random()
        if stage < 0.1:
            continue
        cs.move(officer, cid, "verified", "confirmed by DPO", ts=t + rnd.uniform(2, 30) * 3600)
        if stage < 0.2:
            continue
        med = rnd.choice(["mediator_aisha", "mediator_tunde"])
        cs.move("supervisor", cid, "assigned", mediator=med, ts=t + rnd.uniform(1, 3) * DAY)
        if stage < 0.3:
            continue
        cs.move(med, cid, "mediation", "first meeting at the emir's palace", ts=t + rnd.uniform(3, 9) * DAY)
        if stage < 0.5:
            continue
        cs.move(med, cid, "agreement", terms="crop damage paid; herders use route after 6pm", compensation=rnd.choice([0, 50000, 120000]),
                ts=t + rnd.uniform(10, 20) * DAY)
        cs.move(med, cid, "monitoring", ts=t + rnd.uniform(20, 22) * DAY)
        if stage < 0.75 or t + 55 * DAY > now:
            continue
        cs.move("supervisor", cid, "closed", "no relapse in 30 days", ts=t + 54 * DAY)
    return made


def main():
    ap = argparse.ArgumentParser(description="KwaraHarmony: response and mediation case management (Kwara State)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "kpis", "sla", "risk", "export", "relapse", "reset"):
        sub.add_parser(n)
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Logins (password ChangeMe@468): supervisor, officer_north, officer_south, mediator_aisha, mediator_tunde, auditor")
    elif a.cmd == "serve":
        import app
        app.serve()
    elif a.cmd == "kpis":
        out = cs.kpis()
    elif a.cmd == "sla":
        out = cs.sla_breaches()
    elif a.cmd == "risk":
        out = cs.lga_risk()
    elif a.cmd == "export":
        out = cs.public_geojson()
    elif a.cmd == "relapse":
        with cs.db() as con:
            m = con.execute("SELECT lga FROM cases WHERE state='monitoring' LIMIT 1").fetchone()
        if not m:
            out = "no case is in monitoring"
        else:
            north = ["Baruten", "Kaiama", "Moro", "Edu", "Patigi", "Ifelodun"]
            cid = cs.create("officer_north" if m["lga"] in north else "officer_south", m["lga"], "crop_destruction", 2,
                            "same communities")
            out = f"new case {cid} in {m['lga']}; see Dashboard alerts"
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
