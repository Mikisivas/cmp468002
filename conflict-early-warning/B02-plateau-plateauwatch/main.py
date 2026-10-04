"""PlateauWatch command line. `python main.py -h` for help."""
import argparse
import json
import os
import random
import shutil
import time

import geo
import kde


def reset():
    shutil.rmtree(kde.DATA, ignore_errors=True)


def setup():
    reset()
    kde.db().close()
    import server
    pw = os.environ.get("PLATEAUWATCH_ADMIN_PASSWORD", "ChangeMe@468")
    server.add_user("coordinator", pw, "coordinator")
    server.add_user("observer", pw, "observer")
    hist = geo.history(days=240, seed=4689)
    with kde.db() as con:
        con.executemany("INSERT INTO incidents(ts,lga,lat,lon,type,severity,fatalities,source,added_by) VALUES(?,?,?,?,?,?,?,?,?)",
                        [(h["ts"], h["lga"], h["lat"], h["lon"], h["type"], h["severity"], h["fatalities"],
                          "history (synthetic)", "setup") for h in hist])
    return {"incidents": len(hist), "analysis": summary(kde.analyse())}


def summary(a):
    return {"bandwidth_km": a["bandwidth_km"], "incidents_now": a["incidents_now"],
            "hotspots": [(h["lga"], h["status"]) for h in a["hotspots"]], "fading": [h["lga"] for h in a["fading"]]}


def flare(lga_name="Kanam", n=8):
    """Simulate a new wave of attacks in a quiet LGA (it should appear as an EMERGING hotspot)."""
    g = geo.lga(lga_name)
    rnd = random.Random(3)
    with kde.db() as con:
        for i in range(n):
            con.execute("INSERT INTO incidents(ts,lga,lat,lon,type,severity,fatalities,source,added_by) VALUES(?,?,?,?,?,?,?,?,?)",
                        (time.time() - rnd.uniform(0, 5) * 86400, lga_name, g["lat"] + rnd.gauss(0, .02),
                         g["lon"] + rnd.gauss(0, .02), rnd.choice(["armed_attack", "killing", "cattle_rustling"]), 4, 1,
                         "field report (simulated)", "simulation"))
    return summary(kde.analyse())


def main():
    ap = argparse.ArgumentParser(description="PlateauWatch: offline KDE hotspot early warning (Plateau State)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "analyse", "pai", "reset"):
        sub.add_parser(n)
    f = sub.add_parser("flare", help="simulate a wave of attacks in a quiet LGA")
    f.add_argument("--lga", default="Kanam")
    i = sub.add_parser("import", help="import a CSV file")
    i.add_argument("file")
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Logins: coordinator / ChangeMe@468 (can import data), observer / ChangeMe@468 (view only)")
    elif a.cmd == "serve":
        import server
        server.serve()
    elif a.cmd == "analyse":
        out = summary(kde.analyse())
    elif a.cmd == "pai":
        out = kde.pai()
    elif a.cmd == "flare":
        out = flare(a.lga)
    elif a.cmd == "import":
        out = kde.import_csv(open(a.file, encoding="utf-8").read(), "cli")
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
