"""KadunaCorridor command line. `python main.py -h` for help."""
import argparse
import json
import os
import random
import shutil
import time

import geo
import hawkes as hk


def reset():
    shutil.rmtree(hk.DATA, ignore_errors=True)


def setup():
    reset()
    hk.db().close()
    import app
    pw = os.environ.get("KADUNACORRIDOR_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_staff("analyst", pw, "analyst")
    app.add_staff("commander", pw, "commander")
    hist = geo.history(days=400, seed=77, retaliation=0.45)
    with hk.db() as con:
        con.executemany("INSERT INTO incidents(ts,lga,lat,lon,type,severity,fatalities,source) VALUES(?,?,?,?,?,?,?,?)",
                        [(h["ts"], h["lga"], h["lat"], h["lon"], h["type"], h["severity"], h["fatalities"], "history (synthetic)")
                         for h in hist])
    f = hk.fit()
    hk.forecast()
    return {"incidents": len(hist), "fit": {k: v for k, v in f.items() if k != "mu_per_day"}}


def flare(lga_name="Sanga", n=3):
    g = geo.lga(lga_name)
    rnd = random.Random(2)
    with hk.db() as con:
        for i in range(n):
            con.execute("INSERT INTO incidents(ts,lga,lat,lon,type,severity,fatalities,source) VALUES(?,?,?,?,?,?,?,?)",
                        (time.time() - (n - i) * 14 * 3600, lga_name, g["lat"] + rnd.gauss(0, .02), g["lon"] + rnd.gauss(0, .02),
                         ["armed_attack", "killing", "cattle_killing"][i % 3], 4, i, "field report (simulated)"))
    return [r for r in hk.forecast() if r["lga"] == lga_name][0]


def main():
    ap = argparse.ArgumentParser(description="KadunaCorridor: Hawkes escalation forecasting (Southern Kaduna)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "fit", "forecast", "chains", "reset"):
        sub.add_parser(n)
    f = sub.add_parser("flare", help="simulate an attack and two reprisals in one LGA")
    f.add_argument("--lga", default="Sanga")
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Logins: analyst / ChangeMe@468 (can refit), commander / ChangeMe@468")
    elif a.cmd == "serve":
        import app
        app.serve()
    elif a.cmd == "fit":
        out = hk.fit()
    elif a.cmd == "forecast":
        out = hk.forecast()
    elif a.cmd == "chains":
        out = [[(time.strftime("%d %b %H:%M", time.localtime(e["ts"])), e["lga"], e["type"]) for e in c] for c in hk.chains()[:5]]
    elif a.cmd == "flare":
        out = flare(a.lga)
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
