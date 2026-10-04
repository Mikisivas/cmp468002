"""NigerBasinWatch command line. `python main.py -h` for help."""
import argparse
import csv
import datetime as dt
import io
import json
import math
import os
import random
import shutil

import geo
import tpi


def reset():
    shutil.rmtree(tpi.DATA, ignore_errors=True)


def simulate_incidents(seed=8):
    """Synthetic incidents whose rate rises with environmental pressure, plus independent noise.
    This is a simulation study: it shows the pipeline can recover a known signal, nothing more."""
    rnd = random.Random(seed)
    h = tpi.history_tpi()
    rows = []
    for (lga_name, wk), t in h.items():
        base = 0.15 * (0.3 + geo.lga(lga_name)["baseline"])
        lam = base * (0.25 + 3.0 * t) * rnd.lognormvariate(0, 0.35)
        k, p, u = 0, math.exp(-lam), rnd.random()
        cum = p
        while u > cum and k < 8:
            k += 1
            p *= lam / k
            cum += p
        start = dt.datetime.strptime(wk, "%Y-%m-%d")
        for _ in range(k):
            ts = (start + dt.timedelta(seconds=rnd.randint(0, 7 * 86400 - 1))).timestamp()
            rows.append((ts, lga_name, rnd.choice(list(geo.TYPES)), rnd.randint(2, 5)))
    with tpi.db() as con:
        con.execute("DELETE FROM incidents")
        con.executemany("INSERT INTO incidents VALUES(?,?,?,?)", rows)
    return len(rows)


def setup():
    reset()
    tpi.db().close()
    tpi.init()
    import app
    pw = os.environ.get("BASINWATCH_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_staff("analyst", pw, "analyst")
    app.add_staff("planner", pw, "planner")
    text = tpi.synthetic_csv()
    with open(os.path.join(tpi.DATA, "sample_ndvi_rainfall.csv"), "w", newline="") as fh:
        fh.write(text)
    imp = tpi.import_csv(text, "sample_ndvi_rainfall.csv", "setup")
    n = simulate_incidents()
    cal = tpi.forecast()
    return {"dataset_rows": imp["rows"], "sha256": imp["sha256"][:16], "incidents": n, "calendar_cells": len(cal)}


def drought_update():
    """New satellite week arrives: northern pasture far below normal (simulated)."""
    last = tpi.series(tpi.NORTH)[-1][0]
    d = dt.datetime.strptime(last, "%Y-%m-%d") + dt.timedelta(weeks=1)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["area", "week", "ndvi", "rain_mm"])
    woy = d.isocalendar()[1]
    for g in geo.lgas():
        w.writerow([g["name"], d.strftime("%Y-%m-%d"), round(tpi.clim_ndvi(woy, g["lat"]), 3), 20])
    w.writerow([tpi.NORTH, d.strftime("%Y-%m-%d"), round(tpi.clim_ndvi(woy, 12.5) * 0.4, 3), 0])
    r = tpi.import_csv(out.getvalue(), f"modis_week_{d:%Y%m%d}.csv", "satellite feed")
    before = {}
    with tpi.db() as con:
        for row in con.execute("SELECT lga, MAX(tpi) m FROM calendar GROUP BY lga"):
            before[row["lga"]] = row["m"]
    tpi.forecast()
    with tpi.db() as con:
        after = {row["lga"]: row["m"] for row in con.execute("SELECT lga, MAX(tpi) m FROM calendar GROUP BY lga")}
    return {"import": {k: r[k] for k in ("accepted", "version", "rows")},
            "peak_tpi_change": {k: (round(before[k], 2), round(after[k], 2)) for k in after}}


def main():
    ap = argparse.ArgumentParser(description="NigerBasinWatch: seasonal transhumance pressure forecasting (Niger State)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "forecast", "drought", "validate", "verify-data", "reset"):
        sub.add_parser(n)
    i = sub.add_parser("import")
    i.add_argument("file")
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Logins: analyst / ChangeMe@468 (imports data), planner / ChangeMe@468")
    elif a.cmd == "serve":
        import app
        app.serve()
    elif a.cmd == "forecast":
        rows = tpi.forecast()
        out = sorted(rows, key=lambda r: -r[2])[:10]
    elif a.cmd == "drought":
        out = drought_update()
    elif a.cmd == "validate":
        out = tpi.validate()
    elif a.cmd == "verify-data":
        out = tpi.verify_datasets()
    elif a.cmd == "import":
        with open(a.file, encoding="utf-8", newline="") as fh:
            out = tpi.import_csv(fh.read(), a.file, "cli")
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
