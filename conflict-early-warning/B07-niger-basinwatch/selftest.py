"""NigerBasinWatch end-to-end test. Resets demo data first. Results in results/selftest.json."""
import io
import json
import os
import time

import geo
import main as cli
import tpi

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    t0 = time.time()
    s = cli.setup()
    res["setup"] = s
    res["setup_seconds"] = round(time.time() - t0, 2)
    case("Three years of weekly NDVI and rainfall imported and fingerprinted", s["dataset_rows"] == 156 * 13, s)
    case("Spearman of identical rankings is 1", abs(tpi.spearman([1, 2, 3, 4], [10, 20, 30, 40]) - 1) < 1e-9)
    v = tpi.validate()
    res["validation"] = v
    case("Simulation study: monthly TPI tracks incident counts (Spearman rho > 0.3)", v["spearman_rho"] > 0.3, v)

    h = tpi.history_tpi()
    by_month = {}
    for (lga_name, wk), t in h.items():
        by_month.setdefault(int(wk[5:7]), []).append(t)
    means = {m: round(sum(v_) / len(v_), 3) for m, v_ in sorted(by_month.items())}
    res["mean_tpi_by_month"] = means
    case("Pressure is low in the heart of the dry season (Jan-Feb, few crops in field)",
         means[1] < means[6] and means[2] < means[10], means)

    with tpi.db() as con:
        cal = con.execute("SELECT COUNT(*) FROM calendar").fetchone()[0]
    case("8-week calendar produced for every LGA", cal == 8 * len(geo.lgas()), cal)
    d = cli.drought_update()
    res["drought_update"] = d
    rises = sum(1 for b, a in d["peak_tpi_change"].values() if a > b)
    case("A northern drought week raises projected pressure in most LGAs", rises >= len(geo.lgas()) * 0.75,
         f"{rises}/{len(geo.lgas())} LGAs higher")

    bad = "area,week,ndvi,rain_mm\nMokwa,2026-01-05,1.7,10\nAtlantis,2026-01-05,0.3,10\nMokwa,05/01/2026,0.3,10\n"
    r = tpi.import_csv(bad, "bad.csv", "test")
    case("Invalid dataset rejected with reasons (NDVI range, unknown area, bad date)", not r["accepted"] and r["error_count"] == 3,
         r["errors"])
    case("All stored dataset files match their sealed fingerprints", tpi.verify_datasets()["ok"])
    path = os.path.join(tpi.DATA, "datasets", sorted(os.listdir(os.path.join(tpi.DATA, "datasets")))[0])
    txt = open(path, newline="").read()
    open(path, "w", newline="").write(txt.replace("Mokwa,", "Mokwa ,", 1))
    vd = tpi.verify_datasets()
    case("Edited dataset file detected before it can mislead the forecast", not vd["ok"], vd["problems"])
    open(path, "w", newline="").write(txt)
    with tpi.db() as con:
        con.execute("UPDATE versions SET sha256='00' WHERE id=1")
    case("Forged fingerprint record detected (HMAC seal)", any("forged" in p or "changed" in p for p in tpi.verify_datasets()["problems"]))

    import app
    app.app.secret_key = "t"
    cl = app.app.test_client()
    cl.post("/login", data={"u": "planner", "p": "ChangeMe@468"})
    page = cl.get("/").data.decode()
    case("Calendar page shows the integrity warning when data is tampered", "DATASET INTEGRITY PROBLEM" in page)
    case("Planner cannot upload datasets", cl.post("/data", data={"csrf": "x"}).status_code == 403)
    case("LGA chart page renders", cl.get("/lga/Mokwa").status_code == 200)

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
