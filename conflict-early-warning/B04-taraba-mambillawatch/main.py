"""MambillaWatch command line. `python main.py -h` for help."""
import argparse
import datetime as dt
import json
import os
import shutil
import time
import urllib.error
import urllib.request

import fence
import geo

COLLARS = [("TRB-001", "Ardo Musa herd", "Miyetti Allah Gassol branch", 180),
           ("TRB-002", "Ardo Bello herd", "Mambilla herders association", 240),
           ("TRB-003", "Jauro Sani herd", "Bali herders association", 150),
           ("TRB-004", "Lamido Isa herd", "Wukari herders association", 120)]


def reset():
    shutil.rmtree(fence.DATA, ignore_errors=True)


def setup():
    reset()
    fence.db().close()
    import app
    pw = os.environ.get("MAMBILLAWATCH_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_staff("coordinator", pw, "coordinator")
    app.add_staff("ranger", pw, "ranger")
    keys = {cid: fence.register(cid, herd, grp, heads) for cid, herd, grp, heads in COLLARS}
    with fence.db() as con:
        for g in geo.lgas():
            con.execute("INSERT INTO leaders VALUES(?,?,?)", (g["name"], "farmers", f"{g['name']} farmers' union chair"))
            con.execute("INSERT INTO leaders VALUES(?,?,?)", (g["name"], "herders", f"{g['name']} herders' Ardo"))
    json.dump(keys, open(os.path.join(fence.DATA, "collar_keys.json"), "w"), indent=1)
    return {"collars": list(keys)}


def target_farm(lga_name):
    month = dt.datetime.now().month
    return next(f for f in fence.farms() if f["lga"] == lga_name and fence.in_season(f, month))


def send(cid, counter, lat, lon, battery, key, url):
    body = json.dumps({"collar": cid, "counter": counter, "lat": round(lat, 5), "lon": round(lon, 5), "battery": battery,
                       "sig": fence.sign(key, cid, counter, round(lat, 5), round(lon, 5), battery)}).encode()
    req = urllib.request.Request(url + "/api/ping", data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=5).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def scenario():
    """Four herds: TRB-001 walks into an in-season farm in Bali, TRB-002 stays on the corridor,
    TRB-003 drifts off the corridor, TRB-004's collar is spoofed (teleports)."""
    route = list(geo.cfg()["routes"].values())[0]
    f = target_farm("Bali")
    flat, flon = fence.centroid(f["ring"])
    paths = {"TRB-001": [(flat + 0.06 - 0.006 * i, flon + 0.03 - 0.003 * i) for i in range(11)],
             "TRB-002": [(route[2][0] - 0.02 * i, route[2][1] + 0.025 * i) for i in range(11)],
             "TRB-003": [(8.30 + 0.01 * i, 10.20 + 0.012 * i) for i in range(11)],
             "TRB-004": [(7.60, 9.90)] * 5 + [(6.80, 11.20)] + [(7.60, 9.90)] * 5}
    return paths


def simulate(interval, url=None):
    url = url or f"http://127.0.0.1:{geo.cfg()['port']}"
    keys = json.load(open(os.path.join(fence.DATA, "collar_keys.json")))
    with fence.db() as con:
        counters = {r["id"]: r["last_counter"] for r in con.execute("SELECT id, last_counter FROM collars")}
    paths = scenario()
    for step in range(11):
        for cid, path in paths.items():
            counters[cid] += 1
            lat, lon = path[step]
            r = send(cid, counters[cid], lat, lon, 80 - step * (7 if cid == "TRB-003" else 1), keys[cid], url)
            for a in r.get("alerts", []):
                print(f"  {a['kind']}: {a['text'][:110]}")
            if not r.get("accepted"):
                print(f"  {cid} ping refused: {r.get('reason')}")
        print(f"step {step + 1}/11 sent")
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description="MambillaWatch: herd geofencing early warning (Taraba State)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "season", "reset"):
        sub.add_parser(n)
    s = sub.add_parser("simulate", help="live herd scenario against the running server")
    s.add_argument("--interval", type=float, default=3)
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Logins: coordinator / ChangeMe@468 (registers collars), ranger / ChangeMe@468")
    elif a.cmd == "serve":
        import app
        app.serve()
    elif a.cmd == "simulate":
        simulate(a.interval)
    elif a.cmd == "season":
        m = dt.datetime.now().month
        out = {crop: ("in field" if (s_[0] <= m <= s_[1]) else "off season") for crop, s_ in geo.cfg()["crop_calendar"].items()}
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
