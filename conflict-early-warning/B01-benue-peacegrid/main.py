"""BenuePeaceGrid command line. `python main.py -h` for help."""
import argparse
import hashlib
import hmac
import json
import os
import random
import shutil
import time
import urllib.request

import geo
import grid


def reset():
    shutil.rmtree(grid.DATA, ignore_errors=True)


def setup():
    reset()
    grid.db().close()
    grid.init_keys()
    import app
    pw = os.environ.get("PEACEGRID_ADMIN_PASSWORD", "ChangeMe@468")
    for name, role in (("admin", "admin"), ("analyst", "analyst"), ("responder", "responder")):
        app.add_user(name, pw, role)
    cells = grid.build_grid()
    rnd = random.Random(5)
    with grid.db() as con:
        for g in geo.lgas():
            for role in ("DPO (police)", "Peace committee chair", "LGA chairman"):
                phone = "080" + str(rnd.randint(10000000, 99999999))
                con.execute("INSERT INTO contacts VALUES(?,?,?,?)", (g["name"], role, f"{g['name']} {role.split()[0]}",
                                                                   grid.fernet().encrypt(phone.encode()).decode()))
        hist = geo.history()
        con.executemany("INSERT INTO incidents(ts,lga,lat,lon,type,severity,fatalities,source,verified) "
                        "VALUES(?,?,?,?,?,?,?,?,1)", [(h["ts"], h["lga"], h["lat"], h["lon"], h["type"], h["severity"],
                                                      h["fatalities"], "history (synthetic)") for h in hist])
    devices = {f"COLLAR-{i:02d}": grid.register_device(f"COLLAR-{i:02d}") for i in range(1, 6)}
    json.dump(devices, open(os.path.join(grid.DATA, "keys", "devices.json"), "w"), indent=1)
    grid.score_all()
    grid.audit("setup", "system initialised")
    return {"hex_cells": cells, "history_incidents": len(hist), "devices": list(devices)}


def signed_ping(dev, secret, lat, lon, heads, url):
    body = json.dumps({"lat": round(lat, 5), "lon": round(lon, 5), "heads": heads}).encode()
    ts = str(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(url + "/api/ping", data=body, method="POST",
                                 headers={"X-Device": dev, "X-Time": ts, "X-Sig": sig, "Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=5).read()


def simulate(steps, interval):
    """Live demo: five collared herds move along the corridor; two drift into Guma farmland;
    a cluster of reports arrives from Guma. Runs against a server started with `serve`."""
    url = f"http://127.0.0.1:{geo.cfg()['port']}"
    devices = json.load(open(os.path.join(grid.DATA, "keys", "devices.json")))
    route = list(geo.cfg()["routes"].values())[0]
    target = next(f for f in geo.farmland() if f["lga"] == "Guma")
    tlat = sum(p[1] for p in target["ring"][:4]) / 4
    tlon = sum(p[0] for p in target["ring"][:4]) / 4
    rnd = random.Random(9)
    for step in range(steps):
        f = step / max(1, steps - 1)
        for i, (dev, secret) in enumerate(devices.items()):
            seg = min(int(f * (len(route) - 1)), len(route) - 2)
            frac = f * (len(route) - 1) - seg
            lat = route[seg][0] + (route[seg + 1][0] - route[seg][0]) * frac + rnd.gauss(0, 0.01)
            lon = route[seg][1] + (route[seg + 1][1] - route[seg][1]) * frac + rnd.gauss(0, 0.01)
            if i < 2:  # rogue herds head for the farms
                lat, lon = lat + (tlat - lat) * f, lon + (tlon - lon) * f
            signed_ping(dev, secret, lat, lon, 80 + 40 * i, url)
        if step % 5 == 4:
            with grid.db() as con:
                g = geo.lga("Guma")
                con.execute("INSERT INTO incidents(ts,lga,lat,lon,type,severity,fatalities,source) VALUES(?,?,?,?,?,?,?,?)",
                            (time.time(), "Guma", g["lat"] + rnd.gauss(0, .02), g["lon"] + rnd.gauss(0, .02),
                             rnd.choice(["crop_destruction", "threat", "armed_attack"]), 3, 0, "sms (simulated)"))
        print(f"step {step + 1}/{steps}: 5 herd pings sent")
        time.sleep(interval)
    grid.score_all()
    print("done; open the risk map and press Rescore now")


def main():
    ap = argparse.ArgumentParser(description="BenuePeaceGrid: AHP hexagon early warning (Benue State)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "score", "ahp", "backtest", "top", "reset"):
        sub.add_parser(n)
    s = sub.add_parser("simulate")
    s.add_argument("--steps", type=int, default=30)
    s.add_argument("--interval", type=float, default=2)
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Logins: admin, analyst, responder / ChangeMe@468")
    elif a.cmd == "serve":
        import app
        app.serve()
    elif a.cmd == "score":
        out = f"{len(grid.score_all())} cells scored"
    elif a.cmd == "ahp":
        out = grid.ahp()
    elif a.cmd == "backtest":
        out = grid.backtest()
    elif a.cmd == "top":
        _, rows = grid.latest_scores()
        for r in sorted(rows, key=lambda r: -r["score"])[:15]:
            print(r["hex"], r["lga"], r["level"], r["score"])
    elif a.cmd == "simulate":
        simulate(a.steps, a.interval)
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
