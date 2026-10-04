"""ZamfaraGuard command line. `python main.py -h` for help."""
import argparse
import json
import os
import random
import shutil
import time

import geo
import trust as tr

RELIABLE = [f"0803{1000000 + i}" for i in range(12)]
UNRELIABLE = [f"0905{2000000 + i}" for i in range(4)]


def reset():
    shutil.rmtree(tr.DATA, ignore_errors=True)


def setup():
    """Build reputations from 30 days of past events: reliable informants mostly right, a few rumour spreaders mostly wrong."""
    reset()
    tr.db().close()
    tr.init()
    import app
    pw = os.environ.get("ZAMFARAGUARD_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_staff("verifier", pw, "verifier")
    app.add_staff("analyst", pw, "analyst")
    rnd = random.Random(14)
    now = time.time()
    events = 0
    for d in range(30, 3, -1):
        for _ in range(2):
            g = rnd.choice(geo.lgas())
            t = now - d * 86400 + rnd.uniform(0, 40000)
            real = rnd.random() < 0.75
            pool = rnd.sample(RELIABLE, 2) if real else rnd.sample(UNRELIABLE, 2)
            kind = rnd.choice(list(geo.TYPES))
            ids = []
            for k, ph in enumerate(pool):
                r = tr.submit(ph, g["lat"] + rnd.gauss(0, .01), g["lon"] + rnd.gauss(0, .01), kind, f"report {d}-{k}", ts=t + k * 900)
                ids.append(r["report"])
            with tr.db() as con:
                cid = con.execute("SELECT cluster FROM reports WHERE id=?", (ids[0],)).fetchone()["cluster"]
            tr.verify(cid, real, "history")
            events += 1
    return {"past_events": events}


def scenario(now=None):
    """Two things happen at the same time: a real attack in Maru reported by three trusted informants,
    and a coordinated rumour about Gusau sent from six brand-new numbers with copy-paste text."""
    now = now or time.time()
    g, h = geo.lga("Maru"), geo.lga("Gusau")
    out = []
    for k, ph in enumerate(RELIABLE[:3]):
        out.append(tr.submit(ph, g["lat"] + 0.01 * k, g["lon"], "armed_attack", ["gunmen on motorcycles attacked the market",
                                                                                 "they are shooting near the market", "attack at market now, people running"][k],
                             ts=now + k * 600))
    for k in range(6):
        out.append(tr.submit(f"0816{5550000 + k}", h["lat"], h["lon"] + 0.005 * k, "killing",
                             "herders have killed many people in gusau town share this now", ts=now + k * 120))
    out.append(tr.submit("07011112222", geo.lga("Anka")["lat"], geo.lga("Anka")["lon"], "threat", "heard rumour of attack", ts=now))
    return out


def main():
    ap = argparse.ArgumentParser(description="ZamfaraGuard: trust-weighted crowdsourced early warning (Zamfara State)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "scenario", "clusters", "reset"):
        sub.add_parser(n)
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Logins: verifier / ChangeMe@468 (records verdicts), analyst / ChangeMe@468. Public form at /report.")
    elif a.cmd == "serve":
        import app
        app.serve()
    elif a.cmd == "scenario":
        scenario()
        out = [c for c in tr.recluster() if c["reports"] > 0][:10]
    elif a.cmd == "clusters":
        with tr.db() as con:
            out = [dict(r) for r in con.execute("SELECT id,lga,type,reports,reporters,credibility,status,flag FROM clusters "
                                                "WHERE created>? ORDER BY created DESC", (time.time() - 86400,))]
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
