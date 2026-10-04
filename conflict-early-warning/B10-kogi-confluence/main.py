"""ConfluenceEWS command line. `python main.py -h` for help."""
import argparse
import json
import os
import shutil
import time

import geo
import hub
from field import Tablet, provision

TABLETS = [("KG-TAB-01", "Inspector Ochala", "Omala"), ("KG-TAB-02", "Mrs Ayeni (peace officer)", "Bassa"),
           ("KG-TAB-03", "Mr Idakwo (extension worker)", "Ibaji"), ("KG-TAB-04", "Sgt Musa", "Kotonkarfe")]


def reset():
    shutil.rmtree(hub.DATA, ignore_errors=True)


def setup():
    reset()
    hub.db().close()
    import server
    server.add_admin("hub_admin", os.environ.get("CONFLUENCE_ADMIN_PASSWORD", "ChangeMe@468"))
    hist = geo.history(days=420, seed=91, daily_rate=0.05)
    with hub.db() as con:
        con.executemany("INSERT INTO history VALUES(?,?,?,?)", [(h["ts"], h["lga"], h["type"], h["severity"]) for h in hist])
    url = f"http://127.0.0.1:{geo.cfg()['port']}"
    for dev, officer, lga_name in TABLETS:
        provision(dev, officer, lga_name, url)
    ev = hub.train()
    hub.score()
    return {"history_incidents": len(hist), "tablets": [t[0] for t in TABLETS], "model": ev}


def field_day(transport=None):
    """Officers record incidents with no network, then sync when they reach a town."""
    t1, t2 = Tablet("KG-TAB-01"), Tablet("KG-TAB-02")
    a = t1.add("Omala", "armed_attack", 4, "attack on farm settlement near Abejukolo")
    t1.add("Omala", "cattle_killing", 3, "12 cattle killed in reprisal")
    t2.add("Bassa", "threat", 2, "youths issued ultimatum to herders")
    t1.edit(a, severity=5, note="attack on farm settlement, 2 killed (updated)")
    return {"KG-TAB-01": t1.sync(transport=transport), "KG-TAB-02": t2.sync(transport=transport)}


def main():
    ap = argparse.ArgumentParser(description="ConfluenceEWS: offline-first field reporting and risk model (Kogi State)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "train", "score", "field-day", "reset"):
        sub.add_parser(n)
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Hub login: hub_admin / ChangeMe@468. Tablets: python field.py add|sync|show --device KG-TAB-01")
    elif a.cmd == "serve":
        import server
        server.serve()
    elif a.cmd == "train":
        out = hub.train()
    elif a.cmd == "score":
        out = hub.score()
    elif a.cmd == "field-day":
        out = field_day()
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
