"""SahelStore command line. All write actions live here (the web page is read-only)."""
import argparse
import json
import os
import shutil

import demo
import sahel


def reset():
    for d in ("data", "sample_data"):
        shutil.rmtree(os.path.join(sahel.BASE, d), ignore_errors=True)


def setup():
    reset()
    sahel.init()
    import status_page
    status_page.add_viewer("ictstaff", os.environ.get("SAHELSTORE_VIEW_PASSWORD", "ChangeMe@468"))
    demo.seed()
    first = sahel.snapshot("initial")
    sahel.sync(force=True)
    return first


def ups(percent, plugged):
    json.dump({"percent": percent, "plugged": plugged}, open(os.path.join(sahel.DATA, "ups_override.json"), "w"))


def main():
    ap = argparse.ArgumentParser(description="SahelStore: low-bandwidth, power-aware backup (UNIMAID)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "snapshot", "sync", "restore", "restore-offsite", "status", "attack", "stealth",
              "outage", "portal", "power-cut", "battery-critical", "power-back", "lose-local", "verify-log", "reset"):
        sub.add_parser(n)
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Status page login: ictstaff / ChangeMe@468 (read-only)")
    elif a.cmd == "serve":
        demo.portal(sahel.cfg()["portal_port"], background=True)
        import status_page
        status_page.serve()
    elif a.cmd == "snapshot":
        out = sahel.snapshot("manual")
    elif a.cmd == "sync":
        out = sahel.sync(force=True)
    elif a.cmd == "restore":
        out = sahel.restore()
    elif a.cmd == "restore-offsite":
        out = sahel.restore_offsite()
    elif a.cmd == "status":
        with sahel.db() as con:
            for r in con.execute("SELECT * FROM snaps ORDER BY id DESC LIMIT 10"):
                print(r["id"], r["at"], r["kind"], "ok" if r["ok"] else "REFUSED", r["why"] or "")
            q = con.execute("SELECT COUNT(*) n FROM queue").fetchone()["n"]
        print("offsite queue:", q, "| sent today:", sahel.sent_today(), "bytes | power:", sahel.power_state())
    elif a.cmd == "attack":
        out = f"{demo.attack()} files encrypted"
    elif a.cmd == "stealth":
        out = f"{demo.stealth()} CSV files overwritten"
    elif a.cmd == "outage":
        out = "portal stopped" if demo.stop_portal() else "portal not running"
    elif a.cmd == "portal":
        demo.portal(sahel.cfg()["portal_port"], background=True)
        out = "portal started"
    elif a.cmd == "power-cut":
        ups(35, False)
        out = "simulated: mains off, inverter battery 35% (heavy jobs will wait)"
    elif a.cmd == "battery-critical":
        ups(12, False)
        out = "simulated: inverter battery 12% (emergency snapshot on next tick)"
    elif a.cmd == "power-back":
        os.remove(os.path.join(sahel.DATA, "ups_override.json"))
        out = "simulated: mains power restored"
    elif a.cmd == "lose-local":
        shutil.rmtree(sahel.p(sahel.cfg()["local_store"]))
        out = "local backup store deleted (simulated flood in the server room)"
    elif a.cmd == "verify-log":
        out = "log chain INTACT" if sahel.log_ok() else "log chain BROKEN"
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
