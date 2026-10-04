"""LionKeep command line. Run `python main.py -h` for help."""
import argparse
import json
import os
import shutil

import core
import demo


def reset():
    for d in ("data", "sample_data"):
        shutil.rmtree(os.path.join(core.BASE, d), ignore_errors=True)


def setup():
    reset()
    core.init()
    import app
    pw = os.environ.get("LIONKEEP_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_user("admin", pw, "admin")
    app.add_user("operator", pw, "operator")
    app.add_user("viewer", pw, "viewer")
    demo.seed()
    core.log("setup", "users and keys created")
    return core.backup("full", who="setup")


def main():
    ap = argparse.ArgumentParser(description="LionKeep: full + differential encrypted backups (UNN)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "full", "diff", "verify", "rotate", "list", "monitor", "attack", "stealth",
              "outage", "portal", "reset"):
        sub.add_parser(n)
    r = sub.add_parser("restore")
    r.add_argument("--id", type=int)
    r.add_argument("--to")
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Login: admin / ChangeMe@468 (operator and viewer use the same demo password)")
    elif a.cmd == "serve":
        demo.portal(core.cfg()["portal_port"], background=True)
        import app
        app.serve()
    elif a.cmd in ("full", "diff"):
        out = core.backup(a.cmd, who="cli")
    elif a.cmd == "verify":
        out = core.verify()
    elif a.cmd == "rotate":
        out = core.rotate()
    elif a.cmd == "restore":
        out = core.restore(a.id, a.to, who="cli")
    elif a.cmd == "list":
        with core.db() as con:
            for r in con.execute("SELECT * FROM archives ORDER BY id"):
                print(r["id"], r["created"], r["kind"], r["tier"], r["files"], "files", r["stored_bytes"], "bytes")
    elif a.cmd == "monitor":
        out = core.monitor_once()
    elif a.cmd == "attack":
        out = f"{demo.attack()} files encrypted and renamed"
    elif a.cmd == "stealth":
        out = f"{demo.stealth()} CSV files overwritten in place"
    elif a.cmd == "outage":
        out = "portal stopped" if demo.stop_portal() else "portal not running"
    elif a.cmd == "portal":
        demo.portal(core.cfg()["portal_port"], background=True)
        out = "portal started"
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(json.dumps(out, indent=1) if not isinstance(out, str) else out)


if __name__ == "__main__":
    main()
