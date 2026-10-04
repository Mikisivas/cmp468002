"""ZariaSafe command line. Run `python main.py -h` for the list of commands."""
import argparse
import json
import os
import shutil

import core
import demo


def reset():
    for d in ("data", "sample_data"):
        shutil.rmtree(os.path.join(core.BASE, d), ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="ZariaSafe: versioned-mirror backup and recovery (ABU Zaria)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, text in [("setup", "create keys, users and demo data, then take the first backup"),
                       ("serve", "start the web console and scheduler"),
                       ("backup", "take a backup now"), ("verify", "check every encrypted object, repair from replicas"),
                       ("list", "list versions"), ("monitor", "run one monitoring cycle"),
                       ("attack", "SAFE simulated ransomware on the demo data"),
                       ("stealth", "SAFE quiet ransomware (names unchanged)"),
                       ("outage", "stop the demo student portal"), ("portal", "start the demo student portal"),
                       ("reset", "delete all demo data and keys")]:
        sub.add_parser(name, help=text)
    r = sub.add_parser("restore", help="restore a version (default: latest good)")
    r.add_argument("--version")
    r.add_argument("--to", help="restore into another folder instead of the live one")
    p = sub.add_parser("prune", help="keep only the newest N versions")
    p.add_argument("--keep", type=int, default=None)
    a = ap.parse_args()
    if a.cmd == "setup":
        reset()
        core.init(os.environ.get("ZARIASAFE_ADMIN_PASSWORD", "ChangeMe@468"))
        demo.seed()
        print(json.dumps(core.backup(actor="setup"), indent=1))
        print("Setup complete. Login: admin / ChangeMe@468 (auditor is read-only)")
    elif a.cmd == "serve":
        demo.portal(core.load_config()["portal_port"], background=True)
        import web
        web.serve()
    elif a.cmd == "backup":
        print(json.dumps(core.backup(actor="cli"), indent=1))
    elif a.cmd == "verify":
        print(json.dumps(core.verify(), indent=1))
    elif a.cmd == "restore":
        print(json.dumps(core.restore(a.version, a.to, actor="cli"), indent=1))
    elif a.cmd == "list":
        with core.db() as con:
            for v in con.execute("SELECT * FROM versions ORDER BY id"):
                print(v["id"], v["status"], v["files"], "files", v["changed"], "changed", v["note"])
    elif a.cmd == "prune":
        print(core.prune(a.keep or core.load_config()["keep_versions"]))
    elif a.cmd == "monitor":
        print(core.monitor_once())
    elif a.cmd == "attack":
        print(demo.attack(), "files encrypted and renamed to .locked")
    elif a.cmd == "stealth":
        print(demo.stealth(), "CSV files overwritten in place")
    elif a.cmd == "outage":
        print("portal stopped" if demo.stop_portal() else "portal was not running")
    elif a.cmd == "portal":
        demo.portal(core.load_config()["portal_port"], background=True)
        print("portal started")
    elif a.cmd == "reset":
        reset()
        print("demo data removed")


if __name__ == "__main__":
    main()
