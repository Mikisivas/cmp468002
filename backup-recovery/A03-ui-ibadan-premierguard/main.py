"""PremierGuard command line. `python main.py -h` for help."""
import argparse
import json
import os
import shutil

import demo
import engine


def reset():
    for d in ("data", "sample_data"):
        shutil.rmtree(os.path.join(engine.BASE, d), ignore_errors=True)


def setup():
    reset()
    engine.init()
    import server
    pw = os.environ.get("PREMIERGUARD_ADMIN_PASSWORD", "ChangeMe@468")
    server.add_account("admin", pw, "admin")
    server.add_account("observer", pw, "observer")
    demo.seed()
    return engine.snapshot(note="initial")


def main():
    ap = argparse.ArgumentParser(description="PremierGuard: de-duplicated Merkle snapshots (University of Ibadan)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "snapshot", "verify", "list", "monitor", "attack", "stealth", "outage", "portal",
              "reset"):
        sub.add_parser(n)
    r = sub.add_parser("restore")
    r.add_argument("--id", type=int)
    r.add_argument("--to")
    g = sub.add_parser("gc")
    g.add_argument("--keep", type=int, default=30)
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Login: admin / ChangeMe@468 (observer is read-only)")
    elif a.cmd == "serve":
        demo.portal(engine.cfg()["portal_port"], background=True)
        import server
        server.serve()
    elif a.cmd == "snapshot":
        out = engine.snapshot(note="cli")
    elif a.cmd == "verify":
        out = engine.verify()
    elif a.cmd == "restore":
        out = engine.restore(a.id, a.to)
    elif a.cmd == "gc":
        out = engine.garbage_collect(a.keep)
    elif a.cmd == "list":
        with engine.db() as con:
            for r in con.execute("SELECT * FROM snapshots ORDER BY id"):
                print(r["id"], r["created"], r["status"], r["files"], "files", r["chunks_new"], "new chunks",
                      (r["merkle_root"] or "")[:16], r["note"])
    elif a.cmd == "monitor":
        out = engine.sample()
    elif a.cmd == "attack":
        out = f"{demo.attack()} files encrypted"
    elif a.cmd == "stealth":
        out = f"{demo.stealth()} CSV files overwritten"
    elif a.cmd == "outage":
        out = "portal stopped" if demo.stop_portal() else "portal not running"
    elif a.cmd == "portal":
        demo.portal(engine.cfg()["portal_port"], background=True)
        out = "portal started"
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
