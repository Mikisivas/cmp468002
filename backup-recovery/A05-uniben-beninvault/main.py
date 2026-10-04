"""BeninVault command line. `python main.py -h` for help."""
import argparse
import json
import os
import shutil

import demo
import vault


def reset():
    for d in ("data", "sample_data"):
        shutil.rmtree(os.path.join(vault.BASE, d), ignore_errors=True)


def setup():
    reset()
    vault.init()
    import app
    pw = os.environ.get("BENINVAULT_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_person("admin", pw, "admin")
    app.add_person("auditor", pw, "auditor")
    demo.seed()
    return vault.backup("setup")


def main():
    ap = argparse.ArgumentParser(description="BeninVault: erasure-coded encrypted backup (UNIBEN)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "backup", "scrub", "list", "sla", "check", "attack", "stealth", "outage", "portal",
              "reset"):
        sub.add_parser(n)
    r = sub.add_parser("restore")
    r.add_argument("--id")
    r.add_argument("--to")
    k = sub.add_parser("lose-site", help="simulate losing one storage site (A, B or P)")
    k.add_argument("site", choices=["A", "B", "P"])
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Login: admin / ChangeMe@468 (auditor is read-only)")
    elif a.cmd == "serve":
        demo.portal(vault.cfg()["portal_port"], background=True)
        import app
        app.serve()
    elif a.cmd == "backup":
        out = vault.backup("cli")
    elif a.cmd == "restore":
        out = vault.restore(a.id, a.to, who="cli")
    elif a.cmd == "scrub":
        out = vault.scrub()
    elif a.cmd == "lose-site":
        path = vault.p(vault.cfg()["sites"][a.site])
        shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path)
        out = f"site {a.site} wiped: {vault.cfg()['site_names'][a.site]}"
    elif a.cmd == "list":
        with vault.db() as con:
            for r in con.execute("SELECT * FROM backups ORDER BY created"):
                print(r["id"], r["state"], r["files"], "files", r["reason"] or "")
    elif a.cmd == "sla":
        out = vault.sla()
    elif a.cmd == "check":
        vault.check_services()
        out = vault.sla()
    elif a.cmd == "attack":
        out = f"{demo.attack()} files encrypted"
    elif a.cmd == "stealth":
        out = f"{demo.stealth()} CSV files overwritten"
    elif a.cmd == "outage":
        out = "portal stopped" if demo.stop_portal() else "portal not running"
    elif a.cmd == "portal":
        demo.portal(vault.cfg()["portal_port"], background=True)
        out = "portal started"
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
