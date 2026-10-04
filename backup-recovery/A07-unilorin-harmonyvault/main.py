"""HarmonyVault command line. `python main.py -h` for help."""
import argparse
import json
import os
import shutil

import demo
import history as h


def reset():
    for d in ("data", "sample_data"):
        shutil.rmtree(os.path.join(h.BASE, d), ignore_errors=True)


def setup():
    reset()
    h.init()
    import web
    pw = os.environ.get("HARMONYVAULT_ADMIN_PASSWORD", "ChangeMe@468")
    web.add_member("custodian", pw, "custodian")
    web.add_member("reviewer", pw, "reviewer")
    demo.seed()
    h.plant_honey()
    return h.commit("initial backup", "setup")


def main():
    ap = argparse.ArgumentParser(description="HarmonyVault: signed Git-style backup history (UNILORIN)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "verify", "log", "attack", "stealth", "outage", "portal", "peek-honey", "reset"):
        sub.add_parser(n)
    c = sub.add_parser("commit")
    c.add_argument("-m", default="manual backup")
    r = sub.add_parser("restore")
    r.add_argument("--commit")
    r.add_argument("--to")
    d = sub.add_parser("diff")
    d.add_argument("a")
    d.add_argument("b")
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Login: custodian / ChangeMe@468 (reviewer is read-only)")
    elif a.cmd == "serve":
        demo.portal(h.cfg()["portal_port"], background=True)
        import web
        web.serve()
    elif a.cmd == "commit":
        out = h.commit(a.m, "cli")
    elif a.cmd == "restore":
        out = h.checkout(a.commit, a.to, who="cli")
    elif a.cmd == "verify":
        out = h.verify_chain()
    elif a.cmd == "diff":
        with h.db() as con:
            ids = [con.execute("SELECT id FROM commits WHERE id LIKE ?", (x + "%",)).fetchone()["id"] for x in (a.a, a.b)]
        out = h.diff(*ids)
    elif a.cmd == "log":
        with h.db() as con:
            for r in con.execute("SELECT * FROM commits ORDER BY rowid DESC"):
                print(r["id"][:12], r["at"], f"+{r['added']} ~{r['changed']} -{r['removed']}", r["message"])
    elif a.cmd == "attack":
        out = f"{demo.attack()} files encrypted"
    elif a.cmd == "stealth":
        out = f"{demo.stealth()} CSV files overwritten"
    elif a.cmd == "peek-honey":
        pth = os.path.join(demo.source_dir(), "Exam_Questions_2026_CONFIDENTIAL", "CSC468_exam_paper.txt")
        open(pth, "a").write("copied by intruder\n")
        out = "an intruder edited a honey file"
    elif a.cmd == "outage":
        out = "portal stopped" if demo.stop_portal() else "portal not running"
    elif a.cmd == "portal":
        demo.portal(h.cfg()["portal_port"], background=True)
        out = "portal started"
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
