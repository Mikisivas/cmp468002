"""KanoShield command line. `python main.py -h` for help."""
import argparse
import json
import os
import shutil

import demo
import shield as s


def reset():
    for d in ("data", "sample_data"):
        shutil.rmtree(os.path.join(s.BASE, d), ignore_errors=True)


def setup():
    reset()
    s.init()
    pw = os.environ.get("KANOSHIELD_ADMIN_PASSWORD", "ChangeMe@468")
    secrets_out = {}
    for name in ("ictdirector", "deputyregistrar"):
        secrets_out[name] = s.add_user(name, pw, "admin")
        open(os.path.join(s.DATA, "keys", f"totp_{name}.txt"), "w").write(s.otpauth_uri(name, secrets_out[name]) + "\n")
    s.add_user("auditor", pw, "auditor")
    demo.seed()
    first = s.backup("setup")
    s.replicate()
    return first, secrets_out


def main():
    ap = argparse.ArgumentParser(description="KanoShield: WORM vault, four-eyes approvals and TOTP (BUK)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "backup", "verify", "replicate", "list", "attack", "stealth", "outage", "portal",
              "reset"):
        sub.add_parser(n)
    c = sub.add_parser("code", help="show the current 6-digit code for an admin (demo without a phone)")
    c.add_argument("--user", default="ictdirector")
    d = sub.add_parser("try-delete", help="try to delete a backup (shows the WORM lock)")
    d.add_argument("--id", type=int, default=1)
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        first, sec = setup()
        print(json.dumps(first, indent=1))
        print("Admins: ictdirector and deputyregistrar, password ChangeMe@468, plus an authenticator code.")
        print("Add the otpauth links in data/keys/totp_*.txt to an authenticator app, or run: python main.py code")
        print("auditor / ChangeMe@468 is read-only and needs no code.")
    elif a.cmd == "serve":
        demo.portal(s.cfg()["portal_port"], background=True)
        import app
        app.serve()
    elif a.cmd == "code":
        with s.ops() as con:
            u = con.execute("SELECT totp FROM users WHERE name=?", (a.user,)).fetchone()
        out = f"{a.user}: {s.totp(u['totp'])} (changes every 30 s)"
    elif a.cmd == "backup":
        out = s.backup("cli")
    elif a.cmd == "verify":
        out = s.verify()
    elif a.cmd == "replicate":
        out = s.replicate()
    elif a.cmd == "try-delete":
        out = f"delete backup {a.id}: {s.try_delete(a.id)}"
    elif a.cmd == "list":
        with s.vault() as v:
            for r in v.execute("SELECT id,at,files,retain_until,released FROM backups"):
                print(dict(r))
    elif a.cmd == "attack":
        out = f"{demo.attack()} files encrypted"
    elif a.cmd == "stealth":
        out = f"{demo.stealth()} CSV files overwritten"
    elif a.cmd == "outage":
        out = "portal stopped" if demo.stop_portal() else "portal not running"
    elif a.cmd == "portal":
        demo.portal(s.cfg()["portal_port"], background=True)
        out = "portal started"
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
