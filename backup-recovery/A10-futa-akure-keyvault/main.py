"""AkureKeyVault command line. `python main.py -h` for help."""
import argparse
import glob
import json
import os
import shutil

import demo
import keyvault as kv


def reset():
    for d in ("data", "sample_data"):
        shutil.rmtree(os.path.join(kv.BASE, d), ignore_errors=True)


def setup():
    reset()
    kv.db().close()
    shares = kv.new_keypair(1)
    import app
    pw = os.environ.get("AKUREKEYVAULT_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_operator("operator", pw, "operator")
    app.add_operator("auditor", pw, "auditor")
    demo.seed()
    return kv.backup("setup"), shares


def demo_shares(who=("registrar", "bursar")):
    v = kv.active_key()["version"]
    return [open(os.path.join(kv.DATA, "shares_to_print", f"{c}_v{v}.txt")).read().strip() for c in who]


def main():
    ap = argparse.ArgumentParser(description="AkureKeyVault: split-key envelope encryption backups (FUTA)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "backup", "verify", "shares", "list", "attack", "stealth", "outage", "portal", "reset"):
        sub.add_parser(n)
    r = sub.add_parser("restore", help="restore using two shares from data/shares_to_print (demo)")
    r.add_argument("--id", type=int)
    r.add_argument("--custodians", default="registrar,bursar")
    sub.add_parser("rotate")
    s = sub.add_parser("shred")
    s.add_argument("--id", type=int, required=True)
    s.add_argument("--reason", default="NDPA erasure request")
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        first, shares = setup()
        print(json.dumps(first, indent=1))
        print("Custodian shares (in real use print and hand over, then delete data/shares_to_print):")
        for c, sh in shares.items():
            print(f"  {c:13s} {sh}")
        print("Login: operator / ChangeMe@468 (auditor is read-only)")
    elif a.cmd == "serve":
        demo.portal(kv.cfg()["portal_port"], background=True)
        import app
        app.serve()
    elif a.cmd == "backup":
        out = kv.backup("cli")
    elif a.cmd == "restore":
        out = kv.restore(demo_shares(a.custodians.split(",")), a.id)
    elif a.cmd == "rotate":
        r = kv.rotate(demo_shares())
        out = {"new_version": r["new_version"], "rewrapped": r["rewrapped"]}
    elif a.cmd == "shred":
        out = kv.shred(a.id, a.reason)
    elif a.cmd == "verify":
        out = kv.verify()
    elif a.cmd == "shares":
        for f in sorted(glob.glob(os.path.join(kv.DATA, "shares_to_print", "*.txt"))):
            print(os.path.basename(f), open(f).read().strip())
    elif a.cmd == "list":
        with kv.db() as con:
            for b in con.execute("SELECT id,at,files,key_version,shredded FROM backups"):
                print(dict(b))
    elif a.cmd == "attack":
        out = f"{demo.attack()} files encrypted"
    elif a.cmd == "stealth":
        out = f"{demo.stealth()} CSV files overwritten"
    elif a.cmd == "outage":
        out = "portal stopped" if demo.stop_portal() else "portal not running"
    elif a.cmd == "portal":
        demo.portal(kv.cfg()["portal_port"], background=True)
        out = "portal started"
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
