"""YolaShield command line. `python main.py -h` for help."""
import argparse
import json
import os
import shutil
import urllib.parse
import urllib.request

import geo
import ledger


def reset():
    shutil.rmtree(ledger.DATA, ignore_errors=True)


def setup():
    reset()
    ledger.db().close()
    ledger.init()
    import server
    server.add_admin("commission", os.environ.get("YOLASHIELD_ADMIN_PASSWORD", "ChangeMe@468"))
    hist = geo.history(days=60, seed=55)
    with ledger.db() as con:
        con.executemany("INSERT INTO history VALUES(?,?,?,?)", [(h["ts"], h["lga"], h["type"], h["severity"]) for h in hist])
    return {"history_incidents": len(hist)}


def gateway(session, text, phone="+2348031234567"):
    """Act as the telco gateway against the running server."""
    import server
    body = urllib.parse.urlencode({"sessionId": session, "phoneNumber": phone, "text": text}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{geo.cfg()['port']}/ussd", data=body, method="POST",
                                 headers={"X-Gateway-Token": server.gateway_token()})
    return urllib.request.urlopen(req, timeout=5).read().decode()


def main():
    ap = argparse.ArgumentParser(description="YolaShield: USSD reporting with a signed ledger (Adamawa State)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "seal", "verify", "risk", "demo-calls", "tamper", "reset"):
        sub.add_parser(n)
    e = sub.add_parser("erase")
    e.add_argument("ref")
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Staff login: commission / ChangeMe@468")
    elif a.cmd == "serve":
        import server
        server.serve()
    elif a.cmd == "seal":
        out = ledger.seal_if_due(force=True)
    elif a.cmd == "verify":
        out = ledger.verify()
    elif a.cmd == "risk":
        out = ledger.risk()
    elif a.cmd == "erase":
        out = ledger.erase(a.ref, "data subject request")
    elif a.cmd == "tamper":
        with ledger.db() as con:
            r = con.execute("SELECT ref FROM records WHERE block IS NOT NULL LIMIT 1").fetchone()
            con.execute("UPDATE records SET type='threat', lga='Yola South' WHERE ref=?", (r["ref"],))
        out = f"an insider edited report {r['ref']} in the database; run verify"
    elif a.cmd == "demo-calls":
        calls = [("D1", "2*1*3*2*1*1"), ("D2", "1*1*1*0*3*2*1"), ("D3", "3*3*2*1*2*1"), ("D4", "2*1*3*2*1*1"),
                 ("D5", "1*2*0*2"), ("D6", "2*4*1")]
        for sid, path in calls:
            steps = path.split("*")
            for i in range(len(steps) + 1):
                print(f"[{sid}] {('*'.join(steps[:i]) or '(dial)'):<16} -> {gateway(sid, '*'.join(steps[:i])).splitlines()[0]}")
        out = ledger.seal_if_due(force=True)
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
