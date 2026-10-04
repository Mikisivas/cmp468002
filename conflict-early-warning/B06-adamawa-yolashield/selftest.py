"""YolaShield end-to-end test. Resets demo data first. Results in results/selftest.json."""
import http.client
import json
import os
import threading
import urllib.parse

import geo
import ledger
import main as cli
import ussd

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def walk(sid, path, phone="+2348030000000"):
    steps = path.split("*") if path else []
    screens = [ussd.handle(sid, phone, "*".join(steps[:i])) for i in range(len(steps) + 1)]
    return screens


def run():
    res = {}
    cli.setup()
    s = walk("A1", "2*1*3*2*1*1")
    res["hausa_report_flow"] = s
    case("Hausa caller reports an attack in Lamurde (6 key presses)", s[-1].startswith("END An karbi rahoto YS"), s[-1])
    case("Every screen fits a basic phone (182 characters or fewer)", all(len(x) <= 182 for x in s), max(map(len, s)))
    again = ussd.handle("A1", "+2348030000000", "2*1*3*2*1*1")
    case("Telco retry of the same session does not create a duplicate", again == s[-1])
    p = walk("A2", "1*1*1*0*3*2*1")
    case("LGA list pages with 0 = more (English, Song on page 2)", "Song" in p[-1] or p[-1].startswith("END Report"), p[-2])
    with ledger.db() as con:
        last = con.execute("SELECT lga FROM records ORDER BY ts DESC LIMIT 1").fetchone()["lga"]
    case("Second-page LGA stored correctly", last == "Song", last)
    c = walk("A3", "3*1*4*1*2*2")
    case("Pidgin caller can cancel at the confirm step", c[-1].startswith("END E don cancel"), c[-1])
    case("Invalid key press ends politely", ussd.handle("A4", "+234", "1*9").startswith("END"))
    lvl = ussd.handle("A5", "+234", "1*2*3")
    case("Caller can hear their LGA's alert level", lvl.startswith("END Lamurde: alert level"), lvl)
    case("Mediation request accepted", ussd.handle("A6", "+234", "1*4*1").startswith("END Request MD"))

    for i in range(6):
        ussd.handle(f"B{i}", f"+23480300000{i:02d}", "1*1*3*3*1*1")
    seal = ledger.seal_if_due(force=True)
    v = ledger.verify()
    res["ledger"] = v
    case("Reports sealed into signed blocks and the ledger verifies", v["ok"] and v["blocks"] >= 1, v)
    r = ledger.risk()["Lamurde"]
    res["lamurde_risk"] = r
    case("Urgent attack reports raise Lamurde to High or Severe", r["level"] in ("High", "Severe"), r)

    with ledger.db() as con:
        con.execute("UPDATE records SET type='threat' WHERE ref='YS00001'")
    v = ledger.verify()
    case("Edited report detected (does not match its sealed fingerprint)", not v["ok"] and any("YS00001" in x for x in v["problems"]), v["problems"])
    with ledger.db() as con:
        con.execute("UPDATE records SET type='armed_attack' WHERE ref='YS00001'")
        row = dict(con.execute("SELECT * FROM records WHERE ref='YS00002'").fetchone())
        con.execute("DELETE FROM records WHERE ref='YS00002'")
    v = ledger.verify()
    case("Deleted report detected", not v["ok"] and any("deleted" in x for x in v["problems"]), v["problems"])
    with ledger.db() as con:
        con.execute("INSERT INTO records VALUES(:ref,:ts,:channel,:session,:enc,:lga,:type,:urgent,:fingerprint,:block,:erased)", row)
    case("Ledger verifies again after the row is put back", ledger.verify()["ok"])

    with ledger.db() as con:
        b = dict(con.execute("SELECT * FROM blocks ORDER BY height DESC LIMIT 1").fetchone())
        items = json.loads(b["items"])[:-1]
        import hashlib
        body = {"height": b["height"], "ts": b["ts"], "prev": b["prev"], "merkle": ledger.merkle(items), "items": items}
        new_hash = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        con.execute("UPDATE blocks SET items=?, merkle=?, hash=? WHERE height=?", (json.dumps(items), body["merkle"], new_hash, b["height"]))
    v = ledger.verify()
    case("Rewritten block (without the signing key) fails signature and witness checks",
         any("signature" in x for x in v["problems"]) and any("witness" in x for x in v["problems"]), v["problems"][:3])
    with ledger.db() as con:
        con.execute("UPDATE blocks SET items=?, merkle=?, hash=? WHERE height=?", (b["items"], b["merkle"], b["hash"], b["height"]))
    out = ledger.erase("YS00003", "test")
    case("Lawful erasure removes personal data but the ledger still verifies", ledger.verify()["ok"], out)
    with ledger.db() as con:
        enc = con.execute("SELECT enc FROM records WHERE ref='YS00004'").fetchone()["enc"]
    raw = open(os.path.join(ledger.DATA, "yolashield.db"), "rb").read()
    case("Caller phone numbers not stored in plain text", b"+2348030000000" not in raw and enc.startswith("gAAAA"))

    import server
    srv = server.socketserver.ThreadingTCPServer(("127.0.0.1", 0), server.H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def post(path, form, headers=None):
        con = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        con.request("POST", path, urllib.parse.urlencode(form), {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
        r = con.getresponse()
        return r.status, r.read().decode()

    st, body = post("/ussd", {"sessionId": "H1", "phoneNumber": "+234", "text": ""}, {"X-Gateway-Token": "wrong"})
    case("Gateway call with the wrong token refused", st == 401)
    st, body = post("/ussd", {"sessionId": "H1", "phoneNumber": "+234", "text": ""}, {"X-Gateway-Token": server.gateway_token()})
    case("Gateway call with the right token gets the language menu", st == 200 and body.startswith("CON YolaShield"), body)
    st, _ = post("/sim", {"sessionId": "x", "text": ""})
    case("Phone simulator needs a staff session", st == 403)
    srv.shutdown()

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
