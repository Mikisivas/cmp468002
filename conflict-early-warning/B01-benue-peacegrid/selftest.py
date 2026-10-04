"""BenuePeaceGrid end-to-end test. Resets demo data first. Results in results/selftest.json."""
import hashlib
import hmac
import json
import os
import time

import geo
import grid
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    s = cli.setup()
    res["setup"] = s
    a = grid.ahp()
    res["ahp"] = a
    case("AHP weights sum to 1 and matrix is consistent (CR < 0.10)", abs(sum(a["weights"]) - 1) < 0.01 and a["consistent"],
         f"weights {a['weights']}, CR {a['cr']}")
    with grid.db() as con:
        covered = {r["lga"] for r in con.execute("SELECT DISTINCT lga FROM hexes")}
    case("Hexagon grid covers every LGA", covered == {g["name"] for g in geo.lgas()}, f"{s['hex_cells']} cells")

    bt = grid.backtest()
    res["backtest"] = bt
    case("Back-test: top 20% cells capture more future incidents than chance", bt["hit_rate"] > bt["chance_rate"],
         f"hit rate {bt['hit_rate']} vs chance {bt['chance_rate']} (lift {bt['lift']})")

    t0 = time.time()
    scores = grid.score_all()
    res["scoring_seconds"] = round(time.time() - t0, 3)
    before = max(x["score"] for x in scores if x["lga"] == "Kwande")
    g = geo.lga("Kwande")
    with grid.db() as con:
        for i in range(6):
            con.execute("INSERT INTO incidents(ts,lga,lat,lon,type,severity,fatalities,source) VALUES(?,?,?,?,?,?,?,?)",
                        (time.time() - i * 3600, "Kwande", g["lat"], g["lon"], "armed_attack", 4, 1, "test"))
    devices = json.load(open(os.path.join(grid.DATA, "keys", "devices.json")))
    with grid.db() as con:
        for dev in devices:
            con.execute("INSERT INTO pings(ts,device,lat,lon,heads) VALUES(?,?,?,?,?)", (time.time(), dev, g["lat"], g["lon"], 300))
    scores = grid.score_all()
    after = max(x["score"] for x in scores if x["lga"] == "Kwande")
    res["kwande_escalation"] = {"before": before, "after": after}
    case("A burst of attacks and herds raises Kwande's top cell", after > before + 20, f"{before} -> {after}")
    with grid.db() as con:
        al = con.execute("SELECT * FROM alerts WHERE lga='Kwande'").fetchall()
    case("Alert dispatched to Kwande contacts", len(al) == 1 and "DPO" in al[0]["recipients"], al[0]["message"] if al else "")
    grid.score_all()
    with grid.db() as con:
        n = con.execute("SELECT COUNT(*) FROM alerts WHERE lga='Kwande'").fetchone()[0]
    case("Cooldown prevents duplicate alerts", n == 1)

    dev, secret = next(iter(devices.items()))
    body = json.dumps({"lat": 7.7, "lon": 8.6, "heads": 50}).encode()
    ts = str(time.time())
    good = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    case("Signed herd ping accepted", grid.verify_ping(dev, ts, body, good))
    case("Ping with altered body rejected", not grid.verify_ping(dev, ts, body.replace(b"50", b"500"), good))
    old = str(time.time() - 900)
    case("Old (replayed) ping rejected", not grid.verify_ping(dev, old, body,
                                                           hmac.new(secret.encode(), f"{old}.".encode() + body, hashlib.sha256).hexdigest()))

    import app
    app.app.secret_key = "t"
    cl = app.app.test_client()
    page = cl.get("/report").data.decode()
    import re
    q = re.search(r"What is (\d) \+ (\d)", page)
    r = cl.post("/report", data={"lga": "Agatu", "type": "threat", "note": "test", "phone": "08031234567",
                                 "answer": str(int(q.group(1)) + int(q.group(2)))})
    with grid.db() as con:
        row = con.execute("SELECT * FROM incidents WHERE source='web' ORDER BY id DESC").fetchone()
    case("Community report stored with phone encrypted, not in plain text",
         r.status_code == 200 and row and "08031234567" not in (row["phone_enc"] or "") and
         grid.fernet().decrypt(row["phone_enc"].encode()).decode() == "08031234567")
    codes = []
    for _ in range(6):
        p2 = cl.get("/report").data.decode()
        q = re.search(r"What is (\d) \+ (\d)", p2)
        codes.append(cl.post("/report", data={"lga": "Agatu", "type": "threat", "answer": str(int(q.group(1)) + int(q.group(2)))}
                             ).status_code)
    case("Report flooding from one address is rate-limited", 429 in codes, codes)
    app.REPORTS.clear()
    p3 = cl.get("/report").data.decode()
    q = re.search(r"What is (\d) \+ (\d)", p3)
    case("Unknown LGA in a report is rejected", cl.post("/report", data={
        "lga": "Nowhere", "type": "threat", "answer": str(int(q.group(1)) + int(q.group(2)))}).status_code == 400)
    rc = app.app.test_client()
    rc.post("/login", data={"u": "responder", "p": "ChangeMe@468"})
    case("Responder cannot verify reports", rc.post("/verify", data={"id": 1, "csrf": "x"}).status_code == 403)
    case("Map data needs sign-in", app.app.test_client().get("/api/grid").status_code == 302)
    case("Staff map loads", rc.get("/").status_code == 200 and rc.get("/api/grid").status_code == 200)

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
