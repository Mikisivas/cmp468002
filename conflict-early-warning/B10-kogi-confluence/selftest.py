"""ConfluenceEWS end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import time

import geo
import hub
import main as cli
import model
from field import Tablet

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    t0 = time.time()
    s = cli.setup()
    res["setup_seconds"] = round(time.time() - t0, 1)
    ev = s["model"]
    res["model"] = ev
    case("AUC of a perfect ranking is 1 and of a reversed ranking is 0",
         model.auc([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1]) == 1 and model.auc([0.9, 0.8, 0.2, 0.1], [0, 0, 1, 1]) == 0)
    case("Model beats chance on the most recent 90 days (AUC > 0.6)", ev["auc_model"] > 0.6, ev["auc_model"])
    case("Model at least matches the naive last-30-days rule", ev["auc_model"] >= ev["auc_naive_last30"] - 0.02,
         f"{ev['auc_model']} vs {ev['auc_naive_last30']}")
    case("Probabilities are better calibrated than an always-average forecast (Brier)",
         ev["brier_model"] <= ev["brier_climatology"], f"{ev['brier_model']} vs {ev['brier_climatology']}")

    t1 = Tablet("KG-TAB-01")
    u = t1.add("Omala", "armed_attack", 4, "attack near Abejukolo")
    t1.add("Omala", "cattle_killing", 3, "reprisal")
    case("Tablet works with no network (reports queued locally)", len(t1.pending()) == 2)
    r_off = t1.sync(url="http://127.0.0.1:9")
    case("Sync with no connection fails safely and keeps the queue", r_off.get("offline") and len(t1.pending()) == 2, r_off)
    r1 = t1.sync(transport=hub.sync, drop_reply=True)
    case("Network drops after the hub stored the data (reply lost)", r1.get("lost_reply") and len(t1.pending()) == 2)
    r2 = t1.sync(transport=hub.sync)
    res["retry_after_lost_reply"] = r2
    case("Retry is idempotent: 0 new, 2 recognised duplicates, queue cleared", r2["new"] == 0 and r2["duplicates"] == 2 and r2["pending"] == 0,
         r2)
    with hub.db() as con:
        n = con.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    case("Hub holds exactly 2 reports (no duplicates)", n == 2, n)

    t1.edit(u, severity=5, note="2 killed (updated offline)")
    r3 = t1.sync(transport=hub.sync)
    with hub.db() as con:
        sev = con.execute("SELECT severity, version FROM reports WHERE uuid=?", (u,)).fetchone()
    case("Offline edit with a higher version replaces the old copy", r3["updated"] == 1 and sev["severity"] == 5, dict(sev))
    stale = json.dumps({"device": "KG-TAB-01", "counter": 999, "reports": [{"uuid": u, "created": 1, "edited": 2, "version": 1,
                                                                          "lga": "Omala", "type": "threat", "severity": 1}]}, sort_keys=True).encode()
    code, rep = hub.sync(stale, hub.sign(t1.meta("key"), stale))
    with hub.db() as con:
        sev2 = con.execute("SELECT severity FROM reports WHERE uuid=?", (u,)).fetchone()["severity"]
    case("Older version arriving late does not overwrite newer data", code == 200 and sev2 == 5 and rep["duplicates"] == 1)

    body = t1.build()
    sig = hub.sign(t1.meta("key"), body)
    hub.sync(body, sig)
    code, rep = hub.sync(body, sig)
    case("Captured request replayed later is refused (counter)", code == 409, rep)
    t2 = Tablet("KG-TAB-02")
    forged = json.dumps({"device": "KG-TAB-02", "counter": 5000, "reports": []}).encode()
    code, rep = hub.sync(forged, hub.sign(t1.meta("key"), forged))
    case("Request signed with another tablet's key is refused", code == 401, rep)
    code, rep = hub.sync(b"not json", "x")
    case("Malformed body refused", code == 400)

    before = hub.score()["Bassa"]
    for i in range(4):
        t2.add("Bassa", ["armed_attack", "killing", "cattle_killing", "armed_attack"][i], 4, f"incident {i}")
    r4 = t2.sync(transport=hub.sync)
    after = r4 and json.loads(t2.meta("risk"))["Bassa"]["prob"]
    res["bassa_risk"] = {"before": before, "after": after}
    case("New violent reports raise Bassa's 14-day probability", after > before, f"{before} -> {after}")
    case("Tablet received the risk table for offline use", len(json.loads(t2.meta("risk"))) == len(geo.lgas()))

    import server
    import http.client
    import threading
    srv = server.socketserver.ThreadingTCPServer(("127.0.0.1", 0), server.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
    c.request("GET", "/devices")
    page = c.getresponse().read().decode()
    case("Staff pages need sign-in", "Sign in" in page and "KG-TAB" not in page)
    srv.shutdown()

    res.update(setup={k: v for k, v in s.items() if k != "model"}, tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
