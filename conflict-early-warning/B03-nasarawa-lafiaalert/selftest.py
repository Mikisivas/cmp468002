"""LafiaAlert end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import time

import geo
import main as cli
import nlp
import pipeline as pl

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    s = cli.setup()
    ev = json.load(open(os.path.join(pl.DATA, "model_eval.json")))
    res["model"] = {"accuracy": ev["accuracy"], "per_class": ev["per_class"], "test_size": ev["test_size"]}
    case("Naive Bayes accuracy on held-out messages is at least 0.90", ev["accuracy"] >= 0.90, ev["accuracy"])
    probes = {"an kai hari a giza yanzu da bindigogi": "armed_attack", "cow don chop my maize for shabu": "crop_destruction",
              "barayi sun sace shanu 20 a azara": "cattle_rustling", "please send me recharge card": "noise",
              "an toshe hanyar shanu a doma": "blocked_route"}
    got = {t: pl.model().predict(t)[0] for t in probes}
    res["language_probes"] = got
    case("Correct class for Hausa, Pidgin and English probes", got == probes, got)
    case("Gazetteer finds the LGA from a village name", nlp.geocode("attack at umaisha market") == ("Toto", "umaisha"))
    case("Urgency detector (Hausa 'yanzu' and 'bindigogi')", nlp.urgent("an kai hari yanzu da bindigogi") and
         not nlp.urgent("cattle ate my maize last week"))
    case("Poisson tail P(X>=3 | 0.1) is tiny and P(X>=0) = 1",
         pl.poisson_tail(3, 0.1) < 0.001 and pl.poisson_tail(0, 0.1) == 1.0, pl.poisson_tail(3, 0.1))

    body = json.dumps({"from": "08030000000", "text": "test"}).encode()
    ts = str(time.time())
    case("Signed gateway webhook accepted", pl.check_gateway(ts, body, pl.gateway_signature(ts, body)))
    case("Forged webhook (wrong signature) refused", not pl.check_gateway(ts, body, "0" * 64))
    old = str(time.time() - 600)
    case("Replayed webhook (old timestamp) refused", not pl.check_gateway(old, body, pl.gateway_signature(old, body)))

    t0 = time.time()
    results = [pl.ingest(p, t) for p, t in cli.DEMO]
    res["pipeline_ms_per_message"] = round((time.time() - t0) * 1000 / len(cli.DEMO), 2)
    res["demo_feed"] = results
    case("Irrelevant SMS marked noise and not turned into an event", results[1]["status"] == "noise" and not results[1]["event"])
    case("Two senders about Giza merge into one corroborated event",
         results[2]["event"] == results[3]["event"] and results[3]["event"] is not None)
    with pl.db() as con:
        e = con.execute("SELECT * FROM events WHERE id=?", (results[2]["event"],)).fetchone()
        rep = con.execute("SELECT status FROM messages WHERE id=?", (results[5]["id"],)).fetchone()["status"]
    case("Same sender repeating does not count as corroboration", rep == "repeat" and e["senders"] == 2 and e["reports"] == 3,
         f"senders {e['senders']}, reports {e['reports']}")
    with pl.db() as con:
        al = [dict(r) for r in con.execute("SELECT * FROM alerts")]
    res["alerts"] = [a["text"] for a in al]
    case("Urgent alert sent first as UNCONFIRMED, then CORROBORATED", any("UNCONFIRMED" in a["text"] for a in al)
         and any("CORROBORATED" in a["text"] for a in al))
    case("Spike test flags Keana (several attack events in one day)", any(a["kind"] == "spike" and a["lga"] == "Keana" for a in al),
         [a["text"] for a in al if a["kind"] == "spike"])
    with pl.db() as con:
        enc = con.execute("SELECT sender_enc FROM messages LIMIT 1").fetchone()["sender_enc"]
        raw = open(os.path.join(pl.DATA, "lafiaalert.db"), "rb").read()
    case("Phone numbers never stored in plain text", b"08031110001" not in raw and enc.startswith("gAAAA"))

    import app
    app.app.secret_key = "t"
    cl = app.app.test_client()
    cl.post("/login", data={"u": "viewer", "p": "ChangeMe@468"})
    case("Viewer cannot inject test SMS", cl.post("/test-sms", data={"text": "x"}).status_code == 403)
    case("Webhook without signature refused over HTTP", app.app.test_client().post("/sms/inbound", data=body).status_code == 401)

    res.update(setup=s, tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
