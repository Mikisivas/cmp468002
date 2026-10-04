"""LafiaAlert command line. `python main.py -h` for help."""
import argparse
import json
import os
import random
import shutil
import time
import urllib.request

import geo
import nlp
import pipeline as pl


def reset():
    shutil.rmtree(pl.DATA, ignore_errors=True)


def setup():
    reset()
    pl.db().close()
    pl.init()
    ev = nlp.train(pl.MODEL)
    json.dump(ev, open(os.path.join(pl.DATA, "model_eval.json"), "w"), indent=1)
    import app
    pw = os.environ.get("LAFIAALERT_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_staff("supervisor", pw, "supervisor")
    app.add_staff("operator", pw, "operator")
    app.add_staff("viewer", pw, "viewer")
    hist = geo.history(days=120, seed=31)
    with pl.db() as con:
        con.executemany("INSERT INTO history VALUES(?,?,?,?)", [(h["ts"], h["lga"], h["type"], h["severity"]) for h in hist])
    return {"model_accuracy": ev["accuracy"], "history_incidents": len(hist)}


def send(phone, text, url=None):
    """Post one SMS to the running server exactly as the gateway would (signed webhook)."""
    url = url or f"http://127.0.0.1:{geo.cfg()['port']}"
    body = json.dumps({"from": phone, "text": text}).encode()
    ts = str(time.time())
    req = urllib.request.Request(url + "/sms/inbound", data=body, method="POST", headers={
        "Content-Type": "application/json", "X-Gateway-Timestamp": ts, "X-Gateway-Signature": pl.gateway_signature(ts, body)})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())


DEMO = [("08031110001", "cow don chop all my yam for agyaragu farm"),
        ("08031110002", "Good morning sir please send recharge card"),
        ("08031110003", "an kai hari a giza yanzu da bindigogi"),
        ("08031110004", "gunmen attacked giza now people are running"),
        ("08031110005", "attack ongoing at kadarko houses burning please help"),
        ("08031110003", "an kai hari a giza yanzu da bindigogi"),
        ("08031110006", "maharan sun kona gidaje a amudu an kashe mutane"),
        ("08031110007", "barayi sun sace shanu 14 a tunga"),
        ("08031110008", "farmers blocked the cattle route near rukubi"),
        ("08031110009", "people dey talk say dem go attack umaisha soon")]


def main():
    ap = argparse.ArgumentParser(description="LafiaAlert: SMS early warning with Naive Bayes (Nasarawa State)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "train", "demo-feed", "spikes", "reset"):
        sub.add_parser(n)
    c = sub.add_parser("classify")
    c.add_argument("text")
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Logins: supervisor, operator, viewer / ChangeMe@468")
    elif a.cmd == "serve":
        import app
        app.serve()
    elif a.cmd == "train":
        out = nlp.train(pl.MODEL)
    elif a.cmd == "classify":
        lab, conf = pl.model().predict(a.text)
        out = {"label": lab, "confidence": round(conf, 3), "urgent": nlp.urgent(a.text), "place": nlp.geocode(a.text)}
    elif a.cmd == "demo-feed":
        for phone, text in DEMO:
            print(send(phone, text))
            time.sleep(1.5)
    elif a.cmd == "spikes":
        out = [pl.spike(g["name"]) for g in geo.lgas()]
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
