"""LafiaAlert message pipeline: verify gateway signature -> classify -> geocode -> de-duplicate
and corroborate -> store -> Poisson spike test per LGA -> alert.

Poisson spike test: for each LGA, the mean daily count over the last 60 days is lambda.
If P(X >= today's count | lambda) is below 0.01, today is a statistically unusual spike.
"""
import datetime as dt
import hashlib
import hmac
import math
import os
import sqlite3
import time

from cryptography.fernet import Fernet

import geo
import nlp

DATA = os.path.join(geo.BASE, "data")
MODEL = os.path.join(DATA, "nb_model.json")
SEVERITY = {"crop_destruction": 2, "cattle_rustling": 3, "armed_attack": 4, "threat": 2, "blocked_route": 2}
_model = None


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "lafiaalert.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, ts REAL, sender TEXT, sender_enc TEXT, text TEXT,
        label TEXT, confidence REAL, urgent INT, lga TEXT, place TEXT, status TEXT, merged_into INT);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, first_ts REAL, last_ts REAL, lga TEXT, place TEXT, label TEXT,
        severity INT, urgent INT, reports INT, senders INT, verified INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS history(ts REAL, lga TEXT, type TEXT, severity INT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, lga TEXT, kind TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, ts REAL, to_enc TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS staff(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    """)
    return con


def keys():
    d = os.path.join(DATA, "keys")
    return Fernet(open(os.path.join(d, "phone.key"), "rb").read()), open(os.path.join(d, "pepper.bin"), "rb").read()


def init():
    d = os.path.join(DATA, "keys")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "phone.key"), "wb").write(Fernet.generate_key())
    open(os.path.join(d, "pepper.bin"), "wb").write(os.urandom(32))
    open(os.path.join(d, "gateway.secret"), "w").write(os.urandom(24).hex())


def gateway_secret():
    return os.environ.get(geo.cfg()["gateway_secret_env"]) or open(os.path.join(DATA, "keys", "gateway.secret")).read()


def gateway_signature(ts, body):
    return hmac.new(gateway_secret().encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()


def check_gateway(ts, body, sig):
    """Only the SMS gateway (Termii, Africa's Talking, etc.) knows the secret, so forged webhook
    calls are refused. Timestamps older than 5 minutes are refused to stop replays."""
    try:
        fresh = abs(time.time() - float(ts)) < 300
    except ValueError:
        return False
    return fresh and hmac.compare_digest(gateway_signature(ts, body), sig or "")


def model():
    global _model
    if _model is None:
        _model = nlp.NaiveBayes.load(MODEL)
    return _model


def ingest(phone, text, ts=None):
    ts = ts or time.time()
    text = text.strip()[:480]
    f, pepper = keys()
    sender = hmac.new(pepper, phone.strip().encode(), hashlib.sha256).hexdigest()[:12]
    label, conf = model().predict(text)
    lga_name, place = nlp.geocode(text)
    is_urgent = nlp.urgent(text)
    status = "noise" if label == "noise" else ("needs location" if not lga_name else "new")
    if label != "noise" and conf < 0.6:
        status = "needs review"
    with db() as con:
        cur = con.execute("INSERT INTO messages(ts,sender,sender_enc,text,label,confidence,urgent,lga,place,status) "
                          "VALUES(?,?,?,?,?,?,?,?,?,?)", (ts, sender, f.encrypt(phone.encode()).decode(), text, label,
                                                         round(conf, 3), int(is_urgent), lga_name, place, status))
        mid = cur.lastrowid
    reply = ("LafiaAlert: thank you, your report is received. If life is in danger call 112."
             if label != "noise" else "LafiaAlert: this line is for conflict reports only.")
    with db() as con:
        con.execute("INSERT INTO outbox(ts,to_enc,text) VALUES(?,?,?)", (ts, f.encrypt(phone.encode()).decode(), reply))
    event_id = None
    if status == "new":
        event_id = merge(mid, ts, sender, lga_name, place, label, is_urgent)
        spike(lga_name, ts)
    return {"id": mid, "label": label, "confidence": round(conf, 3), "lga": lga_name, "urgent": is_urgent,
            "status": status, "event": event_id}


def merge(mid, ts, sender, lga_name, place, label, is_urgent):
    """Reports of the same type from the same village within 6 hours are one event. Several
    different senders corroborate it; the same sender repeating does not."""
    with db() as con:
        ev = con.execute("SELECT * FROM events WHERE lga=? AND place=? AND label=? AND last_ts > ? ORDER BY id DESC LIMIT 1",
                         (lga_name, place, label, ts - 6 * 3600)).fetchone()
        if ev:
            senders = {r["sender"] for r in con.execute("SELECT sender FROM messages WHERE merged_into=?", (ev["id"],))}
            new_sender = sender not in senders
            con.execute("UPDATE events SET last_ts=?, reports=reports+1, senders=senders+?, urgent=max(urgent,?) WHERE id=?",
                        (ts, int(new_sender), int(is_urgent), ev["id"]))
            con.execute("UPDATE messages SET merged_into=?, status=? WHERE id=?",
                        (ev["id"], "corroborates" if new_sender else "repeat", mid))
            eid = ev["id"]
            n_senders = ev["senders"] + int(new_sender)
        else:
            cur = con.execute("INSERT INTO events(first_ts,last_ts,lga,place,label,severity,urgent,reports,senders) "
                              "VALUES(?,?,?,?,?,?,?,1,1)", (ts, ts, lga_name, place, label, SEVERITY[label], int(is_urgent)))
            eid = cur.lastrowid
            con.execute("UPDATE messages SET merged_into=? WHERE id=?", (eid, mid))
            n_senders = 1
    if is_urgent and SEVERITY[label] >= 4 and n_senders in (1, 2):
        word = "UNCONFIRMED" if n_senders == 1 else "CORROBORATED by a second person"
        alert(lga_name, "urgent", f"{word}: {label.replace('_', ' ')} reported at {place}, {lga_name} (event {eid}). "
                                  f"Police DPO and peace committee notified.")
    return eid


def poisson_tail(k, lam):
    """P(X >= k) for X ~ Poisson(lam)."""
    if k <= 0:
        return 1.0
    term, cdf = math.exp(-lam), 0.0
    for i in range(k):
        cdf += term
        term *= lam / (i + 1)
    return max(0.0, 1.0 - cdf)


def spike(lga_name, ts=None):
    ts = ts or time.time()
    c = geo.cfg()
    day_start = dt.datetime.fromtimestamp(ts).replace(hour=0, minute=0, second=0).timestamp()
    with db() as con:
        past = con.execute("SELECT COUNT(*) FROM history WHERE lga=? AND ts BETWEEN ? AND ?",
                           (lga_name, day_start - c["baseline_days"] * 86400, day_start)).fetchone()[0]
        past += con.execute("SELECT COUNT(*) FROM events WHERE lga=? AND first_ts BETWEEN ? AND ?",
                            (lga_name, day_start - c["baseline_days"] * 86400, day_start)).fetchone()[0]
        today = con.execute("SELECT COUNT(*) FROM events WHERE lga=? AND first_ts >= ?", (lga_name, day_start)).fetchone()[0]
    lam = max(past / c["baseline_days"], 0.02)
    p = poisson_tail(today, lam)
    if p < c["anomaly_p"]:
        with db() as con:
            done = con.execute("SELECT 1 FROM alerts WHERE lga=? AND kind='spike' AND ts>=?", (lga_name, day_start)).fetchone()
        if not done:
            alert(lga_name, "spike", f"SPIKE in {lga_name}: {today} incident events today against a normal "
                                     f"{lam:.2f} per day (Poisson p = {p:.4f}). Escalate to State Security Council.")
    return {"lga": lga_name, "today": today, "lambda": round(lam, 3), "p": p}


def alert(lga_name, kind, text):
    with db() as con:
        con.execute("INSERT INTO alerts(ts,lga,kind,text) VALUES(?,?,?,?)", (time.time(), lga_name, kind, text))
    print(f"[ALERT] {text}")
