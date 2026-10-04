"""LafiaAlert Flask app: SMS gateway webhook plus the situation-room dashboard."""
import json
import os
import secrets
import time

from flask import Flask, abort, jsonify, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import geo
import nlp
import pipeline as pl

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=16 * 1024)
FAILS = {}
FRAME = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>LafiaAlert</title>
<meta http-equiv="refresh" content="{{ refresh }}"><style>body{margin:0;font-family:Verdana,Arial;background:#f0fdf4;color:#052e16}
.t{background:#166534;color:#fff;padding:10px 16px}.t a{color:#bbf7d0;margin-left:12px}.w{max-width:1250px;margin:auto;padding:12px}
.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px;border:1px solid #bbf7d0}table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:4px;border-bottom:1px solid #dcfce7;text-align:left}.u{color:#b91c1c;font-weight:bold}.mut{color:#64748b}
button{background:#166534;color:#fff;border:0;border-radius:5px;padding:6px 10px}input,textarea{width:100%;max-width:520px;padding:5px}</style></head>
<body><div class="t"><b>LafiaAlert</b> &middot; Nasarawa State SMS early warning{% if session.user %}<a href="/">Inbox</a><a href="/events">Events</a>
<a href="/alerts">Alerts</a><a href="/model">Model</a><a href="/test-sms">Test SMS</a><a href="/logout">Sign out {{ session.user }}</a>{% endif %}</div>
<div class="w">{{ body|safe }}</div></body></html>"""


def show(t, refresh=3600, **kw):
    return render_template_string(FRAME, body=render_template_string(t, csrf=session.get("csrf"), **kw), refresh=refresh)


def need(*roles):
    if "user" not in session:
        abort(redirect("/login"))
    if roles and session["role"] not in roles:
        abort(403)
    if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
        abort(403)


@app.after_request
def hdr(r):
    r.headers.update({"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                      "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'"})
    return r


@app.post("/sms/inbound")
def inbound():
    body = request.get_data()
    if not pl.check_gateway(request.headers.get("X-Gateway-Timestamp", "0"), body, request.headers.get("X-Gateway-Signature")):
        abort(401)
    d = json.loads(body)
    return jsonify(pl.ingest(str(d["from"])[:20], str(d["text"])))


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        ip = request.remote_addr
        FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
        with pl.db() as con:
            u = con.execute("SELECT * FROM staff WHERE name=?", (request.form.get("u", ""),)).fetchone()
        if len(FAILS[ip]) < 5 and u and check_password_hash(u["hash"], request.form.get("p", "")):
            session.clear()
            session.update(user=u["name"], role=u["role"], csrf=secrets.token_hex(16))
            return redirect("/")
        FAILS[ip].append(time.time())
        msg = "Sign-in failed."
    return show("""<div class="c" style="max-width:320px"><p class="u">{{ msg }}</p><form method="post">User<input name="u">
    Password<input type="password" name="p"><br><br><button>Sign in</button></form></div>""", msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


def fmt(t):
    return time.strftime("%d %b %H:%M", time.localtime(t))


@app.get("/")
def inbox():
    need()
    with pl.db() as con:
        rows = con.execute("SELECT * FROM messages ORDER BY ts DESC LIMIT 60").fetchall()
    return show("""<div class="c"><table><tr><th>Time</th><th>Sender (pseudonym)</th><th>Message</th><th>Class</th><th>Conf.</th>
    <th>LGA</th><th>Status</th></tr>{% for m in rows %}<tr class="{{ 'mut' if m.status=='noise' }}"><td>{{ fmt(m.ts) }}</td><td>{{ m.sender }}</td>
    <td>{{ m.text }}</td><td class="{{ 'u' if m.urgent }}">{{ m.label }}{{ ' URGENT' if m.urgent }}</td><td>{{ m.confidence }}</td>
    <td>{{ m.lga or '?' }}</td><td>{{ m.status }}{% if m.merged_into %} (event {{ m.merged_into }}){% endif %}</td></tr>{% endfor %}</table></div>""",
                refresh=10, rows=rows, fmt=fmt)


@app.get("/events")
def events():
    need()
    with pl.db() as con:
        rows = con.execute("SELECT * FROM events ORDER BY last_ts DESC LIMIT 60").fetchall()
    return show("""<div class="c"><table><tr><th>#</th><th>First</th><th>Last</th><th>LGA</th><th>Place</th><th>Type</th><th>Reports</th>
    <th>Different senders</th><th>Verified</th></tr>{% for e in rows %}<tr><td>{{ e.id }}</td><td>{{ fmt(e.first_ts) }}</td><td>{{ fmt(e.last_ts) }}</td>
    <td>{{ e.lga }}</td><td>{{ e.place }}</td><td class="{{ 'u' if e.urgent }}">{{ e.label }}</td><td>{{ e.reports }}</td><td>{{ e.senders }}</td>
    <td>{% if e.verified %}yes{% elif session.role=='supervisor' %}<form method="post" action="/verify"><input type="hidden" name="csrf" value="{{ csrf }}">
    <input type="hidden" name="id" value="{{ e.id }}"><button>Verify</button></form>{% else %}no{% endif %}</td></tr>{% endfor %}</table></div>""",
                refresh=15, rows=rows, fmt=fmt)


@app.get("/alerts")
def alerts():
    need()
    with pl.db() as con:
        rows = con.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 40").fetchall()
    stats = [pl.spike(g["name"]) for g in geo.lgas()]
    return show("""<div class="c"><h3>Alerts</h3><table>{% for a in rows %}<tr><td>{{ fmt(a.ts) }}</td><td class="u">{{ a.kind }}</td>
    <td>{{ a.text }}</td></tr>{% endfor %}</table></div><div class="c"><h3>Today's Poisson spike test per LGA</h3><table><tr><th>LGA</th>
    <th>Events today</th><th>Normal per day</th><th>p-value</th></tr>{% for s in stats %}<tr><td>{{ s.lga }}</td><td>{{ s.today }}</td>
    <td>{{ s.lambda }}</td><td class="{{ 'u' if s.p < 0.01 }}">{{ '%.4f'|format(s.p) }}</td></tr>{% endfor %}</table></div>""",
                refresh=20, rows=rows, stats=stats, fmt=fmt)


@app.get("/model")
def model_page():
    need()
    ev = json.load(open(os.path.join(pl.DATA, "model_eval.json")))
    return show("""<div class="c"><h3>Naive Bayes classifier (from scratch)</h3><p>Accuracy on {{ ev.test_size }} held-out messages:
    <b>{{ ev.accuracy }}</b></p><table><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th></tr>{% for c, v in ev.per_class.items() %}
    <tr><td>{{ c }}</td><td>{{ v.precision }}</td><td>{{ v.recall }}</td><td>{{ v.f1 }}</td></tr>{% endfor %}</table></div>""", ev=ev)


@app.route("/test-sms", methods=["GET", "POST"])
def test_sms():
    need("supervisor", "operator")
    out = None
    if request.method == "POST":
        out = pl.ingest(request.form.get("from", "08000000000"), request.form.get("text", ""))
    return show("""<div class="c"><h3>Send a test SMS through the pipeline</h3><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
    From<input name="from" value="08031110000">Message<textarea name="text">an kai hari a giza yanzu da bindigogi</textarea><br>
    <button>Process</button></form>{% if out %}<pre>{{ out }}</pre>{% endif %}</div>""", out=out)


@app.post("/verify")
def verify():
    need("supervisor")
    with pl.db() as con:
        con.execute("UPDATE events SET verified=1 WHERE id=?", (int(request.form["id"]),))
    return redirect("/events")


def add_staff(name, pw, role):
    with pl.db() as con:
        con.execute("INSERT OR REPLACE INTO staff VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def serve():
    app.secret_key = os.environ.get("LAFIAALERT_SECRET") or secrets.token_hex(32)
    app.run(host="127.0.0.1", port=geo.cfg()["port"])
