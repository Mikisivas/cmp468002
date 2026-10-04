"""RiversRecover Flask console: live database status, change journal, freeze control and
point-in-time recovery. Roles: dba (recover, unfreeze, amend) and auditor (read only)."""
import os
import secrets
import threading
import time

from flask import Flask, abort, flash, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import cdp

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
BAD = {}
LAYOUT = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>RiversRecover</title>
<style>body{margin:0;font-family:Segoe UI,Arial;background:#ecfeff;color:#083344}.h{background:#155e75;color:#fff;padding:10px 16px}
.h a{color:#a5f3fc;margin-left:12px}.w{max-width:1150px;margin:auto;padding:14px}.k{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px;border:1px solid #a5f3fc}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #cffafe;text-align:left}
.frz{background:#fee2e2;border-color:#ef4444}.r{color:#b91c1c;font-weight:bold}.g{color:#15803d;font-weight:bold}
button{background:#155e75;color:#fff;border:0;padding:6px 10px;border-radius:5px}.f{background:#fef9c3;padding:8px;border-radius:6px;margin-bottom:8px}</style></head>
<body><div class="h"><b>RiversRecover</b> &middot; {{ inst }}{% if session.user %}<a href="/">Database</a><a href="/journal">Change journal</a>
<a href="/recover">Point-in-time recovery</a><a href="/logout">Sign out {{ session.user }}</a>{% endif %}</div><div class="w">
{% for m in get_flashed_messages() %}<div class="f">{{ m }}</div>{% endfor %}{{ body|safe }}</div></body></html>"""


def page(t, **kw):
    return render_template_string(LAYOUT, body=render_template_string(t, csrf=session.get("csrf"), **kw),
                                  inst=cdp.cfg()["institution"]["name"])


def need(dba=False):
    if "user" not in session:
        abort(redirect("/login"))
    if dba and session["role"] != "dba":
        abort(403)
    if request.method == "POST" and request.form.get("csrf") != session["csrf"]:
        abort(403)


@app.after_request
def hdr(r):
    r.headers.update({"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                      "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'"})
    return r


@app.get("/health")
def health():
    return {"status": "ok"}


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        ip = request.remote_addr
        BAD[ip] = [t for t in BAD.get(ip, []) if t > time.time() - 900]
        with cdp.rec() as con:
            u = con.execute("SELECT * FROM staff WHERE name=?", (request.form.get("u", ""),)).fetchone()
        if len(BAD[ip]) >= 5:
            msg = "Locked for 15 minutes."
        elif u and check_password_hash(u["hash"], request.form.get("p", "")):
            session.clear()
            session.update(user=u["name"], role=u["role"], csrf=secrets.token_hex(16))
            return redirect("/")
        else:
            BAD[ip].append(time.time())
            msg = "Wrong details."
    return page("""<div class="k" style="max-width:320px"><p class="r">{{ msg }}</p><form method="post">User<br><input name="u"><br>
    Password<br><input type="password" name="p"><br><br><button>Sign in</button></form></div>""", msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/")
def home():
    need()
    try:
        with cdp.live() as con:
            ctl = con.execute("SELECT * FROM control").fetchone()
            counts = {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in cdp.TABLES}
            approved = con.execute("SELECT COUNT(*) FROM results WHERE approved=1").fetchone()[0]
            per_min = con.execute("SELECT substr(ts,1,16) m, COUNT(*) n FROM journal GROUP BY m ORDER BY m DESC LIMIT 15").fetchall()
        healthy = True
    except Exception as exc:  # noqa: BLE001
        ctl, counts, approved, per_min, healthy = None, {}, 0, [], str(exc)
    with cdp.rec() as con:
        ev = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 15").fetchall()
        seg = con.execute("SELECT * FROM segments ORDER BY id DESC LIMIT 1").fetchone()
        base = con.execute("SELECT * FROM bases ORDER BY id DESC LIMIT 1").fetchone()
    return page("""<div class="k {{ 'frz' if ctl and ctl.frozen }}">{% if healthy != True %}<p class="r">LIVE DATABASE UNREADABLE: {{ healthy }}</p>
    {% elif ctl.frozen %}<p class="r">FROZEN: {{ ctl.reason }}</p>{% else %}<p class="g">Live database writable</p>{% endif %}
    Students {{ counts.students }} &middot; results {{ counts.results }} ({{ approved }} Senate-approved, locked)<br>
    Last shipped journal row: {{ seg.last_ts if seg else '-' }} &middot; last base snapshot: {{ base.at if base else '-' }}
    {% if session.role == 'dba' %}<form method="post" action="/control" style="margin-top:8px"><input type="hidden" name="csrf" value="{{ csrf }}">
    <button name="do" value="base">Base snapshot now</button> <button name="do" value="unfreeze">Unfreeze</button>
    <input name="reason" placeholder="amendment reason"> <button name="do" value="amend">Open 15-min amendment window</button></form>{% endif %}</div>
    <div class="k"><h3>Row changes per minute</h3><svg viewBox="0 0 600 120" style="width:100%">{% for r in per_min|reverse %}
    <rect x="{{ loop.index0*40 }}" y="{{ 110 - [r.n,100]|min }}" width="30" height="{{ [r.n,100]|min }}" fill="#0891b2"><title>{{ r.m }}: {{ r.n }}</title></rect>{% endfor %}</svg></div>
    <div class="k"><h3>Events</h3><table>{% for e in ev %}<tr><td>{{ e.at }}</td><td class="{{ 'r' if e.sev=='critical' }}">{{ e.sev }}</td><td>{{ e.text }}</td></tr>{% endfor %}</table></div>""",
                ctl=ctl, counts=counts, approved=approved, per_min=per_min, healthy=healthy, ev=ev, seg=seg, base=base)


@app.get("/journal")
def journal():
    need()
    with cdp.live() as con:
        rows = con.execute("SELECT * FROM journal ORDER BY seq DESC LIMIT 100").fetchall()
    return page("""<div class="k"><table><tr><th>#</th><th>Time</th><th>Table</th><th>Op</th><th>Key</th><th>Row image</th></tr>
    {% for r in rows %}<tr><td>{{ r.seq }}</td><td>{{ r.ts }}</td><td>{{ r.tbl }}</td><td>{{ r.op }}</td><td>{{ r.pk }}</td><td><small>{{ r.row }}</small></td></tr>{% endfor %}</table></div>""", rows=rows)


@app.route("/recover", methods=["GET", "POST"])
def recover():
    need(dba=request.method == "POST")
    if request.method == "POST":
        t = request.form["when"].replace("T", " ")
        if len(t) == 16:
            t += ":00"
        flash(str(cdp.pitr(t)))
        return redirect("/")
    with cdp.rec() as con:
        bases = con.execute("SELECT * FROM bases ORDER BY id DESC").fetchall()
        recs = con.execute("SELECT * FROM recoveries ORDER BY rowid DESC LIMIT 10").fetchall()
    return page("""<div class="k"><p>Pick any moment after the oldest base snapshot. The database is rebuilt from the newest base before
    that moment plus every journal row up to it.</p>{% if session.role == 'dba' %}<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
    <input type="datetime-local" step="1" name="when" required> <button>Recover to this moment</button></form>{% endif %}</div>
    <div class="k"><h3>Base snapshots</h3><table>{% for b in bases %}<tr><td>{{ b.at }}</td><td>up to journal row {{ b.upto_seq }}</td><td>{{ b.bytes//1024 }} KiB</td></tr>{% endfor %}</table></div>
    <div class="k"><h3>Past recoveries</h3><table>{% for r in recs %}<tr><td>{{ r.at }}</td><td>to {{ r.target_time }}</td><td>{{ r.replayed }} rows replayed</td><td>{{ '%.2f'|format(r.seconds) }} s</td></tr>{% endfor %}</table></div>""",
                bases=bases, recs=recs)


@app.post("/control")
def control():
    need(dba=True)
    do = request.form.get("do")
    if do == "base":
        flash(str(cdp.base_snapshot()))
    elif do == "unfreeze":
        cdp.unfreeze(session["user"])
    elif do == "amend":
        flash("Amendment window open until " + cdp.open_amendment(15, session["user"], request.form.get("reason", "")[:200]))
    return redirect("/")


def add_staff(name, pw, role):
    with cdp.rec() as con:
        con.execute("INSERT OR REPLACE INTO staff VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def shipper():
    c = cdp.cfg()
    last_base = time.time()
    while True:
        try:
            cdp.ship()
            cdp.probe()
            if time.time() - last_base > c["base_minutes"] * 60:
                cdp.base_snapshot()
                last_base = time.time()
        except Exception as exc:  # noqa: BLE001
            cdp.event("warning", f"shipper: {exc}")
        time.sleep(c["ship_seconds"])


def serve():
    app.secret_key = os.environ.get("RIVERSRECOVER_SECRET") or secrets.token_hex(32)
    threading.Thread(target=shipper, daemon=True).start()
    app.run(host="127.0.0.1", port=cdp.cfg()["port"])
