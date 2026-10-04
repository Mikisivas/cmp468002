"""KanoShield Flask console: password + TOTP sign-in, WORM backups, four-eyes approvals."""
import os
import secrets
import threading
import time

from flask import Flask, abort, flash, redirect, render_template_string, request, session

import demo
import shield as s

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", PERMANENT_SESSION_LIFETIME=900)
FRAME = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>KanoShield</title><style>
body{margin:0;font-family:"Trebuchet MS",Arial;background:#f7fee7;color:#1a2e05}nav{background:#365314;color:#fff;padding:10px 16px}
nav a{color:#d9f99d;margin-left:12px}.w{max-width:1100px;margin:auto;padding:14px}.box{background:#fff;border:1px solid #d9f99d;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:5px;border-bottom:1px solid #ecfccb;text-align:left}
.crit{color:#b91c1c;font-weight:bold}.ok{color:#15803d;font-weight:bold}button{background:#365314;color:#fff;border:0;border-radius:4px;padding:5px 10px}
.flash{background:#fef9c3;padding:8px;border-radius:5px;margin-bottom:10px}
</style></head><body><nav><b>KanoShield</b> &middot; {{ inst }}{% if session.user %}<a href="/">Overview</a><a href="/backups">WORM vault</a>
<a href="/approvals">Approvals ({{ pending }})</a><a href="/logout">Sign out {{ session.user }} ({{ session.role }})</a>{% endif %}</nav>
<div class="w">{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}{{ body|safe }}</div></body></html>"""


def page(tpl, **kw):
    with s.ops() as con:
        pending = con.execute("SELECT COUNT(*) n FROM requests WHERE status='pending'").fetchone()["n"]
    return render_template_string(FRAME, body=render_template_string(tpl, csrf=session.get("csrf"), **kw),
                                  inst=s.cfg()["institution"]["name"], pending=pending)


def need(admin=False):
    if "user" not in session:
        abort(redirect("/login"))
    if admin and session["role"] != "admin":
        abort(403)
    if request.method == "POST" and request.form.get("csrf") != session["csrf"]:
        abort(403)


@app.after_request
def hdr(r):
    r.headers.update({"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
                      "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'"})
    return r


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        role = s.authenticate(request.form.get("u", ""), request.form.get("p", ""), request.form.get("code", ""),
                              request.remote_addr)
        if role:
            session.clear()
            session.update(user=request.form["u"], role=role, csrf=secrets.token_hex(16))
            session.permanent = True
            return redirect("/")
        msg = "Sign-in failed (password, authenticator code, or too many attempts)."
    return page("""<div class="box" style="max-width:340px"><h3>Sign in</h3><p class="crit">{{ msg }}</p><form method="post">
    User<br><input name="u"><br>Password<br><input type="password" name="p"><br>Authenticator code (admins)<br>
    <input name="code" inputmode="numeric" maxlength="6"><br><br><button>Sign in</button></form></div>""", msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/")
def overview():
    need()
    with s.ops() as con:
        host = con.execute("SELECT * FROM host ORDER BY rowid DESC LIMIT 1").fetchone()
        st = con.execute("SELECT * FROM status").fetchall()
        al = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 15").fetchall()
    return page("""<div class="box">{% if host %}CPU {{ host.cpu }}% &middot; RAM {{ host.mem }}% &middot; Disk {{ host.disk }}%{% endif %}
    &nbsp; {% for x in st %}{{ x.name }} <span class="{{ 'ok' if x.up else 'crit' }}">{{ 'UP' if x.up else 'DOWN' }}</span> {% endfor %}</div>
    {% if session.role == 'admin' %}<div class="box"><form method="post" action="/backup"><input type="hidden" name="csrf" value="{{ csrf }}">
    <button>Seal a backup now</button></form></div>{% endif %}
    <div class="box"><h3>Alerts</h3><table>{% for a in al %}<tr><td>{{ a.at }}</td><td class="{{ 'crit' if a.sev=='critical' else '' }}">{{ a.sev }}</td>
    <td>{{ a.text }}</td></tr>{% endfor %}</table></div>""", host=host, st=st, al=al)


@app.get("/backups")
def backups():
    need()
    with s.vault() as v:
        rows = v.execute("SELECT id,at,files,bytes,retain_until,released FROM backups ORDER BY id DESC").fetchall()
    return page("""<div class="box"><p>Backups are write-once. Database triggers refuse any edit, and refuse deletion until the
    retention date unless two admins approved an early release.</p><table><tr><th>#</th><th>Sealed</th><th>Files</th><th>Size</th>
    <th>Locked until</th><th></th></tr>{% for b in rows %}<tr><td>{{ b.id }}</td><td>{{ b.at }}</td><td>{{ b.files }}</td><td>{{ b.bytes//1024 }} KiB</td>
    <td>{{ 'RELEASED' if b.released else b.retain_until }}</td><td>{% if session.role=='admin' %}
    <form method="post" action="/request" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="id" value="{{ b.id }}">
    <input name="reason" placeholder="reason" required> <button name="kind" value="restore">Request restore</button>
    <button name="kind" value="release">Request early release</button></form>{% endif %}</td></tr>{% endfor %}</table></div>""", rows=rows)


@app.get("/approvals")
def approvals():
    need()
    with s.ops() as con:
        rows = con.execute("SELECT * FROM requests ORDER BY id DESC LIMIT 40").fetchall()
    return page("""<div class="box"><table><tr><th>#</th><th>When</th><th>Action</th><th>Backup</th><th>Requested by</th><th>Reason</th><th>Status</th><th></th></tr>
    {% for r in rows %}<tr><td>{{ r.id }}</td><td>{{ r.at }}</td><td>{{ r.kind }}</td><td>{{ r.backup_id }}</td><td>{{ r.requested_by }}</td><td>{{ r.reason }}</td>
    <td>{{ r.status }}{% if r.decided_by %} by {{ r.decided_by }}{% endif %}</td><td>{% if r.status=='pending' and session.role=='admin' and r.requested_by != session.user %}
    <form method="post" action="/decide" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="id" value="{{ r.id }}">
    <button name="ok" value="1">Approve</button> <button name="ok" value="0">Reject</button></form>{% endif %}</td></tr>{% endfor %}</table></div>""", rows=rows)


@app.post("/backup")
def do_backup():
    need(admin=True)
    flash(str(s.backup(session["user"])))
    return redirect("/")


@app.post("/request")
def do_request():
    need(admin=True)
    rid = s.request_action(request.form["kind"], int(request.form["id"]), session["user"], request.form["reason"][:200])
    flash(f"Request {rid} recorded. A different admin must approve it.")
    return redirect("/approvals")


@app.post("/decide")
def do_decide():
    need(admin=True)
    flash(str(s.decide(int(request.form["id"]), session["user"], request.form.get("ok") == "1")))
    return redirect("/approvals")


def loop():
    c = s.cfg()
    last = time.time()
    while True:
        try:
            s.watch()
            with s.ops() as con:
                if con.execute("SELECT 1 FROM status WHERE up=0").fetchone():
                    demo.portal(c["portal_port"], background=True)
            if time.time() - last > c["backup_minutes"] * 60:
                if s.backup().get("status") == "ok":
                    s.replicate()
                last = time.time()
        except Exception as exc:  # noqa: BLE001
            s.alert("warning", f"scheduler: {exc}")
        time.sleep(c["watch_seconds"])


def serve():
    app.secret_key = os.environ.get("KANOSHIELD_SECRET") or secrets.token_hex(32)
    threading.Thread(target=loop, daemon=True).start()
    app.run(host="127.0.0.1", port=s.cfg()["port"])
