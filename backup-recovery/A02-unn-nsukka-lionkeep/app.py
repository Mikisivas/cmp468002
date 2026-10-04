"""LionKeep Flask dashboard with a background scheduler.

Security: werkzeug scrypt password hashes, per-account lockout (5 failures = 15 min),
signed session cookie (HttpOnly, SameSite=Strict), CSRF token on every form,
three roles (admin, operator, viewer) and security headers.
"""
import os
import secrets
import threading
import time
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import core
import demo

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  PERMANENT_SESSION_LIFETIME=1800)

BASE_HTML = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>LionKeep</title><style>
body{margin:0;font-family:Georgia,serif;background:#fffaf0;color:#1f2937}
nav{background:#7c2d12;padding:10px 18px;color:#fde68a}nav a{color:#fff;margin-right:16px;text-decoration:none}
.wrap{max-width:1100px;margin:auto;padding:16px}.row{display:flex;flex-wrap:wrap;gap:12px}
.box{flex:1 1 200px;background:#fff;border:1px solid #e7d7c1;border-radius:6px;padding:12px;margin-bottom:12px}
.n{font-size:26px;font-weight:bold}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:5px;border-bottom:1px solid #eee;text-align:left}.critical,.DOWN{color:#b91c1c;font-weight:bold}
.UP{color:#166534;font-weight:bold}button{background:#7c2d12;color:#fff;border:0;padding:6px 10px;border-radius:4px}
.flash{background:#fef3c7;padding:8px;border-radius:4px}
</style></head><body><nav><b>LionKeep</b> &middot; {{ inst }}
{% if session.user %}&nbsp; <a href="/">Overview</a><a href="/archives">Archives</a><a href="/quarantine">Quarantine</a>
<a href="/log">Activity log</a><a href="/logout">Logout {{ session.user }} ({{ session.role }})</a>{% endif %}</nav>
<div class="wrap">{% for m in get_flashed_messages() %}<p class="flash">{{ m }}</p>{% endfor %}{{ body|safe }}</div></body></html>"""


def view(body_tpl, **ctx):
    body = render_template_string(body_tpl, csrf=session.get("csrf"), **ctx)
    return render_template_string(BASE_HTML, body=body, inst=core.cfg()["institution"]["name"])


def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if "user" not in session:
                return redirect(url_for("login"))
            if role and session["role"] not in role:
                abort(403)
            if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
                abort(400, "CSRF token missing or wrong")
            return fn(*a, **kw)
        return inner
    return deco


@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u, pw = request.form.get("u", ""), request.form.get("p", "")
        with core.db() as con:
            row = con.execute("SELECT * FROM users WHERE name=?", (u,)).fetchone()
        if row and row["locked_until"] > time.time():
            msg = "Account locked for 15 minutes after 5 failed attempts."
        elif row and check_password_hash(row["pw"], pw):
            with core.db() as con:
                con.execute("UPDATE users SET failed=0 WHERE name=?", (u,))
            session.clear()
            session.update(user=u, role=row["role"], csrf=secrets.token_hex(16))
            session.permanent = True
            core.log(u, "login")
            return redirect("/")
        else:
            if row:
                with core.db() as con:
                    f = row["failed"] + 1
                    con.execute("UPDATE users SET failed=?, locked_until=? WHERE name=?",
                                (f, time.time() + 900 if f >= 5 else 0, u))
            core.log(u[:40] or "?", "failed login")
            msg = "Wrong user name or password."
    return view("""<div class="box" style="max-width:340px"><h3>Sign in</h3><p class="critical">{{ msg }}</p>
    <form method="post">User<br><input name="u"><br>Password<br><input type="password" name="p"><br><br>
    <button>Sign in</button></form></div>""", msg=msg)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required()
def overview():
    with core.db() as con:
        m = con.execute("SELECT * FROM metrics ORDER BY rowid DESC LIMIT 1").fetchone()
        svc = con.execute("SELECT * FROM services").fetchall()
        alerts = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 10").fetchall()
        last = con.execute("SELECT * FROM archives ORDER BY id DESC LIMIT 1").fetchone()
        rs = con.execute("SELECT * FROM restores ORDER BY rowid DESC LIMIT 1").fetchone()
    return view("""<div class="row">
    {% if m %}{% for k in ['cpu','mem','disk'] %}<div class="box">{{ k|upper }}<div class="n">{{ m[k]|round|int }}%</div></div>{% endfor %}{% endif %}
    <div class="box">Last archive<div class="n">{{ last.kind if last else 'none' }}</div>{{ last.created if last else '' }}</div>
    <div class="box">Last restore time<div class="n">{{ '%.2f s'|format(rs.seconds) if rs else '-' }}</div></div></div>
    {% if session.role in ['admin','operator'] %}<div class="box">
    <form method="post" action="/backup" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}">
    <input type="hidden" name="kind" value="diff"><button>Differential backup now</button></form>
    <form method="post" action="/backup" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}">
    <input type="hidden" name="kind" value="full"><button>Full backup now</button></form>
    <form method="post" action="/verify" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}">
    <button>Verify all archives</button></form></div>{% endif %}
    <div class="box"><h3>Services</h3><table>{% for s in svc %}<tr><td>{{ s.name }}</td><td class="{{ s.status }}">{{ s.status }}</td><td>since {{ s.since }}</td></tr>{% endfor %}</table></div>
    <div class="box"><h3>Alerts</h3><table>{% for a in alerts %}<tr><td>{{ a.ts }}</td><td class="{{ a.level }}">{{ a.level }}</td><td>{{ a.message }}</td></tr>{% endfor %}</table></div>""",
                m=m, svc=svc, alerts=alerts, last=last, rs=rs)


@app.route("/archives")
@login_required()
def archives():
    with core.db() as con:
        rows = con.execute("SELECT * FROM archives ORDER BY id DESC").fetchall()
    return view("""<div class="box"><table><tr><th>#</th><th>Created</th><th>Type</th><th>GFS tier</th><th>Files</th>
    <th>Raw</th><th>Stored</th><th>Quarantined</th><th></th></tr>{% for r in rows %}<tr><td>{{ r.id }}</td>
    <td>{{ r.created }}</td><td>{{ r.kind }}{% if r.base_full %} (on full #{{ r.base_full }}){% endif %}</td><td>{{ r.tier }}</td>
    <td>{{ r.files }}</td><td>{{ r.raw_bytes//1024 }} KiB</td><td>{{ r.stored_bytes//1024 }} KiB</td><td>{{ r.quarantined }}</td>
    <td>{% if session.role == 'admin' %}<form method="post" action="/restore"><input type="hidden" name="csrf" value="{{ csrf }}">
    <input type="hidden" name="id" value="{{ r.id }}"><button>Restore</button></form>{% endif %}</td></tr>{% endfor %}</table></div>""",
                rows=rows)


@app.route("/quarantine")
@login_required()
def quarantine():
    with core.db() as con:
        rows = con.execute("SELECT * FROM quarantine ORDER BY id DESC LIMIT 100").fetchall()
    return view("""<div class="box"><p>Files that failed signature or entropy checks. They were NOT written into any
    archive, so the last clean copy stays recoverable.</p><table>{% for r in rows %}<tr><td>{{ r.ts }}</td><td>{{ r.path }}</td>
    <td class="critical">{{ r.reason }}</td></tr>{% endfor %}</table></div>""", rows=rows)


@app.route("/log")
@login_required()
def activity():
    with core.db() as con:
        rows = con.execute("SELECT * FROM log ORDER BY id DESC LIMIT 80").fetchall()
    return view("""<p class="{{ 'UP' if ok else 'critical' }}">Hash chain {{ 'INTACT' if ok else 'BROKEN' }}</p>
    <div class="box"><table>{% for r in rows %}<tr><td>{{ r.ts }}</td><td>{{ r.who }}</td><td>{{ r.what }}</td>
    <td><small>{{ r.hash[:16] }}</small></td></tr>{% endfor %}</table></div>""", rows=rows, ok=core.log_intact())


@app.route("/backup", methods=["POST"])
@login_required(role=["admin", "operator"])
def do_backup():
    flash(str(core.backup(request.form.get("kind", "diff"), who=session["user"])))
    return redirect("/")


@app.route("/verify", methods=["POST"])
@login_required(role=["admin", "operator"])
def do_verify():
    flash(str(core.verify()))
    return redirect("/")


@app.route("/restore", methods=["POST"])
@login_required(role=["admin"])
def do_restore():
    flash(str(core.restore(int(request.form["id"]), who=session["user"])))
    return redirect("/archives")


def add_user(name, pw, role):
    with core.db() as con:
        con.execute("INSERT OR REPLACE INTO users(name,pw,role) VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def scheduler():
    c = core.cfg()
    last_diff = last_full = time.time()
    while True:
        try:
            core.monitor_once()
            with core.db() as con:
                down = con.execute("SELECT 1 FROM services WHERE status='DOWN'").fetchone()
            if down:
                demo.portal(c["portal_port"], background=True)
                core.log("scheduler", "restarted student portal")
            if time.time() - last_full > c["full_every_hours"] * 3600:
                core.backup("full")
                core.rotate()
                last_full = last_diff = time.time()
            elif time.time() - last_diff > c["diff_minutes"] * 60:
                core.backup("diff")
                last_diff = time.time()
        except Exception as exc:  # noqa: BLE001
            core.alert("warning", f"scheduler: {exc}")
        time.sleep(c["monitor_seconds"])


def serve():
    c = core.cfg()
    app.secret_key = os.environ.get(c["secret_env"]) or secrets.token_hex(32)
    threading.Thread(target=scheduler, daemon=True).start()
    app.run(host="127.0.0.1", port=c["port"], debug=False)
