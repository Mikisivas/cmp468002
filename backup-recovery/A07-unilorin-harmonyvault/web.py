"""HarmonyVault Flask console: timeline of signed commits, diff between commits,
file history and restore. Roles: custodian (restore) and reviewer (read only)."""
import os
import secrets
import threading
import time

from flask import Flask, abort, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import demo
import history as h

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
FAILED = {}
SHELL = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>HarmonyVault</title><style>
body{margin:0;font-family:Candara,Calibri,Arial;background:#f5f3ff;color:#2e1065}
.bar{background:#5b21b6;color:#fff;padding:10px 16px}.bar a{color:#ddd6fe;margin-left:12px}
.m{max-width:1000px;margin:auto;padding:16px}.tl{border-left:4px solid #7c3aed;margin-left:12px;padding-left:16px}
.c{background:#fff;border-radius:8px;padding:10px;margin:10px 0;position:relative}.c:before{content:"";position:absolute;left:-26px;top:14px;width:12px;height:12px;border-radius:50%;background:#7c3aed}
.r{color:#b91c1c;font-weight:bold}.g{color:#15803d;font-weight:bold}code{background:#ede9fe;padding:1px 4px}
button{background:#5b21b6;color:#fff;border:0;border-radius:5px;padding:5px 10px}table{width:100%;border-collapse:collapse}td{padding:4px;border-bottom:1px solid #ede9fe;font-size:14px}
</style></head><body><div class="bar"><b>HarmonyVault</b> &middot; {{ inst }}{% if session.user %}<a href="/">Timeline</a><a href="/alarms">Alarms</a>
<a href="/verify">Verify history</a><a href="/logout">Sign out {{ session.user }}</a>{% endif %}</div><div class="m">{{ body|safe }}</div></body></html>"""


def show(tpl, **kw):
    return render_template_string(SHELL, body=render_template_string(tpl, csrf=session.get("csrf"), **kw),
                                  inst=h.cfg()["institution"]["name"])


def need(role=None):
    if "user" not in session:
        abort(redirect("/login"))
    if role and session["role"] != role:
        abort(403)
    if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
        abort(403)


@app.after_request
def headers(r):
    r.headers.update({"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                      "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'"})
    return r


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        ip = request.remote_addr
        FAILED[ip] = [t for t in FAILED.get(ip, []) if t > time.time() - 900]
        with h.db() as con:
            m = con.execute("SELECT * FROM members WHERE name=?", (request.form.get("u", ""),)).fetchone()
        if len(FAILED[ip]) >= 5:
            msg = "Too many attempts, wait 15 minutes."
        elif m and check_password_hash(m["hash"], request.form.get("p", "")):
            session.clear()
            session.update(user=m["name"], role=m["role"], csrf=secrets.token_hex(16))
            return redirect("/")
        else:
            FAILED[ip].append(time.time())
            msg = "Wrong details."
    return show("""<div class="c" style="max-width:300px"><p class="r">{{ msg }}</p><form method="post">User<br><input name="u"><br>
    Password<br><input type="password" name="p"><br><br><button>Sign in</button></form></div>""", msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/")
def timeline():
    need()
    with h.db() as con:
        commits = con.execute("SELECT * FROM commits ORDER BY rowid DESC LIMIT 40").fetchall()
        refused = con.execute("SELECT * FROM refused ORDER BY id DESC LIMIT 5").fetchall()
        svc = con.execute("SELECT * FROM services").fetchall()
    return show("""<p>Signing key fingerprint <code>{{ fp }}</code> &middot;
    {% for s in svc %}{{ s.name }} <span class="{{ 'g' if s.up else 'r' }}">{{ 'UP' if s.up else 'DOWN' }}</span> {% endfor %}</p>
    {% if session.role == 'custodian' %}<form method="post" action="/commit"><input type="hidden" name="csrf" value="{{ csrf }}">
    <input name="msg" placeholder="message" value="manual backup"> <button>Commit backup now</button></form>{% endif %}
    {% for r in refused %}<p class="r">Refused {{ r.at }}: {{ r.reason }}</p>{% endfor %}
    <div class="tl">{% for c in commits %}<div class="c"><b>{{ c.message }}</b> <code>{{ c.id[:12] }}</code><br>
    <small>{{ c.at }} by {{ c.author }} &middot; {{ c.files }} files: +{{ c.added }} ~{{ c.changed }} -{{ c.removed }}
    &middot; {{ c.new_blobs }} new blobs</small><br>
    {% if c.parent %}<a href="/diff?a={{ c.parent }}&b={{ c.id }}">what changed</a>{% endif %}
    {% if session.role == 'custodian' %}<form method="post" action="/restore" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}">
    <input type="hidden" name="id" value="{{ c.id }}"><button>Restore this point</button></form>{% endif %}</div>{% endfor %}</div>""",
                commits=commits, refused=refused, svc=svc, fp=h.fingerprint_pub())


@app.get("/diff")
def diff():
    need()
    d = h.diff(request.args["a"], request.args["b"])
    return show("""{% for k in ['added','changed','removed'] %}<h3>{{ k|title }} ({{ d[k]|length }})</h3>
    <table>{% for f in d[k] %}<tr><td><a href="/file?path={{ f|urlencode }}">{{ f }}</a></td></tr>{% endfor %}</table>{% endfor %}""", d=d)


@app.get("/file")
def file():
    need()
    rows = h.file_history(request.args["path"])
    return show("""<h3>History of {{ path }}</h3><table>{% for r in rows %}<tr><td><code>{{ r.commit }}</code></td><td>{{ r.at }}</td>
    <td>{{ 'version stored' if r.present else 'deleted' }}</td></tr>{% endfor %}</table>""", rows=rows, path=request.args["path"])


@app.get("/alarms")
def alarms():
    need()
    with h.db() as con:
        rows = con.execute("SELECT * FROM alarms ORDER BY id DESC LIMIT 60").fetchall()
    return show("""<table>{% for a in rows %}<tr><td>{{ a.at }}</td><td class="{{ 'r' if a.level=='critical' else '' }}">{{ a.level }}</td>
    <td>{{ a.text }}</td></tr>{% endfor %}</table>""", rows=rows)


@app.get("/verify")
def verify():
    need()
    v = h.verify_chain()
    return show("""<div class="c"><p class="{{ 'g' if v.ok else 'r' }}">{{ 'Every commit signature, tree and blob verified' if v.ok else 'VERIFICATION FAILED' }}</p>
    <pre>{{ v }}</pre></div>""", v=v)


@app.post("/commit")
def do_commit():
    need("custodian")
    h.commit(request.form.get("msg", "manual backup")[:120], session["user"])
    return redirect("/")


@app.post("/restore")
def do_restore():
    need("custodian")
    h.checkout(request.form["id"], who=session["user"])
    return redirect("/alarms")


def add_member(name, pw, role):
    with h.db() as con:
        con.execute("INSERT OR REPLACE INTO members VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def loop():
    c = h.cfg()
    last = time.time()
    while True:
        try:
            h.probe()
            with h.db() as con:
                if con.execute("SELECT 1 FROM services WHERE up=0").fetchone():
                    demo.portal(c["portal_port"], background=True)
            if time.time() - last > c["commit_minutes"] * 60:
                h.commit()
                last = time.time()
        except Exception as exc:  # noqa: BLE001
            h.alarm("warning", f"scheduler: {exc}")
        time.sleep(c["probe_seconds"])


def serve():
    app.secret_key = os.environ.get("HARMONYVAULT_SECRET") or secrets.token_hex(32)
    threading.Thread(target=loop, daemon=True).start()
    app.run(host="127.0.0.1", port=h.cfg()["port"])
