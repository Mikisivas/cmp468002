"""AkureKeyVault Flask console. Restore and rotation need an unlock ceremony with two
custodian shares typed into the page; the operator account alone cannot decrypt anything."""
import hashlib
import hmac
import os
import secrets
import threading
import time

from flask import Flask, abort, flash, redirect, render_template_string, request, session

import demo
import keyvault as kv

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
WRONG = {}
SKIN = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AkureKeyVault</title>
<style>body{margin:0;font-family:Arial;background:#fff7ed;color:#431407}.t{background:#9a3412;color:#fff;padding:10px 16px}.t a{color:#fed7aa;margin-left:12px}
.w{max-width:1100px;margin:auto;padding:14px}.c{background:#fff;border:1px solid #fed7aa;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:5px;border-bottom:1px solid #ffedd5;text-align:left}
.r{color:#b91c1c;font-weight:bold}.g{color:#15803d;font-weight:bold}button{background:#9a3412;color:#fff;border:0;border-radius:5px;padding:6px 10px}
textarea,input{font-family:Consolas,monospace}.f{background:#fef9c3;padding:8px;border-radius:6px;margin-bottom:8px;word-break:break-all}</style></head>
<body><div class="t"><b>AkureKeyVault</b> &middot; {{ inst }}{% if session.user %}<a href="/">Overview</a><a href="/backups">Backups</a>
<a href="/ceremonies">Ceremonies</a><a href="/logout">Sign out {{ session.user }}</a>{% endif %}</div><div class="w">
{% for m in get_flashed_messages() %}<div class="f">{{ m }}</div>{% endfor %}{{ body|safe }}</div></body></html>"""
CEREMONY = """<p>Two custodians (Registrar, Bursar, ICT Director) each type their share.</p>
<input type="hidden" name="csrf" value="{{ csrf }}">Share 1<br><input name="s1" size="90" required><br>Share 2<br><input name="s2" size="90" required><br>"""


def show(t, **kw):
    return render_template_string(SKIN, body=render_template_string(t, csrf=session.get("csrf"), ceremony=CEREMONY, **kw),
                                  inst=kv.cfg()["institution"]["name"])


def need(post=False):
    if "user" not in session:
        abort(redirect("/login"))
    if post and (session["role"] != "operator" or request.form.get("csrf") != session["csrf"]):
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
        ip = request.remote_addr
        WRONG[ip] = [t for t in WRONG.get(ip, []) if t > time.time() - 900]
        with kv.db() as con:
            u = con.execute("SELECT * FROM operators WHERE name=?", (request.form.get("u", ""),)).fetchone()
        good = u and hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", request.form.get("p", "").encode(),
                                                             bytes.fromhex(u["salt"]), 300_000).hex(), u["hash"])
        if len(WRONG[ip]) >= 5:
            msg = "Locked for 15 minutes."
        elif good:
            session.clear()
            session.update(user=u["name"], role=u["role"], csrf=secrets.token_hex(16))
            return redirect("/")
        else:
            WRONG[ip].append(time.time())
            msg = "Wrong details."
    return show("""<div class="c" style="max-width:320px"><p class="r">{{ msg }}</p><form method="post">User<br><input name="u"><br>Password<br>
    <input type="password" name="p"><br><br><button>Sign in</button></form></div>""", msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/")
def overview():
    need()
    with kv.db() as con:
        h = con.execute("SELECT * FROM host ORDER BY rowid DESC LIMIT 1").fetchone()
        hl = con.execute("SELECT * FROM health").fetchall()
        ev = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 15").fetchall()
    k = kv.active_key()
    return show("""<div class="c">Recovery key <b>v{{ k.version }}</b> fingerprint <code>{{ k.fingerprint }}</code> (2-of-3 custodian shares)<br>
    {% if h %}CPU {{ h.cpu }}% &middot; RAM {{ h.mem }}% &middot; Disk {{ h.disk }}%{% endif %} &nbsp;
    {% for x in hl %}{{ x.name }} <span class="{{ 'g' if x.up else 'r' }}">{{ 'UP' if x.up else 'DOWN' }}</span> {% endfor %}</div>
    {% if session.role == 'operator' %}<div class="c"><form method="post" action="/backup" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}">
    <button>Back up now (needs only the public key)</button></form></div>
    <div class="c"><h3>Rotate recovery key</h3><form method="post" action="/rotate">{{ ceremony|safe }}<br><button>Rotate and issue new shares</button></form></div>{% endif %}
    <div class="c"><h3>Events</h3><table>{% for e in ev %}<tr><td>{{ e.at }}</td><td class="{{ 'r' if e.sev=='critical' }}">{{ e.sev }}</td><td>{{ e.text }}</td></tr>{% endfor %}</table></div>""",
                k=k, h=h, hl=hl, ev=ev)


@app.get("/backups")
def backups():
    need()
    with kv.db() as con:
        rows = con.execute("SELECT * FROM backups ORDER BY id DESC LIMIT 40").fetchall()
    return show("""<div class="c"><table><tr><th>#</th><th>Sealed</th><th>Files</th><th>Stored</th><th>Key</th><th>State</th></tr>
    {% for b in rows %}<tr><td>{{ b.id }}</td><td>{{ b.at }}</td><td>{{ b.files }}</td><td>{{ b.stored//1024 }} KiB</td><td>v{{ b.key_version }}</td>
    <td class="{{ 'r' if b.shredded else 'g' }}">{{ 'SHREDDED' if b.shredded else 'readable with 2 shares' }}</td></tr>{% endfor %}</table></div>
    {% if session.role == 'operator' %}<div class="c"><h3>Restore (unlock ceremony)</h3><form method="post" action="/restore">{{ ceremony|safe }}
    Backup # (empty = newest)<br><input name="id"><br><br><button>Unlock and restore</button></form></div>
    <div class="c"><h3>Crypto-shred a backup</h3><form method="post" action="/shred"><input type="hidden" name="csrf" value="{{ csrf }}">
    Backup # <input name="id" required> Reason <input name="reason" required> <button>Destroy its data key</button></form></div>{% endif %}""", rows=rows)


@app.get("/ceremonies")
def ceremonies():
    need()
    with kv.db() as con:
        rows = con.execute("SELECT * FROM ceremonies ORDER BY id DESC").fetchall()
    return show("""<div class="c"><table><tr><th>When</th><th>Share numbers</th><th>Purpose</th><th>Result</th></tr>{% for r in rows %}
    <tr><td>{{ r.at }}</td><td>{{ r.custodians }}</td><td>{{ r.purpose }}</td><td class="{{ 'g' if r.ok else 'r' }}">{{ 'unlocked' if r.ok else 'FAILED' }}</td></tr>{% endfor %}</table></div>""", rows=rows)


@app.post("/backup")
def do_backup():
    need(post=True)
    flash(str(kv.backup(session["user"])))
    return redirect("/")


@app.post("/restore")
def do_restore():
    need(post=True)
    try:
        flash(str(kv.restore([request.form["s1"], request.form["s2"]], int(request.form["id"]) if request.form.get("id") else None)))
    except Exception as exc:  # noqa: BLE001
        flash(f"Restore refused: {exc}")
    return redirect("/backups")


@app.post("/rotate")
def do_rotate():
    need(post=True)
    try:
        r = kv.rotate([request.form["s1"], request.form["s2"]])
        flash(f"Key v{r['new_version']} active, {r['rewrapped']} data keys re-wrapped. New shares are in "
              f"data/shares_to_print/. Print them, hand them over, then delete the files.")
    except Exception as exc:  # noqa: BLE001
        flash(f"Rotation refused: {exc}")
    return redirect("/")


@app.post("/shred")
def do_shred():
    need(post=True)
    flash(str(kv.shred(int(request.form["id"]), f"{request.form['reason'][:150]} (by {session['user']})")))
    return redirect("/backups")


def add_operator(name, pw, role):
    salt = os.urandom(16).hex()
    with kv.db() as con:
        con.execute("INSERT OR REPLACE INTO operators VALUES(?,?,?,?)",
                    (name, salt, hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 300_000).hex(), role))


def loop():
    c = kv.cfg()
    last = time.time()
    while True:
        try:
            kv.watch()
            with kv.db() as con:
                if con.execute("SELECT 1 FROM health WHERE up=0").fetchone():
                    demo.portal(c["portal_port"], background=True)
            if time.time() - last > c["backup_minutes"] * 60:
                kv.backup()
                last = time.time()
        except Exception as exc:  # noqa: BLE001
            kv.event("warning", f"scheduler: {exc}")
        time.sleep(c["watch_seconds"])


def serve():
    app.secret_key = os.environ.get("AKUREKEYVAULT_SECRET") or secrets.token_hex(32)
    threading.Thread(target=loop, daemon=True).start()
    app.run(host="127.0.0.1", port=kv.cfg()["port"])
