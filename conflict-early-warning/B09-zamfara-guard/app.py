"""ZamfaraGuard Flask app: community report form, trust-weighted cluster map, verifier desk."""
import os
import secrets
import time

from flask import Flask, abort, flash, jsonify, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import geo
import trust as tr

app = Flask(__name__, static_folder="static")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=16 * 1024)
FAILS = {}
SKIN = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>ZamfaraGuard</title>
<link rel="stylesheet" href="/static/leaflet/leaflet.css"><script src="/static/leaflet/leaflet.js"></script><style>
body{margin:0;font-family:Arial;background:#f5f5f4;color:#1c1917}.t{background:#44403c;color:#fff;padding:10px 16px}.t a{color:#fde68a;margin-left:12px}
.w{max-width:1250px;margin:auto;padding:12px}.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #e7e5e4;text-align:left}
.probable,.confirmed{color:#b91c1c;font-weight:bold}.verify{color:#c2410c;font-weight:bold}.watch{color:#57534e}.dismissed{color:#78716c;text-decoration:line-through}
button{background:#44403c;color:#fff;border:0;border-radius:5px;padding:5px 9px}input,select{padding:5px}.f{background:#fef9c3;padding:8px;border-radius:6px}</style></head>
<body><div class="t"><b>ZamfaraGuard</b> &middot; trust-weighted community reports{% if session.user %}<a href="/">Clusters</a><a href="/reporters">Reporters</a>
<a href="/logout">Sign out {{ session.user }}</a>{% else %}<a href="/report">Send a report</a><a href="/login">Staff</a>{% endif %}</div><div class="w">
{% for m in get_flashed_messages() %}<div class="f">{{ m }}</div>{% endfor %}{{ body|safe }}</div></body></html>"""


def show(t, **kw):
    return render_template_string(SKIN, body=render_template_string(t, csrf=session.get("csrf"), **kw))


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
                      "Content-Security-Policy": "default-src 'self'; img-src 'self' data: https://*.tile.openstreetmap.org; "
                                                 "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"})
    return r


@app.route("/report", methods=["GET", "POST"])
def report():
    if request.method == "POST":
        try:
            g = geo.lga(request.form["lga"])
            r = tr.submit(request.form["phone"], g["lat"], g["lon"], request.form["type"], request.form.get("text", ""))
        except (KeyError, StopIteration):
            abort(400)
        flash("Report received. Thank you." if r["accepted"] else f"Not accepted: {r['reason']}")
        return redirect("/report")
    return show("""<div class="c" style="max-width:520px"><h3>Send a report</h3><form method="post">Phone (never shown to staff)<br><input name="phone" required><br>
    LGA<br><select name="lga">{% for g in lgas %}<option>{{ g.name }}</option>{% endfor %}</select><br>What happened<br><select name="type">
    {% for k, v in types.items() %}<option value="{{ k }}">{{ v[0] }}</option>{% endfor %}</select><br>Details<br><input name="text" size="50"><br><br>
    <button>Send</button></form></div>""", lgas=geo.lgas(), types=geo.TYPES)


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        ip = request.remote_addr
        FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
        with tr.db() as con:
            u = con.execute("SELECT * FROM staff WHERE name=?", (request.form.get("u", ""),)).fetchone()
        if len(FAILS[ip]) < 5 and u and check_password_hash(u["hash"], request.form.get("p", "")):
            session.clear()
            session.update(user=u["name"], role=u["role"], csrf=secrets.token_hex(16))
            return redirect("/")
        FAILS[ip].append(time.time())
        msg = "Sign-in failed."
    return show("""<div class="c" style="max-width:300px"><p>{{ msg }}</p><form method="post">User<br><input name="u"><br>Password<br>
    <input type="password" name="p"><br><br><button>Sign in</button></form></div>""", msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/")
def clusters():
    need()
    with tr.db() as con:
        rows = con.execute("SELECT * FROM clusters ORDER BY created DESC LIMIT 60").fetchall()
        al = con.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 10").fetchall()
    return show("""<div style="display:grid;grid-template-columns:minmax(0,1.4fr) minmax(320px,1fr);gap:12px"><div class="c"><div id="map" style="height:520px"></div></div>
    <div class="c"><h3>Alerts</h3><table>{% for a in al %}<tr><td class="probable">{{ a.text }}</td></tr>{% endfor %}</table></div></div>
    <div class="c"><table><tr><th>#</th><th>First report</th><th>LGA</th><th>Type</th><th>Reports</th><th>Independent reporters</th><th>Credibility</th>
    <th>Status</th><th>Flag</th><th></th></tr>{% for c in rows %}<tr><td>{{ c.id }}</td><td>{{ fmt(c.created) }}</td><td>{{ c.lga }}</td><td>{{ c.type }}</td>
    <td>{{ c.reports }}</td><td>{{ c.reporters }}</td><td>{{ c.credibility }}</td><td class="{{ c.status }}">{{ c.status }}</td><td><small>{{ c.flag or '' }}</small></td>
    <td>{% if session.role == 'verifier' and not c.verdict %}<form method="post" action="/verdict" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}">
    <input type="hidden" name="id" value="{{ c.id }}"><button name="v" value="1">True</button> <button name="v" value="0">False</button></form>{% endif %}</td></tr>{% endfor %}</table></div>
    <script>const COL={probable:'#dc2626',confirmed:'#7f1d1d',verify:'#f97316',watch:'#a8a29e',dismissed:'#d6d3d1'};
    if(typeof L!=='undefined'){const m=L.map('map').setView([12.45,6.3],8);L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:14,attribution:'&copy; OpenStreetMap'}).addTo(m);
    fetch('/api/clusters').then(r=>r.json()).then(cs=>cs.forEach(c=>L.circleMarker([c.lat,c.lon],{radius:5+3*c.reporters,color:COL[c.status],fillOpacity:.6})
    .bindTooltip(c.type+' '+c.status+' '+c.credibility).addTo(m)));}</script>""", rows=rows, al=al,
                fmt=lambda t: time.strftime("%d %b %H:%M", time.localtime(t)))


@app.get("/api/clusters")
def api_clusters():
    need()
    with tr.db() as con:
        return jsonify([dict(r) for r in con.execute("SELECT id,lat,lon,type,status,credibility,reporters FROM clusters WHERE created>?",
                                                     (time.time() - 7 * 86400,))])


@app.get("/reporters")
def reporters():
    need()
    with tr.db() as con:
        rows = con.execute("SELECT r.*, (SELECT COUNT(*) FROM reports WHERE reporter=r.id) n FROM reporters r ORDER BY n DESC LIMIT 80").fetchall()
    return show("""<div class="c"><p>Reporters are pseudonyms (HMAC of the phone number). Trust = (1 + confirmed) / (2 + confirmed + false).</p>
    <table><tr><th>Pseudonym</th><th>Reports</th><th>Confirmed</th><th>False</th><th>Trust</th></tr>{% for r in rows %}<tr><td>{{ r.id }}</td><td>{{ r.n }}</td>
    <td>{{ r.confirmed }}</td><td>{{ r.false_reports }}</td><td>{{ '%.2f'|format((1+r.confirmed)/(2+r.confirmed+r.false_reports)) }}</td></tr>{% endfor %}</table></div>""", rows=rows)


@app.post("/verdict")
def verdict():
    need("verifier")
    flash(str(tr.verify(int(request.form["id"]), request.form.get("v") == "1", session["user"])))
    tr.recluster()
    return redirect("/")


def add_staff(name, pw, role):
    with tr.db() as con:
        con.execute("INSERT OR REPLACE INTO staff VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def serve():
    app.secret_key = os.environ.get("ZAMFARAGUARD_SECRET") or secrets.token_hex(32)
    app.run(host="127.0.0.1", port=geo.cfg()["port"])
