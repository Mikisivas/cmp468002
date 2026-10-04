"""NigerBasinWatch Flask app: 8-week seasonal risk calendar, LGA NDVI charts, dataset versions."""
import os
import secrets
import time

from flask import Flask, abort, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import geo
import tpi

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=2 * 1024 * 1024)
FAILS = {}
COL = {"Low": "#bbf7d0", "Moderate": "#fde68a", "High": "#fdba74", "Severe": "#f87171"}
WRAP = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>NigerBasinWatch</title>
<style>body{margin:0;font-family:Calibri,Arial;background:#eff6ff;color:#172554}.h{background:#1e3a8a;color:#fff;padding:10px 16px}.h a{color:#bfdbfe;margin-left:12px}
.w{max-width:1200px;margin:auto;padding:12px}.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px;overflow-x:auto}
table{border-collapse:collapse;font-size:13px;width:100%}td,th{padding:4px;border-bottom:1px solid #dbeafe;text-align:left}
.cell{text-align:center;font-weight:bold;min-width:70px}button{background:#1e3a8a;color:#fff;border:0;border-radius:5px;padding:6px 10px}.bad{color:#b91c1c;font-weight:bold}</style></head>
<body><div class="h"><b>NigerBasinWatch</b> &middot; Niger State seasonal transhumance risk{% if session.user %}<a href="/">Risk calendar</a><a href="/data">Datasets</a>
<a href="/logout">Sign out {{ session.user }}</a>{% endif %}</div><div class="w">{{ body|safe }}</div></body></html>"""


def show(t, **kw):
    return render_template_string(WRAP, body=render_template_string(t, csrf=session.get("csrf"), **kw))


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


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        ip = request.remote_addr
        FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
        with tpi.db() as con:
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
def calendar():
    need()
    with tpi.db() as con:
        rows = con.execute("SELECT * FROM calendar ORDER BY lga, week").fetchall()
        al = con.execute("SELECT * FROM alerts ORDER BY at DESC, week LIMIT 12").fetchall()
    weeks = sorted({r["week"] for r in rows})
    grid = {}
    for r in rows:
        grid.setdefault(r["lga"], {})[r["week"]] = r
    v = tpi.verify_datasets()
    return show("""{% if not v.ok %}<div class="c bad">DATASET INTEGRITY PROBLEM: {{ v.problems }}. Forecast must not be trusted.</div>{% endif %}
    <div class="c"><h3>8-week transhumance pressure calendar</h3><table><tr><th>LGA</th>{% for w in weeks %}<th>{{ w[5:] }}</th>{% endfor %}</tr>
    {% for lga, row in grid.items() %}<tr><td><a href="/lga/{{ lga }}">{{ lga }}</a></td>{% for w in weeks %}{% set c = row[w] %}
    <td class="cell" style="background:{{ col[c.level] }}" title="{{ c.level }}">{{ '%.2f'|format(c.tpi) }}</td>{% endfor %}</tr>{% endfor %}</table>
    <small>0 = no pressure, 1 = maximum. Colours: Low, Moderate, High (0.55+), Severe (0.70+).</small></div>
    <div class="c"><h3>Seasonal warnings</h3><table>{% for a in al %}<tr><td>{{ a.text }}</td></tr>{% endfor %}</table></div>""",
                grid=grid, weeks=weeks, col=COL, al=al, v=v)


@app.get("/lga/<name>")
def lga_page(name):
    need()
    if name not in [g["name"] for g in geo.lgas()]:
        abort(404)
    s = tpi.series(name)[-104:]
    n = tpi.series(tpi.NORTH)[-104:]
    W, H = 640, 150

    def line(vals, colr):
        return "<polyline fill='none' stroke='%s' stroke-width='2' points='%s'/>" % (colr, " ".join(
            f"{i / (len(vals) - 1) * W:.1f},{H - 10 - v * (H - 20) / 0.8:.1f}" for i, v in enumerate(vals)))
    svg = (f"<svg viewBox='0 0 {W} {H}' style='width:100%;max-width:700px;background:#f8fafc'>{line([x[1] for x in s], '#15803d')}"
           f"{line([x[1] for x in n], '#b45309')}<text x='4' y='14' font-size='11'>green = {name} NDVI, brown = northern source zone "
           f"NDVI, last 2 years</text></svg>")
    return show("<div class='c'><h3>{{ name }}</h3>{{ svg|safe }}</div>", name=name, svg=svg)


@app.route("/data", methods=["GET", "POST"])
def data():
    need()
    msg = None
    if request.method == "POST":
        need("analyst")
        f = request.files.get("file")
        if f:
            msg = tpi.import_csv(f.read().decode("utf-8", "replace"), f.filename or "upload.csv", session["user"])
            if msg.get("accepted"):
                tpi.forecast()
    with tpi.db() as con:
        vers = con.execute("SELECT * FROM versions ORDER BY id DESC").fetchall()
    return show("""{% if msg %}<div class="c">{{ msg }}</div>{% endif %}<div class="c"><h3>Dataset versions</h3><table><tr><th>#</th><th>Imported</th>
    <th>File</th><th>Rows</th><th>SHA-256</th><th>By</th></tr>{% for v in vers %}<tr><td>{{ v.id }}</td><td>{{ fmt(v.at) }}</td><td>{{ v.name }}</td>
    <td>{{ v.rows }}</td><td><code>{{ v.sha256[:24] }}</code></td><td>{{ v.by }}</td></tr>{% endfor %}</table></div>
    {% if session.role == 'analyst' %}<div class="c"><h3>Import NDVI / rainfall CSV</h3><p>Columns: area, week (YYYY-MM-DD), ndvi, rain_mm.</p>
    <form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="file" name="file" accept=".csv">
    <button>Import</button></form></div>{% endif %}""", vers=vers, msg=msg, fmt=lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)))


def add_staff(name, pw, role):
    with tpi.db() as con:
        con.execute("INSERT OR REPLACE INTO staff VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def serve():
    app.secret_key = os.environ.get("BASINWATCH_SECRET") or secrets.token_hex(32)
    app.run(host="127.0.0.1", port=geo.cfg()["port"])
