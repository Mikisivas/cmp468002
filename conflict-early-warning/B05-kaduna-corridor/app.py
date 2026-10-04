"""KadunaCorridor Flask app: escalation forecast table, intensity charts (SVG), retaliation chains."""
import os
import secrets
import time

from flask import Flask, abort, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import geo
import hawkes as hk

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
FAILS = {}
LAYOUT = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>KadunaCorridor</title>
<style>body{margin:0;font-family:"Segoe UI",Arial;background:#fff1f2;color:#4c0519}.b{background:#9f1239;color:#fff;padding:10px 16px}
.b a{color:#fecdd3;margin-left:12px}.w{max-width:1200px;margin:auto;padding:12px}.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #ffe4e6;text-align:left}
.ESCALATING{color:#b91c1c;font-weight:bold}.elevated{color:#c2410c}button{background:#9f1239;color:#fff;border:0;border-radius:5px;padding:6px 10px}</style></head>
<body><div class="b"><b>KadunaCorridor</b> &middot; Southern Kaduna escalation forecasting{% if session.user %}<a href="/">Forecast</a><a href="/chains">Retaliation chains</a>
<a href="/model">Model</a><a href="/logout">Sign out {{ session.user }}</a>{% endif %}</div><div class="w">{{ body|safe }}</div></body></html>"""


def show(t, **kw):
    return render_template_string(LAYOUT, body=render_template_string(t, csrf=session.get("csrf"), **kw))


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
        with hk.db() as con:
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


def chart(lga_name):
    pts, marks = hk.series(lga_name)
    top = max(pts) or 1
    W, H = 600, 110
    poly = " ".join(f"{i / (len(pts) - 1) * W:.1f},{H - 8 - v / top * (H - 18):.1f}" for i, v in enumerate(pts))
    ticks = "".join(f'<line x1="{m / (len(pts) - 1) * W:.1f}" x2="{m / (len(pts) - 1) * W:.1f}" y1="{H - 6}" y2="{H}" stroke="#111"/>' for m in marks)
    return (f'<svg viewBox="0 0 {W} {H}" style="width:100%;max-width:640px"><polyline points="{poly}" fill="none" '
            f'stroke="#be123c" stroke-width="2"/>{ticks}<text x="2" y="12" font-size="11">peak {top:.3f} events/day; '
            f'ticks = violent events; last 120 days</text></svg>')


@app.get("/")
def forecast_page():
    need()
    rows = hk.forecast()
    with hk.db() as con:
        warns = con.execute("SELECT * FROM warnings ORDER BY at DESC LIMIT 10").fetchall()
    charts = {r["lga"]: chart(r["lga"]) for r in rows[:4]}
    return show("""<div class="c"><h3>Escalation forecast (next 7 days)</h3><table><tr><th>LGA</th><th>Status</th><th>Intensity now</th>
    <th>Background</th><th>Ratio</th><th>Expected violent events</th><th>P(at least one)</th></tr>{% for r in rows %}<tr><td>{{ r.lga }}</td>
    <td class="{{ r.status }}">{{ r.status }}</td><td>{{ r.intensity }}</td><td>{{ r.background }}</td><td>{{ r.ratio }}x</td>
    <td>{{ r.expected_7d }}</td><td>{{ (r.p_any_7d*100)|round|int }}%</td></tr>{% endfor %}</table></div>
    <div class="c"><h3>Warnings</h3><table>{% for w in warns %}<tr><td>{{ fmt(w.at) }}</td><td class="ESCALATING">{{ w.text }}</td></tr>{% endfor %}</table></div>
    {% for lga, svg in charts.items() %}<div class="c"><b>{{ lga }}</b> conditional intensity<br>{{ svg|safe }}</div>{% endfor %}""",
                rows=rows, warns=warns, charts=charts, fmt=lambda t: time.strftime("%d %b %H:%M", time.localtime(t)))


@app.get("/chains")
def chain_page():
    need()
    ch = hk.chains()
    return show("""<div class="c"><p>A chain links violent events within {{ hrs }} hours and {{ km }} km of an earlier one. Long chains are
    revenge cycles that mediation should target.</p>{% for c in ch[:10] %}<h4>Chain of {{ c|length }} events starting in {{ c[0].lga }}</h4>
    <table>{% for e in c %}<tr><td>{{ fmt(e.ts) }}</td><td>{{ e.lga }}</td><td>{{ e.type }}</td><td>{{ e.fatalities }} killed</td></tr>{% endfor %}</table>{% endfor %}</div>""",
                ch=ch, hrs=geo.cfg()["chain_hours"], km=geo.cfg()["chain_km"], fmt=lambda t: time.strftime("%d %b %H:%M", time.localtime(t)))


@app.route("/model", methods=["GET", "POST"])
def model_page():
    need()
    if request.method == "POST":
        need("analyst")
        hk.fit()
    with hk.db() as con:
        f = con.execute("SELECT * FROM fits ORDER BY id DESC LIMIT 1").fetchone()
    return show("""<div class="c"><h3>Fitted Hawkes model</h3><p>Branching ratio &alpha; = <b>{{ f.alpha }}</b> (each violent event triggers on
    average {{ f.alpha }} more). Memory 1/&beta; = <b>{{ '%.1f'|format(1/f.beta) }} days</b>. Trained on {{ f.n_train }} events.</p>
    <p>Held-out log-likelihood on the next {{ f.n_test }} events: Hawkes {{ '%.1f'|format(f.test_ll_hawkes) }} vs Poisson
    {{ '%.1f'|format(f.test_ll_poisson) }} ({{ 'Hawkes explains the data better' if f.test_ll_hawkes > f.test_ll_poisson else 'no gain over Poisson' }}).</p>
    {% if session.role == 'analyst' %}<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Refit now</button></form>{% endif %}</div>""", f=f)


def add_staff(name, pw, role):
    with hk.db() as con:
        con.execute("INSERT OR REPLACE INTO staff VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def serve():
    app.secret_key = os.environ.get("KADUNACORRIDOR_SECRET") or secrets.token_hex(32)
    app.run(host="127.0.0.1", port=geo.cfg()["port"])
