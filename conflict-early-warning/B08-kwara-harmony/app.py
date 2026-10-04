"""KwaraHarmony Flask app: case list (filtered by ABAC), case timeline and actions, KPIs, export."""
import json
import os
import secrets
import time

from flask import Flask, Response, abort, flash, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import cases as cs
import geo

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
FAILS = {}
PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>KwaraHarmony</title>
<style>body{margin:0;font-family:"Gill Sans",Calibri,Arial;background:#fefce8;color:#422006}.t{background:#854d0e;color:#fff;padding:10px 16px}
.t a{color:#fef08a;margin-left:12px}.w{max-width:1200px;margin:auto;padding:12px}.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #fef9c3;text-align:left}
.st{padding:2px 6px;border-radius:9px;background:#fde68a}.bad{color:#b91c1c;font-weight:bold}button{background:#854d0e;color:#fff;border:0;border-radius:5px;padding:5px 9px}
.f{background:#fef9c3;padding:8px;border-radius:6px;margin-bottom:8px}input,select,textarea{padding:5px}</style></head>
<body><div class="t"><b>KwaraHarmony</b> &middot; Kwara State response and mediation{% if session.user %}<a href="/">Cases</a><a href="/dashboard">Dashboard</a>
<a href="/export">Public export</a><a href="/logout">Sign out {{ session.user }} ({{ session.role }})</a>{% endif %}</div><div class="w">
{% for m in get_flashed_messages() %}<div class="f">{{ m }}</div>{% endfor %}{{ body|safe }}</div></body></html>"""


def show(t, **kw):
    return render_template_string(PAGE, body=render_template_string(t, csrf=session.get("csrf"), **kw))


def need():
    if "user" not in session:
        abort(redirect("/login"))
    if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
        abort(403)
    return cs.user(session["user"])


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
        FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
        with cs.db() as con:
            u = con.execute("SELECT * FROM users WHERE name=? AND role<>'system'", (request.form.get("u", ""),)).fetchone()
        if len(FAILS[ip]) < 5 and u and check_password_hash(u["hash"], request.form.get("p", "")):
            session.clear()
            session.update(user=u["name"], role=u["role"], csrf=secrets.token_hex(16))
            return redirect("/")
        FAILS[ip].append(time.time())
        msg = "Sign-in failed."
    return show("""<div class="c" style="max-width:300px"><p class="bad">{{ msg }}</p><form method="post">User<br><input name="u"><br>Password<br>
    <input type="password" name="p"><br><br><button>Sign in</button></form></div>""", msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


def fmt(t):
    return time.strftime("%d %b %Y %H:%M", time.localtime(t))


@app.route("/", methods=["GET", "POST"])
def case_list():
    u = need()
    if request.method == "POST":
        try:
            cid = cs.create(u, request.form["lga"], request.form["type"], int(request.form["severity"]), request.form["parties"])
            flash(f"Case {cid} opened.")
        except (PermissionError, ValueError, KeyError) as exc:
            flash(f"Refused: {exc}")
        return redirect("/")
    rows = cs.visible(u)
    lgas = [g["name"] for g in geo.lgas() if "*" in u["lgas"] or g["name"] in u["lgas"]]
    return show("""<div class="c"><p>You see {{ rows|length }} case(s): {{ scope }}.</p><table><tr><th>#</th><th>Opened</th><th>LGA</th><th>Type</th>
    <th>Sev.</th><th>State</th><th>Mediator</th></tr>{% for c in rows %}<tr><td><a href="/case/{{ c.id }}">{{ c.id }}</a></td><td>{{ fmt(c.created) }}</td>
    <td>{{ c.lga }}</td><td>{{ c.type }}</td><td>{{ c.severity }}</td><td><span class="st">{{ c.state }}</span></td><td>{{ c.mediator or '' }}</td></tr>{% endfor %}</table></div>
    {% if u.role in ['officer','supervisor'] %}<div class="c"><h3>Open a case</h3><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
    LGA <select name="lga">{% for l in lgas %}<option>{{ l }}</option>{% endfor %}</select> Type <select name="type">{% for k in types %}<option>{{ k }}</option>{% endfor %}</select>
    Severity <select name="severity">{% for i in range(1,6) %}<option>{{ i }}</option>{% endfor %}</select> Parties <input name="parties" placeholder="communities involved">
    <button>Open</button></form></div>{% endif %}""", rows=rows, u=u, lgas=lgas, types=list(geo.TYPES), fmt=fmt,
                scope="all LGAs" if u["role"] in ("supervisor", "auditor") else ("cases assigned to you" if u["role"] == "mediator" else ", ".join(u["lgas"])))


@app.route("/case/<int:cid>", methods=["GET", "POST"])
def case_page(cid):
    u = need()
    c = cs.get(cid)
    if not c or not cs.can(u, "view", c):
        abort(403)
    if request.method == "POST":
        try:
            if request.form.get("note"):
                cs.add_note(u, cid, request.form["note"][:2000])
            else:
                comp = request.form.get("compensation")
                cs.move(u, cid, request.form["to"], request.form.get("why", ""), mediator=request.form.get("mediator") or None,
                        terms=request.form.get("terms") or None, compensation=float(comp) if comp else None)
        except (PermissionError, ValueError) as exc:
            flash(f"Refused: {exc}")
        return redirect(f"/case/{cid}")
    with cs.db() as con:
        steps = con.execute("SELECT * FROM steps WHERE case_id=? ORDER BY ts", (cid,)).fetchall()
        mediators = [r["name"] for r in con.execute("SELECT name FROM users WHERE role='mediator'")]
    notes = cs.read_notes(u, cid)
    nxt = [to for (fr, to) in cs.MOVES if fr == c["state"] and u["role"] in cs.MOVES[(fr, to)]]
    return show("""<div class="c"><h3>Case {{ c.id }}: {{ c.type }} in {{ c.lga }}</h3><p>State <span class="st">{{ c.state }}</span> since {{ fmt(c.state_since) }}.
    Parties: {{ c.parties }}. Mediator: {{ c.mediator or 'none' }}.{% if c.terms %} Agreement: {{ c.terms }} (compensation NGN {{ c.compensation_ngn }}).{% endif %}</p>
    <h4>Timeline</h4><table>{% for s in steps %}<tr><td>{{ fmt(s.ts) }}</td><td>{{ s.who }}</td><td>{{ s.from_state or '' }} &rarr; {{ s.to_state }}</td><td>{{ s.note }}</td></tr>{% endfor %}</table></div>
    {% if nxt %}<div class="c"><h4>Move case</h4><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><select name="to">{% for n in nxt %}<option>{{ n }}</option>{% endfor %}</select>
    Mediator <select name="mediator"><option value="">-</option>{% for m in mediators %}<option>{{ m }}</option>{% endfor %}</select>
    Terms <input name="terms"> Compensation NGN <input name="compensation" size="8"> Reason <input name="why"> <button>Apply</button></form></div>{% endif %}
    <div class="c"><h4>Field notes (encrypted)</h4>{% if notes is none %}<p class="bad">Your role cannot read field notes for this case.</p>{% else %}
    {% for n in notes %}<p><small>{{ fmt(n.ts) }} {{ n.who }}</small><br>{{ n.text }}</p>{% endfor %}
    {% if u.role in ['officer','mediator'] %}<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><textarea name="note" cols="70" rows="3"></textarea><br>
    <button>Add note</button></form>{% endif %}{% endif %}</div>""", c=c, steps=steps, notes=notes, nxt=nxt, mediators=mediators, u=u, fmt=fmt)


@app.get("/dashboard")
def dashboard():
    need()
    return show("""<div class="c"><h3>Performance</h3><p>{{ k }}</p></div><div class="c"><h3>Service-level breaches</h3><table>{% for b in sla %}<tr>
    <td>case {{ b.case }}</td><td>{{ b.lga }}</td><td>{{ b.state }}</td><td class="bad">{{ b.target }} {{ b.hours_late }} h late</td></tr>{% endfor %}</table></div>
    <div class="c"><h3>LGA risk</h3><table><tr><th>LGA</th><th>Open</th><th>New (30 d)</th><th>Relapses (90 d)</th><th>Level</th></tr>{% for n, r in risk.items() %}
    <tr><td>{{ n }}</td><td>{{ r.open }}</td><td>{{ r.recent_30d }}</td><td>{{ r.relapses_90d }}</td><td class="{{ 'bad' if r.level in ['High','Severe'] }}">{{ r.level }}</td></tr>{% endfor %}</table></div>
    <div class="c"><h3>Alerts</h3><table>{% for a in al %}<tr><td>{{ fmt(a.ts) }}</td><td class="bad">{{ a.text }}</td></tr>{% endfor %}</table></div>""",
                k=cs.kpis(), sla=cs.sla_breaches(), risk=dict(sorted(cs.lga_risk().items(), key=lambda x: -x[1]["score"])),
                al=cs.db().execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 20").fetchall(), fmt=fmt)


@app.get("/export")
def export():
    u = need()
    if not cs.can(u, "export_public"):
        abort(403)
    return Response(json.dumps(cs.public_geojson(), indent=1), mimetype="application/geo+json",
                    headers={"Content-Disposition": "attachment; filename=kwara_cases_public.geojson"})


def add_user(name, pw, role, lgas):
    with cs.db() as con:
        con.execute("INSERT OR REPLACE INTO users VALUES(?,?,?,?)", (name, generate_password_hash(pw) if pw else "!", role, json.dumps(lgas)))


def serve():
    app.secret_key = os.environ.get("KWARAHARMONY_SECRET") or secrets.token_hex(32)
    app.run(host="127.0.0.1", port=geo.cfg()["port"])
