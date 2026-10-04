"""BenuePeaceGrid web application (Flask + Leaflet).

Public: /report (community incident report, rate-limited, phone encrypted).
Staff: map of hexagon risk, incidents, alerts, AHP weights, audit trail.
Devices: /api/ping (HMAC-signed herd GPS pings).
Roles: admin, analyst (verify reports, rescore), responder (view alerts and map).
"""
import json
import os
import secrets
import threading
import time

from flask import Flask, abort, jsonify, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import geo
import grid

app = Flask(__name__, static_folder="static")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=64 * 1024)
REPORTS = {}
LOGIN_FAILS = {}

SHELL = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>BenuePeaceGrid</title>{{ head|safe }}<style>
body{margin:0;font-family:Segoe UI,Arial;background:#f1f5f9;color:#0f172a}nav{background:#7f1d1d;color:#fff;padding:10px 16px}
nav a{color:#fecaca;margin-left:12px}.w{max-width:1250px;margin:auto;padding:12px}.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #e2e8f0;text-align:left}
.Low{color:#15803d}.Moderate{color:#a16207}.High{color:#c2410c;font-weight:bold}.Severe{color:#b91c1c;font-weight:bold}
button{background:#7f1d1d;color:#fff;border:0;border-radius:5px;padding:6px 10px}input,select,textarea{padding:5px;margin:3px 0 8px;width:100%;max-width:420px}
</style></head><body><nav><b>BenuePeaceGrid</b> &middot; Benue State farmer-herder early warning
{% if session.user %}<a href="/">Risk map</a><a href="/incidents">Incidents</a><a href="/alerts">Alerts</a><a href="/method">AHP weights</a>
<a href="/logout">Sign out {{ session.user }} ({{ session.role }})</a>{% else %}<a href="/report">Report an incident</a><a href="/login">Staff sign in</a>{% endif %}
</nav><div class="w">{{ body|safe }}</div></body></html>"""


def page(body, head="", **kw):
    return render_template_string(SHELL, body=render_template_string(body, csrf=session.get("csrf"), **kw), head=head)


def need(*roles):
    if "user" not in session:
        abort(redirect("/login"))
    if roles and session["role"] not in roles:
        abort(403)
    if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
        abort(403)


@app.after_request
def sec(r):
    r.headers.update({"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                      "Content-Security-Policy": "default-src 'self'; img-src 'self' data: https://*.tile.openstreetmap.org; "
                                                 "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"})
    return r


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        ip = request.remote_addr
        LOGIN_FAILS[ip] = [t for t in LOGIN_FAILS.get(ip, []) if t > time.time() - 900]
        with grid.db() as con:
            u = con.execute("SELECT * FROM users WHERE name=?", (request.form.get("u", ""),)).fetchone()
        if len(LOGIN_FAILS[ip]) >= 5:
            msg = "Too many attempts. Wait 15 minutes."
        elif u and check_password_hash(u["hash"], request.form.get("p", "")):
            session.clear()
            session.update(user=u["name"], role=u["role"], csrf=secrets.token_hex(16))
            grid.audit(u["name"], "sign in")
            return redirect("/")
        else:
            LOGIN_FAILS[ip].append(time.time())
            msg = "Wrong user name or password."
    return page("""<div class="c" style="max-width:340px"><h3>Staff sign in</h3><p style="color:#b91c1c">{{ msg }}</p><form method="post">
    User<input name="u">Password<input type="password" name="p"><button>Sign in</button></form></div>""", msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ----------------------------------------------------------------- public report
@app.route("/report", methods=["GET", "POST"])
def report():
    msg = ""
    if request.method == "POST":
        ip = request.remote_addr
        REPORTS[ip] = [t for t in REPORTS.get(ip, []) if t > time.time() - 3600]
        if len(REPORTS[ip]) >= geo.cfg()["max_reports_per_hour"]:
            return page("<div class='c'>Too many reports from this connection. Please call the hotline.</div>"), 429
        if request.form.get("answer", "").strip() != str(session.get("q_answer")):
            msg = "The arithmetic check was wrong. Please try again."
        else:
            lga_name = request.form.get("lga", "")
            kind = request.form.get("type", "")
            if lga_name not in [g["name"] for g in geo.lgas()] or kind not in geo.TYPES:
                abort(400)
            g = geo.lga(lga_name)
            phone = request.form.get("phone", "").strip()[:20]
            with grid.db() as con:
                con.execute("INSERT INTO incidents(ts,lga,lat,lon,type,severity,fatalities,source,reporter,phone_enc,note) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                            (time.time(), lga_name, g["lat"], g["lon"], kind, geo.TYPES[kind][1], 0, "web",
                             grid.reporter_id(phone) if phone else None,
                             grid.fernet().encrypt(phone.encode()).decode() if phone else None,
                             request.form.get("note", "")[:500]))
            REPORTS[ip].append(time.time())
            msg = "Thank you. Your report was received. Your phone number is stored encrypted."
    a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
    session["q_answer"] = a + b
    return page("""<div class="c"><h3>Report an incident (community)</h3><p>{{ msg }}</p><form method="post">
    Local Government Area<select name="lga">{% for g in lgas %}<option>{{ g.name }}</option>{% endfor %}</select>
    What happened<select name="type">{% for k, v in types.items() %}<option value="{{ k }}">{{ v[0] }}</option>{% endfor %}</select>
    Short description (no names)<textarea name="note" maxlength="500"></textarea>
    Your phone (optional, kept encrypted)<input name="phone" maxlength="20">
    What is {{ a }} + {{ b }}?<input name="answer" required><button>Send report</button></form></div>""",
                msg=msg, lgas=geo.lgas(), types=geo.TYPES, a=a, b=b)


# ----------------------------------------------------------------- staff pages
MAP_HEAD = '<link rel="stylesheet" href="/static/leaflet/leaflet.css"><script src="/static/leaflet/leaflet.js"></script>'


@app.get("/")
def risk_map():
    need()
    t, rows = grid.latest_scores()
    top = sorted(rows, key=lambda r: -r["score"])[:12]
    return page("""<div class="c"><b>Hexagon risk</b> (each cell about {{ size }} km across). Last scored: {{ when }}
    {% if session.role in ['admin','analyst'] %}<form method="post" action="/rescore" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}">
    <button>Rescore now</button></form>{% endif %}</div>
    <div style="display:grid;grid-template-columns:minmax(0,2fr) minmax(260px,1fr);gap:12px">
    <div class="c"><div id="map" style="height:620px;background:#dbeafe"></div></div>
    <div class="c"><h3>Highest-risk cells</h3><table>{% for r in top %}<tr><td>{{ r.hex }}</td><td>{{ r.lga }}</td>
    <td class="{{ r.level }}">{{ r.level }} {{ r.score }}</td></tr>{% endfor %}</table></div></div>
    <script>
    const COL={Low:'#22c55e',Moderate:'#facc15',High:'#f97316',Severe:'#dc2626'};
    if(typeof L!=='undefined'){const m=L.map('map').setView([7.5,8.7],8);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:15,attribution:'&copy; OpenStreetMap'}).addTo(m);
    fetch('/api/grid').then(r=>r.json()).then(fc=>{L.geoJSON(fc,{style:f=>({color:'#334155',weight:.4,fillColor:COL[f.properties.level],fillOpacity:.15+f.properties.score/160}),
    onEachFeature:(f,l)=>l.bindPopup(`<b>${f.properties.hex}</b> ${f.properties.lga}<br>${f.properties.level} ${f.properties.score}<br>`+
     Object.entries(f.properties.factors).map(([k,v])=>`${k.replace(/_/g,' ')}: ${v}`).join('<br>'))}).addTo(m);});
    fetch('/api/layers').then(r=>r.json()).then(d=>{d.routes.forEach(r=>L.polyline(r,{color:'#7c2d12',dashArray:'6 6'}).addTo(m));
     d.farms.forEach(f=>L.polygon(f,{color:'#15803d',weight:1,fillOpacity:.25}).addTo(m));
     d.incidents.forEach(i=>L.circleMarker([i.lat,i.lon],{radius:3,color:'#111'}).addTo(m));
     d.herds.forEach(h=>L.circleMarker([h.lat,h.lon],{radius:6,color:'#7c3aed',fillOpacity:.8}).bindTooltip(h.device+' '+h.heads+' cattle').addTo(m));});}
    </script>""", head=MAP_HEAD, top=top, when=time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "never",
                size=geo.cfg()["hex_km"])


@app.get("/api/grid")
def api_grid():
    need()
    _, rows = grid.latest_scores()
    return jsonify({"type": "FeatureCollection", "features": [
        {"type": "Feature", "geometry": {"type": "Polygon", "coordinates": [json.loads(r["ring"])]},
         "properties": {"hex": r["hex"], "lga": r["lga"], "score": r["score"], "level": r["level"],
                        "factors": json.loads(r["factors"])}} for r in rows]})


@app.get("/api/layers")
def api_layers():
    need()
    with grid.db() as con:
        inc = con.execute("SELECT lat, lon FROM incidents WHERE ts>?", (time.time() - 30 * 86400,)).fetchall()
        herds = con.execute("SELECT device, lat, lon, heads FROM pings WHERE id IN (SELECT MAX(id) FROM pings GROUP BY device)"
                            " AND ts>?", (time.time() - 86400,)).fetchall()
    return jsonify(routes=list(geo.cfg()["routes"].values()),
                   farms=[[[p[1], p[0]] for p in f["ring"]] for f in geo.farmland()],
                   incidents=[dict(i) for i in inc], herds=[dict(h) for h in herds])


@app.get("/incidents")
def incidents():
    need()
    with grid.db() as con:
        rows = con.execute("SELECT id,ts,lga,type,severity,fatalities,source,reporter,note,verified FROM incidents "
                           "ORDER BY ts DESC LIMIT 80").fetchall()
    return page("""<div class="c"><table><tr><th>When</th><th>LGA</th><th>Type</th><th>Sev.</th><th>Deaths</th><th>Source</th>
    <th>Reporter (pseudonym)</th><th>Note</th><th>Verified</th></tr>{% for r in rows %}<tr><td>{{ fmt(r.ts) }}</td><td>{{ r.lga }}</td>
    <td>{{ types[r.type][0] }}</td><td>{{ r.severity }}</td><td>{{ r.fatalities }}</td><td>{{ r.source }}</td><td>{{ r.reporter or '-' }}</td>
    <td>{{ r.note or '' }}</td><td>{% if r.verified %}yes{% elif session.role in ['admin','analyst'] %}<form method="post" action="/verify">
    <input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="id" value="{{ r.id }}"><button>Verify</button></form>{% else %}no{% endif %}</td></tr>{% endfor %}</table></div>""",
                rows=rows, types=geo.TYPES, fmt=lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)))


@app.get("/alerts")
def alerts():
    need()
    with grid.db() as con:
        rows = con.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 50").fetchall()
    return page("""<div class="c"><table>{% for a in rows %}<tr><td>{{ fmt(a.ts) }}</td><td class="{{ a.level }}">{{ a.level }}</td><td>{{ a.lga }}</td>
    <td>{{ a.message }}</td><td><small>to {{ a.recipients }}</small></td></tr>{% endfor %}</table></div>""",
                rows=rows, fmt=lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)))


@app.get("/method")
def method():
    need()
    a = grid.ahp()
    m = geo.cfg()["ahp"]["pairwise"]
    return page("""<div class="c"><h3>Analytic Hierarchy Process weights</h3><p>Pairwise comparison matrix (row factor versus column factor,
    Saaty 1-9 scale):</p><table><tr><th></th>{% for f in a.factors %}<th>{{ f }}</th>{% endfor %}<th>Weight</th></tr>
    {% for i in range(a.factors|length) %}<tr><th>{{ a.factors[i] }}</th>{% for v in m[i] %}<td>{{ '%.2f'|format(v) }}</td>{% endfor %}
    <td><b>{{ a.weights[i] }}</b></td></tr>{% endfor %}</table><p>&lambda;max = {{ a.lambda_max }}, CI = {{ a.ci }},
    consistency ratio CR = <b>{{ a.cr }}</b> ({{ 'acceptable, below 0.10' if a.consistent else 'NOT acceptable' }})</p></div>""", a=a, m=m)


@app.post("/rescore")
def rescore():
    need("admin", "analyst")
    grid.score_all()
    grid.audit(session["user"], "manual rescore")
    return redirect("/")


@app.post("/verify")
def verify():
    need("admin", "analyst")
    with grid.db() as con:
        con.execute("UPDATE incidents SET verified=1 WHERE id=?", (int(request.form["id"]),))
    grid.audit(session["user"], f"verified incident {request.form['id']}")
    return redirect("/incidents")


@app.post("/api/ping")
def api_ping():
    body = request.get_data()
    dev, ts, sig = request.headers.get("X-Device", ""), request.headers.get("X-Time", "0"), request.headers.get("X-Sig", "")
    if not grid.verify_ping(dev, ts, body, sig):
        grid.audit("api", f"rejected ping from {dev[:20]}")
        abort(401)
    d = json.loads(body)
    if not grid.in_state(d["lat"], d["lon"]):
        abort(400)
    with grid.db() as con:
        con.execute("INSERT INTO pings(ts,device,lat,lon,heads) VALUES(?,?,?,?,?)",
                    (time.time(), dev, float(d["lat"]), float(d["lon"]), int(d["heads"])))
    return jsonify(ok=True)


def add_user(name, pw, role):
    with grid.db() as con:
        con.execute("INSERT OR REPLACE INTO users VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def scorer():
    while True:
        try:
            grid.score_all()
        except Exception as exc:  # noqa: BLE001
            print("scorer:", exc)
        time.sleep(60)


def serve():
    app.secret_key = os.environ.get(geo.cfg()["secret_env"]) or secrets.token_hex(32)
    threading.Thread(target=scorer, daemon=True).start()
    app.run(host="127.0.0.1", port=geo.cfg()["port"], threaded=True)
