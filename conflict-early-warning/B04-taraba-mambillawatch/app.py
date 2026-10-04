"""MambillaWatch Flask app: collar ping API, live Leaflet map, alerts, collar registry."""
import json
import os
import secrets
import time

from flask import Flask, abort, jsonify, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import fence
import geo

app = Flask(__name__, static_folder="static")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=4096)
FAILS = {}
BASE_HTML = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MambillaWatch</title>
<link rel="stylesheet" href="/static/leaflet/leaflet.css"><script src="/static/leaflet/leaflet.js"></script><style>
body{margin:0;font-family:Tahoma,Arial;background:#ecfdf5;color:#064e3b}.n{background:#047857;color:#fff;padding:10px 16px}.n a{color:#a7f3d0;margin-left:12px}
.w{max-width:1300px;margin:auto;padding:12px}.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #d1fae5;text-align:left}
.BREACH,.SPOOF,.RESTRICTED{color:#b91c1c;font-weight:bold}.APPROACH{color:#c2410c;font-weight:bold}.DEVIATION{color:#a16207}
button{background:#047857;color:#fff;border:0;border-radius:5px;padding:6px 10px}input{padding:5px}</style></head><body>
<div class="n"><b>MambillaWatch</b> &middot; Taraba State herd geofencing{% if session.user %}<a href="/">Live map</a><a href="/alerts">Alerts</a>
<a href="/collars">Collars</a><a href="/logout">Sign out {{ session.user }}</a>{% endif %}</div><div class="w">{{ body|safe }}</div></body></html>"""


def show(t, **kw):
    return render_template_string(BASE_HTML, body=render_template_string(t, csrf=session.get("csrf"), **kw))


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


@app.post("/api/ping")
def ping():
    d = request.get_json(force=True, silent=True) or {}
    try:
        ok, reason, alerts = fence.accept(str(d["collar"]), int(d["counter"]), float(d["lat"]), float(d["lon"]),
                                          int(d["battery"]), str(d["sig"]))
    except (KeyError, ValueError, TypeError):
        abort(400)
    return jsonify(accepted=ok, reason=reason, alerts=alerts), (200 if ok else 403)


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        ip = request.remote_addr
        FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
        with fence.db() as con:
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
def live():
    need()
    return show("""<div style="display:grid;grid-template-columns:minmax(0,2fr) minmax(280px,1fr);gap:12px">
    <div class="c"><div id="map" style="height:640px;background:#d1fae5"></div></div><div class="c"><h3>Latest alerts</h3><table id="al"></table></div></div>
    <script>
    const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    let m=null,herds=null,tracks=null;
    if(typeof L!=='undefined'){m=L.map('map').setView([7.9,10.7],8);
     L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:15,attribution:'&copy; OpenStreetMap'}).addTo(m);
     herds=L.layerGroup().addTo(m);tracks=L.layerGroup().addTo(m);
     fetch('/api/zones').then(r=>r.json()).then(z=>{
      z.farms.forEach(f=>L.polygon(f.ring,{color:f.in_season?'#b45309':'#9ca3af',weight:1,fillOpacity:f.in_season?.45:.15}).bindTooltip(esc(f.name)+(f.in_season?' (crop in field)':' (off season)')).addTo(m));
      z.routes.forEach(r=>L.polyline(r,{color:'#065f46',weight:Math.max(3,z.corridor_px),opacity:.25}).addTo(m));
      z.reserves.forEach(r=>L.circle([r[1],r[2]],{radius:r[3]*1000,color:'#16a34a',fillOpacity:.1}).bindTooltip(esc(r[0])).addTo(m));
      z.restricted.forEach(r=>L.circle([r[1],r[2]],{radius:r[3]*1000,color:'#7f1d1d',dashArray:'4 4',fillOpacity:.08}).bindTooltip(esc(r[0])).addTo(m));});}
    function tick(){fetch('/api/state').then(r=>r.json()).then(s=>{
     if(m){herds.clearLayers();tracks.clearLayers();
      s.collars.forEach(c=>{if(c.last_lat==null)return;const col=c.state=='suspect'?'#dc2626':'#7c3aed';
       L.circleMarker([c.last_lat,c.last_lon],{radius:7,color:col,fillOpacity:.9}).bindTooltip(esc(c.herd)+' ('+c.heads+' cattle) '+c.battery+'%').addTo(herds);
       if(s.tracks[c.id])L.polyline(s.tracks[c.id],{color:col,weight:2,opacity:.6}).addTo(tracks);});}
     document.getElementById('al').innerHTML=s.alerts.map(a=>`<tr><td>${new Date(a.ts*1000).toLocaleTimeString()}</td><td class="${a.kind}">${a.kind}</td><td>${esc(a.text)}</td></tr>`).join('');});}
    tick();setInterval(tick,4000);</script>""")


@app.get("/api/zones")
def zones():
    need()
    month = time.localtime().tm_mon
    c = geo.cfg()
    return jsonify(farms=[{"name": f["name"], "ring": [[p[1], p[0]] for p in f["ring"]], "in_season": fence.in_season(f, month)}
                          for f in fence.farms()], routes=list(c["routes"].values()), reserves=c["reserves"],
                   restricted=c["restricted"], corridor_px=c["corridor_km"])


@app.get("/api/state")
def state():
    need()
    with fence.db() as con:
        collars = [dict(r) for r in con.execute("SELECT id,herd,heads,last_lat,last_lon,battery,state FROM collars")]
        alerts = [dict(r) for r in con.execute("SELECT ts,kind,text FROM alerts ORDER BY id DESC LIMIT 25")]
        tracks = {}
        for r in con.execute("SELECT collar, lat, lon FROM pings WHERE accepted=1 AND ts>? ORDER BY id", (time.time() - 86400,)):
            tracks.setdefault(r["collar"], []).append([r["lat"], r["lon"]])
    return jsonify(collars=collars, alerts=alerts, tracks=tracks)


@app.get("/alerts")
def alerts():
    need()
    with fence.db() as con:
        rows = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 80").fetchall()
    return show("""<div class="c"><table><tr><th>Time</th><th>Kind</th><th>Collar</th><th>LGA</th><th>ETA</th><th>Message</th><th>Sent to</th></tr>
    {% for a in rows %}<tr><td>{{ fmt(a.ts) }}</td><td class="{{ a.kind }}">{{ a.kind }}</td><td>{{ a.collar }}</td><td>{{ a.lga }}</td>
    <td>{{ '%.0f min'|format(a.eta_min) if a.eta_min else '' }}</td><td>{{ a.text }}</td><td><small>{{ a.sent_to }}</small></td></tr>{% endfor %}</table></div>""",
                rows=rows, fmt=lambda t: time.strftime("%H:%M:%S", time.localtime(t)))


@app.route("/collars", methods=["GET", "POST"])
def collars():
    need()
    new_key = None
    if request.method == "POST":
        need("coordinator")
        cid = request.form["id"].strip()[:20]
        new_key = (cid, fence.register(cid, request.form["herd"][:40], request.form["group"][:60], int(request.form["heads"])))
    with fence.db() as con:
        rows = con.execute("SELECT id,herd,owner_group,heads,last_counter,battery,state,last_ts FROM collars").fetchall()
        rej = con.execute("SELECT collar, reason, COUNT(*) n FROM pings WHERE accepted=0 GROUP BY collar, reason").fetchall()
    return show("""{% if new_key %}<div class="c">Key for {{ new_key[0] }} (shown once, load it into the collar): <code>{{ new_key[1] }}</code></div>{% endif %}
    <div class="c"><table><tr><th>Collar</th><th>Herd</th><th>Herders' group</th><th>Cattle</th><th>Counter</th><th>Battery</th><th>State</th></tr>
    {% for c in rows %}<tr><td>{{ c.id }}</td><td>{{ c.herd }}</td><td>{{ c.owner_group }}</td><td>{{ c.heads }}</td><td>{{ c.last_counter }}</td>
    <td>{{ c.battery }}%</td><td class="{{ 'SPOOF' if c.state=='suspect' }}">{{ c.state }}</td></tr>{% endfor %}</table></div>
    <div class="c"><h3>Rejected pings</h3><table>{% for r in rej %}<tr><td>{{ r.collar }}</td><td>{{ r.reason }}</td><td>{{ r.n }}</td></tr>{% endfor %}</table></div>
    {% if session.role == 'coordinator' %}<div class="c"><h3>Register a collar</h3><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
    ID <input name="id" required> Herd <input name="herd" required> Group <input name="group" required> Cattle <input name="heads" type="number" required>
    <button>Register</button></form></div>{% endif %}""", rows=rows, rej=rej, new_key=new_key)


def add_staff(name, pw, role):
    with fence.db() as con:
        con.execute("INSERT OR REPLACE INTO staff VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def serve():
    app.secret_key = os.environ.get("MAMBILLAWATCH_SECRET") or secrets.token_hex(32)
    app.run(host="127.0.0.1", port=geo.cfg()["port"], threaded=True)
