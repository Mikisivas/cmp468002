"""PremierGuard: JSON API + single-page dashboard (Flask).

The browser page is static HTML that calls the API with fetch(). Every state-changing
call must carry the X-CSRF-Token header that the API hands out after login, so a
forged form on another site cannot trigger a restore.
"""
import os
import secrets
import threading
import time
from functools import wraps

from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import demo
import engine

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
ATTEMPTS = {}

PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>PremierGuard</title><style>
:root{--ink:#0f172a;--bg:#eef2ff;--brand:#3730a3;--ok:#047857;--bad:#be123c}
body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--ink)}
header{background:var(--brand);color:#fff;padding:12px 18px;display:flex;justify-content:space-between}
main{max-width:1150px;margin:auto;padding:16px}section{background:#fff;border-radius:10px;padding:14px;margin-bottom:14px}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}.k div{background:#f8fafc;border-radius:8px;padding:10px}
.k b{display:block;font-size:24px}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #e2e8f0;text-align:left}
.critical,.down{color:var(--bad);font-weight:600}.ok,.up{color:var(--ok);font-weight:600}button{background:var(--brand);color:#fff;border:0;border-radius:6px;padding:7px 12px}
#login{max-width:320px;margin:60px auto}input{width:100%;padding:6px;margin:4px 0 10px}
</style></head><body><header><b>PremierGuard &middot; University of Ibadan</b><span id="who"></span></header><main>
<section id="login"><h3>Sign in</h3><input id="u" placeholder="user"><input id="p" type="password" placeholder="password">
<button onclick="login()">Sign in</button><p id="err" class="critical"></p></section>
<div id="app" hidden>
<section><div class="k" id="kpi"></div></section>
<section id="acts"><button onclick="act('/api/snapshot')">Snapshot now</button> <button onclick="act('/api/verify')">Verify Merkle roots and chunks</button>
 <span id="out"></span></section>
<section><h3>Snapshots</h3><table id="snaps"></table></section>
<section><h3>Events</h3><table id="events"></table></section></div></main>
<script>
let csrf=null,role=null;
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(u,opt={}){opt.headers=Object.assign({'Content-Type':'application/json'},opt.headers||{});if(csrf)opt.headers['X-CSRF-Token']=csrf;const r=await fetch(u,opt);return [r.status,await r.json()];}
async function login(){const [s,d]=await api('/api/login',{method:'POST',body:JSON.stringify({u:u.value,p:p.value})});
 if(s!=200){err.textContent=d.error;return;} csrf=d.csrf;role=d.role;start();}
async function act(u,body){out.textContent='working...';const [s,d]=await api(u,{method:'POST',body:JSON.stringify(body||{})});out.textContent=JSON.stringify(d);refresh();}
function start(){document.getElementById('login').hidden=true;app.hidden=false;who.textContent=role;if(role!='admin')acts.hidden=true;refresh();setInterval(refresh,5000);}
async function refresh(){const [s,d]=await api('/api/state');if(s!=200)return;
 const m=d.sample||{};kpi.innerHTML=`<div>CPU<b>${m.cpu??'-'}%</b><small>normal ${m.cpu_ewma??'-'}%</small></div><div>Memory<b>${m.mem??'-'}%</b></div><div>Disk<b>${m.disk??'-'}%</b></div>`+
 d.probes.map(x=>`<div>${esc(x.name)}<b class="${x.up?'up':'down'}">${x.up?'UP':'DOWN'}</b></div>`).join('')+`<div>De-dup saving<b>${d.dedup}%</b></div>`;
 snaps.innerHTML='<tr><th>#</th><th>Created</th><th>Files</th><th>Chunks (new)</th><th>New bytes</th><th>Merkle root</th><th>Status</th><th></th></tr>'+d.snapshots.map(x=>`<tr><td>${x.id}</td><td>${esc(x.created)}</td><td>${x.files}</td><td>${x.chunks_total??''} (${x.chunks_new??''})</td><td>${x.bytes_new??''}</td><td><code>${esc((x.merkle_root||'').slice(0,16))}</code></td><td class="${x.status=='ok'?'ok':'critical'}">${esc(x.status)}</td><td>${x.status=='ok'&&role=='admin'?`<button onclick="act('/api/restore',{id:${x.id}})">Restore</button>`:''}</td></tr>`).join('');
 events.innerHTML=d.events.map(e=>`<tr><td>${esc(e.ts)}</td><td>${esc(e.kind)}</td><td class="${esc(e.level)}">${esc(e.level)}</td><td>${esc(e.text)}</td></tr>`).join('');}
</script></body></html>"""


def need(role=None):
    def deco(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if "user" not in session:
                return jsonify(error="login required"), 401
            if role and session["role"] != role:
                return jsonify(error="forbidden for your role"), 403
            if request.method == "POST" and request.headers.get("X-CSRF-Token") != session.get("csrf"):
                return jsonify(error="CSRF token missing or wrong"), 403
            return fn(*a, **kw)
        return inner
    return deco


@app.after_request
def sec(resp):
    resp.headers.update({"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                         "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline' 'self'; "
                                                    "style-src 'unsafe-inline'"})
    return resp


@app.get("/")
def index():
    return PAGE


@app.post("/api/login")
def login():
    ip = request.remote_addr
    recent = [t for t in ATTEMPTS.get(ip, []) if t > time.time() - 600]
    if len(recent) >= 5:
        return jsonify(error="too many attempts, wait 10 minutes"), 429
    body = request.get_json(silent=True) or {}
    with engine.db() as con:
        row = con.execute("SELECT * FROM accounts WHERE name=?", (body.get("u", ""),)).fetchone()
    if not row or not check_password_hash(row["hash"], body.get("p", "")):
        ATTEMPTS[ip] = recent + [time.time()]
        engine.event("auth", "warning", f"failed login for {str(body.get('u'))[:30]} from {ip}")
        return jsonify(error="wrong user or password"), 401
    session.clear()
    session.update(user=row["name"], role=row["role"], csrf=secrets.token_urlsafe(24))
    engine.event("auth", "info", f"{row['name']} signed in")
    return jsonify(csrf=session["csrf"], role=row["role"])


@app.get("/api/state")
@need()
def state():
    with engine.db() as con:
        s = con.execute("SELECT * FROM samples ORDER BY rowid DESC LIMIT 1").fetchone()
        probes = [dict(r) for r in con.execute("SELECT * FROM probes")]
        snaps = [dict(r) for r in con.execute("SELECT * FROM snapshots ORDER BY id DESC LIMIT 25")]
        ev = [dict(r) for r in con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 15")]
        t = con.execute("SELECT SUM(bytes_in) a FROM snapshots WHERE status='ok'").fetchone()["a"] or 0
        st = con.execute("SELECT SUM(stored) a FROM chunks").fetchone()["a"] or 0
    return jsonify(sample=dict(s) if s else {}, probes=probes, snapshots=snaps, events=ev,
                   dedup=round(100 * (1 - st / t), 1) if t else 0)


@app.post("/api/snapshot")
@need("admin")
def snap():
    return jsonify(engine.snapshot(note=f"manual by {session['user']}"))


@app.post("/api/verify")
@need("admin")
def verify():
    return jsonify(engine.verify())


@app.post("/api/restore")
@need("admin")
def restore():
    sid = int((request.get_json(silent=True) or {}).get("id", 0)) or None
    return jsonify(engine.restore(sid))


def add_account(name, pw, role):
    with engine.db() as con:
        con.execute("INSERT OR REPLACE INTO accounts VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def loop():
    c = engine.cfg()
    last = time.time()
    while True:
        try:
            engine.sample()
            with engine.db() as con:
                down = con.execute("SELECT 1 FROM probes WHERE up=0").fetchone()
            if down:
                demo.portal(c["portal_port"], background=True)
            if time.time() - last > c["snapshot_minutes"] * 60:
                engine.snapshot()
                engine.garbage_collect(c["keep_snapshots"])
                last = time.time()
        except Exception as exc:  # noqa: BLE001
            engine.event("scheduler", "warning", str(exc))
        time.sleep(c["sample_seconds"])


def serve():
    app.secret_key = os.environ.get("PREMIERGUARD_SECRET") or secrets.token_hex(32)
    threading.Thread(target=loop, daemon=True).start()
    app.run(host="127.0.0.1", port=engine.cfg()["port"])
