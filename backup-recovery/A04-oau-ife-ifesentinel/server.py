"""IfeSentinel central server (Flask).

Agents on lab, bursary and registry computers enrol once with a one-time token,
then every request they send is signed: HMAC-SHA256(agent_secret, method|path|timestamp|nonce|sha256(body)).
The server rejects bad signatures, timestamps older than 120 s and repeated nonces (replay).
Backup blobs arrive already encrypted by the agent. The server never holds the agent's
data key, so a compromised server cannot read student records (zero-knowledge storage).
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
SDATA = os.path.join(BASE, "data", "server")
app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=200 * 1024 * 1024)
NONCES = {}
LOCK = threading.Lock()


def cfg():
    with open(os.path.join(BASE, "config.json")) as fh:
        return json.load(fh)


def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db():
    os.makedirs(SDATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(SDATA, "sentinel.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS agents(name TEXT PRIMARY KEY, secret TEXT, role TEXT, location TEXT, enrolled TEXT,
        last_seen REAL, state TEXT, cpu REAL, mem REAL, disk REAL, files INT);
    CREATE TABLE IF NOT EXISTS tokens(token_hash TEXT PRIMARY KEY, location TEXT, used INT);
    CREATE TABLE IF NOT EXISTS blobs(id INTEGER PRIMARY KEY, agent TEXT, created TEXT, kind TEXT, size INT, sha256 TEXT,
        files INT, trusted INT);
    CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, ts TEXT, agent TEXT, level TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS staff(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    """)
    return con


def incident(agent, level, text):
    with db() as con:
        con.execute("INSERT INTO incidents(ts,agent,level,text) VALUES(?,?,?,?)", (now(), agent, level, text))
    print(f"[{level}] {agent}: {text}")


def make_token(location):
    tok = secrets.token_urlsafe(18)
    with db() as con:
        con.execute("INSERT INTO tokens VALUES(?,?,0)", (hashlib.sha256(tok.encode()).hexdigest(), location))
    return tok


# ----------------------------------------------------------------- agent API
def signed(fn):
    @wraps(fn)
    def inner(*a, **kw):
        name = request.headers.get("X-Agent", "")
        ts = request.headers.get("X-Time", "0")
        nonce = request.headers.get("X-Nonce", "")
        sig = request.headers.get("X-Sig", "")
        with db() as con:
            row = con.execute("SELECT * FROM agents WHERE name=?", (name,)).fetchone()
        if not row:
            abort(401)
        if abs(time.time() - float(ts)) > 120:
            incident(name, "warning", "request rejected: stale timestamp")
            abort(401)
        body_hash = hashlib.sha256(request.get_data()).hexdigest()
        msg = f"{request.method}|{request.path}|{ts}|{nonce}|{body_hash}".encode()
        if not hmac.compare_digest(hmac.new(bytes.fromhex(row["secret"]), msg, "sha256").hexdigest(), sig):
            incident(name, "critical", "request rejected: bad signature (possible impersonation)")
            abort(401)
        with LOCK:
            for k in [k for k, t in NONCES.items() if t < time.time() - 300]:
                del NONCES[k]
            if (name, nonce) in NONCES:
                incident(name, "critical", "request rejected: replayed nonce")
                abort(409)
            NONCES[(name, nonce)] = time.time()
        request.agent = row
        return fn(*a, **kw)
    return inner


@app.post("/agent/enrol")
def enrol():
    body = request.get_json(force=True)
    th = hashlib.sha256(str(body.get("token", "")).encode()).hexdigest()
    with db() as con:
        t = con.execute("SELECT * FROM tokens WHERE token_hash=? AND used=0", (th,)).fetchone()
        if not t:
            abort(403)
        secret = secrets.token_hex(32)
        con.execute("UPDATE tokens SET used=1 WHERE token_hash=?", (th,))
        con.execute("INSERT OR REPLACE INTO agents(name,secret,role,location,enrolled,last_seen,state) "
                    "VALUES(?,?,?,?,?,?,?)", (body["name"], secret, body.get("role", "workstation"), t["location"],
                                              now(), time.time(), "online"))
    incident(body["name"], "info", f"enrolled at {t['location']}")
    return jsonify(secret=secret)


@app.post("/agent/heartbeat")
@signed
def heartbeat():
    m = request.get_json(force=True)
    a = request.agent
    state = a["state"] if a["state"] == "isolated" else "online"
    with db() as con:
        con.execute("UPDATE agents SET last_seen=?, state=?, cpu=?, mem=?, disk=?, files=? WHERE name=?",
                    (time.time(), state, m["cpu"], m["mem"], m["disk"], m.get("files"), a["name"]))
    if a["state"] == "offline":
        incident(a["name"], "info", "back online")
    for k, lim in cfg()["thresholds"].items():
        if m.get(k, 0) > lim:
            incident(a["name"], "warning", f"{k} {m[k]}% above {lim}%")
    return jsonify(state=state)


@app.post("/agent/canary")
@signed
def canary():
    a = request.agent
    detail = request.get_json(force=True).get("detail", "")
    with db() as con:
        con.execute("UPDATE agents SET state='isolated' WHERE name=?", (a["name"],))
    incident(a["name"], "critical", f"CANARY TRIPPED: {detail}. Agent isolated, its backup history frozen.")
    return jsonify(state="isolated")


@app.post("/agent/upload")
@signed
def upload():
    a = request.agent
    data = request.get_data()
    kind = request.headers.get("X-Kind", "incremental")
    files = int(request.headers.get("X-Files", "0"))
    trusted = 0 if a["state"] == "isolated" else 1  # uploads after a canary trip are kept but never used for restore
    d = os.path.join(SDATA, "blobs", a["name"])
    os.makedirs(d, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()
    with db() as con:
        cur = con.execute("INSERT INTO blobs(agent,created,kind,size,sha256,files,trusted) VALUES(?,?,?,?,?,?,?)",
                          (a["name"], now(), kind, len(data), digest, files, trusted))
        bid = cur.lastrowid
    with open(os.path.join(d, f"{bid:06d}.bin"), "wb") as fh:
        fh.write(data)
    if not trusted:
        incident(a["name"], "warning", f"upload {bid} received while isolated: marked untrusted")
    return jsonify(id=bid, trusted=trusted)


@app.post("/agent/catalogue")
@signed
def catalogue():
    with db() as con:
        rows = [dict(r) for r in con.execute("SELECT id,created,kind,sha256,trusted FROM blobs WHERE agent=? "
                                             "ORDER BY id", (request.agent["name"],))]
    return jsonify(rows)


@app.post("/agent/blob/<int:bid>")
@signed
def blob(bid):
    with db() as con:
        r = con.execute("SELECT * FROM blobs WHERE id=? AND agent=?", (bid, request.agent["name"])).fetchone()
    if not r:
        abort(404)
    data = open(os.path.join(SDATA, "blobs", r["agent"], f"{bid:06d}.bin"), "rb").read()
    if hashlib.sha256(data).hexdigest() != r["sha256"]:
        incident(r["agent"], "critical", f"stored blob {bid} failed its SHA-256 check")
        abort(500)
    return data


@app.post("/agent/release")
@signed
def release_check():
    return jsonify(state=request.agent["state"])


# ----------------------------------------------------------------- staff console
PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="refresh" content="10"><title>IfeSentinel</title><style>
body{margin:0;font-family:Verdana,Arial;background:#111827;color:#e5e7eb}header{padding:12px 18px;background:#1f2937;border-bottom:3px solid #f59e0b}
main{padding:16px;max-width:1200px;margin:auto}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.a{background:#1f2937;border-radius:8px;padding:12px;border-left:6px solid #10b981}.a.offline{border-color:#6b7280}.a.isolated{border-color:#ef4444}
table{width:100%;border-collapse:collapse;font-size:13px}td{padding:4px;border-bottom:1px solid #374151}
.critical{color:#f87171}.warning{color:#fbbf24}a,button{color:#fbbf24}button{background:#374151;border:0;padding:5px 9px;border-radius:4px}
</style></head><body><header><b>IfeSentinel</b> &middot; {{ inst }} &middot; {{ online }}/{{ agents|length }} agents online
&middot; {{ user }} <a href="/logout">logout</a></header><main><div class="grid">
{% for a in agents %}<div class="a {{ a.state }}"><b>{{ a.name }}</b> <small>{{ a.location }}</small><br>
state: <b>{{ a.state|upper }}</b><br>CPU {{ a.cpu or 0 }}% &middot; RAM {{ a.mem or 0 }}% &middot; disk {{ a.disk or 0 }}%<br>
protected files: {{ a.files or 0 }} &middot; backups: {{ counts.get(a.name, 0) }}<br><small>last seen {{ a.ago }} s ago</small>
{% if a.state == 'isolated' and role == 'admin' %}<form method="post" action="/release"><input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="agent" value="{{ a.name }}"><button>Release after clean-up</button></form>{% endif %}</div>{% endfor %}</div>
<h3>Incidents</h3><table>{% for i in incidents %}<tr><td>{{ i.ts }}</td><td>{{ i.agent }}</td><td class="{{ i.level }}">{{ i.level }}</td><td>{{ i.text }}</td></tr>{% endfor %}</table>
</main></body></html>"""
LOGIN = """<!doctype html><html><body style="font-family:Verdana;background:#111827;color:#eee"><form method="post" style="max-width:300px;margin:80px auto">
<h3>IfeSentinel sign in</h3><p style="color:#f87171">{{ msg }}</p>User<br><input name="u"><br>Password<br><input type="password" name="p"><br><br><button>Sign in</button></form></body></html>"""
FAILS = {}


@app.after_request
def sec(resp):
    resp.headers.update({"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"})
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        ip = request.remote_addr
        FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
        with db() as con:
            r = con.execute("SELECT * FROM staff WHERE name=?", (request.form.get("u", ""),)).fetchone()
        if len(FAILS[ip]) >= 5:
            msg = "Too many attempts. Wait 15 minutes."
        elif r and check_password_hash(r["hash"], request.form.get("p", "")):
            session.clear()
            session.update(user=r["name"], role=r["role"], csrf=secrets.token_hex(16))
            return redirect("/")
        else:
            FAILS[ip].append(time.time())
            msg = "Wrong user or password."
    return render_template_string(LOGIN, msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/")
def console():
    if "user" not in session:
        return redirect("/login")
    sweep()
    with db() as con:
        agents = [dict(r) for r in con.execute("SELECT * FROM agents ORDER BY name")]
        inc = con.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 25").fetchall()
        counts = {r["agent"]: r["n"] for r in con.execute("SELECT agent, COUNT(*) n FROM blobs GROUP BY agent")}
    for a in agents:
        a["ago"] = int(time.time() - (a["last_seen"] or 0))
    return render_template_string(PAGE, agents=agents, incidents=inc, counts=counts, user=session["user"],
                                  role=session["role"], csrf=session["csrf"], inst=cfg()["institution"]["name"],
                                  online=sum(a["state"] == "online" for a in agents))


@app.post("/release")
def release():
    if session.get("role") != "admin" or request.form.get("csrf") != session.get("csrf"):
        abort(403)
    name = request.form["agent"]
    with db() as con:
        con.execute("UPDATE agents SET state='online' WHERE name=?", (name,))
    incident(name, "info", f"released from isolation by {session['user']}")
    return redirect("/")


def sweep():
    """Mark agents offline when three heartbeats are missed."""
    limit = time.time() - 3 * cfg()["heartbeat_seconds"]
    with db() as con:
        rows = con.execute("SELECT name FROM agents WHERE state='online' AND last_seen < ?", (limit,)).fetchall()
        for r in rows:
            con.execute("UPDATE agents SET state='offline' WHERE name=?", (r["name"],))
    for r in rows:
        incident(r["name"], "critical", "agent OFFLINE (missed 3 heartbeats)")


def add_staff(name, pw, role):
    with db() as con:
        con.execute("INSERT OR REPLACE INTO staff VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def serve():
    c = cfg()
    app.secret_key = os.environ.get("IFESENTINEL_SECRET") or secrets.token_hex(32)

    def sweeper():
        while True:
            sweep()
            time.sleep(c["heartbeat_seconds"])
    threading.Thread(target=sweeper, daemon=True).start()
    print(f"IfeSentinel server on http://{c['server_bind']}:{c['server_port']}")
    app.run(host=c["server_bind"], port=c["server_port"], threaded=True)
