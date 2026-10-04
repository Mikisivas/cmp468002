"""ZariaSafe web console built on Python's standard http.server (no web framework).

Security controls: PBKDF2 passwords, random session tokens in HttpOnly SameSite cookies,
a per-session CSRF token on every POST, login lockout after 5 failures, role checks
(viewer cannot back up or restore), and strict security headers.
"""
import html
import http.server
import secrets
import socketserver
import threading
import time
import urllib.parse

import core
import demo

SESSIONS = {}
FAILS = {}
CSS = """body{font-family:Segoe UI,Arial;margin:0;background:#f4f1ea;color:#222}
header{background:#14532d;color:#fff;padding:12px 20px}header a{color:#d9f99d;margin-right:14px}
main{padding:18px;max-width:1150px;margin:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.card{background:#fff;border-radius:8px;padding:14px;box-shadow:0 1px 3px #0002;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{border-bottom:1px solid #ddd;padding:5px;text-align:left}
.UP,.ok{color:#15803d;font-weight:bold}.DOWN,.held,.critical{color:#b91c1c;font-weight:bold}.warning{color:#b45309}
button{background:#14532d;color:#fff;border:0;padding:7px 12px;border-radius:5px;cursor:pointer}
.big{font-size:28px;font-weight:bold}"""


def esc(x):
    return html.escape(str(x))


def page(title, body, sess=None):
    nav = ""
    if sess:
        nav = (f"<a href='/'>Dashboard</a><a href='/versions'>Versions</a><a href='/audit'>Audit trail</a>"
               f"<a href='/logout'>Logout ({esc(sess['user'])})</a>")
    inst = core.load_config()["institution"]["name"]
    return (f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
            f"<title>ZariaSafe</title><style>{CSS}</style></head><body><header><b>ZariaSafe</b> &middot; "
            f"{esc(inst)} &nbsp; {nav}</header><main><h2>{esc(title)}</h2>{body}</main></body></html>")


def form(action, label, sess, extra=""):
    return (f"<form method='post' action='{action}' style='display:inline'>{extra}"
            f"<input type='hidden' name='csrf' value='{sess['csrf']}'><button>{esc(label)}</button></form>")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def session(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "zs" and v in SESSIONS and SESSIONS[v]["exp"] > time.time():
                SESSIONS[v]["exp"] = time.time() + 1800
                return v, SESSIONS[v]
        return None, None

    def send(self, body, code=200, headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, to, headers=None):
        self.send_response(303)
        self.send_header("Location", to)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    # ------------------------------------------------------------- GET
    def do_GET(self):
        sid, sess = self.session()
        p = urllib.parse.urlparse(self.path).path
        if p == "/login" or not sess:
            return self.send(page("Sign in", "<form method='post' action='/login' class='card' style='max-width:320px'>"
                                  "User<br><input name='u'><br>Password<br><input name='p' type='password'><br><br>"
                                  "<button>Sign in</button></form>"))
        if p == "/logout":
            SESSIONS.pop(sid, None)
            return self.redirect("/login", {"Set-Cookie": "zs=; Max-Age=0; Path=/"})
        if p == "/versions":
            return self.send(page("Backup versions", self.versions(sess), sess))
        if p == "/audit":
            return self.send(page("Signed audit trail", self.audit(), sess))
        return self.send(page("Dashboard", self.dashboard(sess), sess))

    def dashboard(self, sess):
        with core.db() as con:
            m = con.execute("SELECT * FROM metrics ORDER BY rowid DESC LIMIT 1").fetchone()
            svc = con.execute("SELECT * FROM services").fetchall()
            al = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 12").fetchall()
            v = con.execute("SELECT * FROM versions ORDER BY id DESC LIMIT 1").fetchone()
            d = con.execute("SELECT * FROM drills ORDER BY rowid DESC LIMIT 1").fetchone()
        tiles = ""
        if m:
            tiles += "".join(f"<div class='card'>{k.upper()}<div class='big'>{m[k]:.0f}%</div></div>"
                             for k in ("cpu", "mem", "disk"))
        tiles += (f"<div class='card'>Last backup<div class='big {esc(v['status']) if v else ''}'>"
                  f"{esc(v['status']) if v else 'none'}</div>{esc(v['created']) if v else ''}</div>")
        tiles += f"<div class='card'>Last measured RTO<div class='big'>{d['rto_s']:.2f}s</div></div>" if d else ""
        svc_rows = "".join(f"<tr><td>{esc(s['name'])}</td><td class='{s['status']}'>{s['status']}</td>"
                           f"<td>{s['latency_ms']} ms</td><td>{esc(s['checked'])}</td></tr>" for s in svc)
        al_rows = "".join(f"<tr><td>{esc(a['ts'])}</td><td class='{esc(a['level'])}'>{esc(a['level'])}</td>"
                          f"<td>{esc(a['source'])}</td><td>{esc(a['message'])}</td></tr>" for a in al)
        actions = ""
        if sess["role"] == "admin":
            actions = form("/backup", "Run backup now", sess) + " " + form("/verify", "Verify and repair", sess)
        return (f"<div class='grid'>{tiles}</div><div class='card'>{actions}</div>"
                f"<div class='card'><h3>Services</h3><table>{svc_rows}</table></div>"
                f"<div class='card'><h3>Alerts</h3><table>{al_rows}</table></div>")

    def versions(self, sess):
        with core.db() as con:
            rows = con.execute("SELECT * FROM versions ORDER BY id DESC LIMIT 40").fetchall()
        out = "<table><tr><th>Version</th><th>Created</th><th>Files</th><th>Changed</th><th>Stored</th>" \
              "<th>Status</th><th>Note</th><th></th></tr>"
        for r in rows:
            btn = ""
            if sess["role"] == "admin" and r["status"] == "ok":
                btn = form("/restore", "Restore", sess, f"<input type='hidden' name='v' value='{esc(r['id'])}'>")
            out += (f"<tr><td>{esc(r['id'])}</td><td>{esc(r['created'])}</td><td>{r['files']}</td><td>{r['changed']}</td>"
                    f"<td>{r['bytes_stored'] // 1024} KiB</td><td class='{esc(r['status'])}'>{esc(r['status'])}</td>"
                    f"<td>{esc(r['note'])}</td><td>{btn}</td></tr>")
        return f"<div class='card'>{out}</table></div>"

    def audit(self):
        ok, bad = core.audit_ok()
        with core.db() as con:
            rows = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 60").fetchall()
        head = "<p class='ok'>Signature chain INTACT</p>" if ok else f"<p class='critical'>BROKEN at row {bad}</p>"
        return head + "<div class='card'><table>" + "".join(
            f"<tr><td>{r['id']}</td><td>{esc(r['ts'])}</td><td>{esc(r['actor'])}</td><td>{esc(r['action'])}</td>"
            f"<td>{esc(r['detail'])}</td></tr>" for r in rows) + "</table></div>"

    # ------------------------------------------------------------- POST
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        f = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
        p = urllib.parse.urlparse(self.path).path
        if p == "/login":
            ip = self.client_address[0]
            fails = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
            if len(fails) >= 5:
                return self.send(page("Locked", "<p>Too many failed attempts. Wait 15 minutes.</p>"), 429)
            role = core.check_user(f.get("u", ""), f.get("p", ""))
            if not role:
                FAILS[ip] = fails + [time.time()]
                core.audit(f.get("u", "?")[:40], "login-failed", ip)
                return self.send(page("Sign in", "<p class='critical'>Wrong user or password.</p>"
                                      "<a href='/login'>Try again</a>"), 401)
            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = {"user": f["u"], "role": role, "csrf": secrets.token_urlsafe(24), "exp": time.time() + 1800}
            core.audit(f["u"], "login", ip)
            return self.redirect("/", {"Set-Cookie": f"zs={sid}; HttpOnly; SameSite=Strict; Path=/"})
        _, sess = self.session()
        if not sess or not secrets.compare_digest(f.get("csrf", ""), sess["csrf"]):
            return self.send(page("Forbidden", "<p>Session expired or CSRF check failed.</p>"), 403)
        if sess["role"] != "admin":
            return self.send(page("Forbidden", "<p>Your role is read-only.</p>", sess), 403)
        if p == "/backup":
            res = core.backup(actor=sess["user"])
            return self.send(page("Backup result", f"<pre>{esc(res)}</pre>", sess))
        if p == "/verify":
            res = core.verify()
            return self.send(page("Verification", f"<pre>{esc(res)}</pre>", sess))
        if p == "/restore":
            res = core.restore(f.get("v"), actor=sess["user"])
            with core.db() as con:
                con.execute("INSERT INTO drills VALUES(?,?,?,?)", (core.now(), res["seconds"], res["files"], -1))
            return self.send(page("Restore complete", f"<pre>{esc(res)}</pre>", sess))
        self.send(page("Not found", "", sess), 404)


def scheduler(stop):
    cfg = core.load_config()
    last_backup = 0.0
    while not stop.is_set():
        try:
            core.monitor_once()
            with core.db() as con:
                down = con.execute("SELECT name FROM services WHERE status='DOWN'").fetchall()
            if down and cfg["self_heal"]:
                demo.portal(cfg["portal_port"], background=True)
                core.audit("scheduler", "self-heal", "restarted student portal")
            if time.time() - last_backup > cfg["backup_minutes"] * 60:
                core.backup()
                last_backup = time.time()
        except Exception as exc:  # noqa: BLE001  keep the scheduler alive
            core.alert("warning", "scheduler", str(exc))
        stop.wait(cfg["monitor_seconds"])


def serve():
    cfg = core.load_config()
    stop = threading.Event()
    threading.Thread(target=scheduler, args=(stop,), daemon=True).start()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", cfg["port"]), Handler) as srv:
        print(f"ZariaSafe console on http://127.0.0.1:{cfg['port']}  (Ctrl+C to stop)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            stop.set()
