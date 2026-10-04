"""YolaShield web server (standard library).

/ussd       telco gateway endpoint (shared token + IP allow-list), plain-text CON/END replies
/phone      staff-only phone simulator to demonstrate the USSD menu in a browser
/reports, /ledger, /risk   staff pages (PBKDF2 login, session token, CSRF on POST)
"""
import hashlib
import hmac
import html
import http.server
import json
import os
import secrets
import socketserver
import threading
import time
import urllib.parse

import geo
import ledger
import ussd

SESS, FAILS = {}, {}
E = html.escape
CSS = """body{margin:0;font-family:Arial;background:#f8fafc;color:#0f172a}header{background:#0f766e;color:#fff;padding:10px 16px}
header a{color:#ccfbf1;margin-left:12px}main{max-width:1150px;margin:auto;padding:12px}.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #e2e8f0;text-align:left}
.bad{color:#b91c1c;font-weight:bold}.ok{color:#15803d;font-weight:bold}button{background:#0f766e;color:#fff;border:0;border-radius:5px;padding:6px 10px}
.phone{width:260px;background:#111;border-radius:24px;padding:18px;color:#e5e7eb}.scr{background:#d9f99d;color:#111;min-height:170px;padding:8px;
font-family:Consolas,monospace;font-size:13px;white-space:pre-wrap;border-radius:6px}.keys button{width:60px;margin:3px;background:#374151}"""


def add_admin(name, pw):
    salt = os.urandom(16).hex()
    with ledger.db() as con:
        con.execute("INSERT OR REPLACE INTO admins VALUES(?,?,?)", (name, salt, hashlib.pbkdf2_hmac(
            "sha256", pw.encode(), bytes.fromhex(salt), 300_000).hex()))


def gateway_token():
    return os.environ.get(geo.cfg()["gateway_token_env"]) or open(ledger.kpath("gateway.token")).read().strip()


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def sess(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "ys" and v in SESS and SESS[v]["exp"] > time.time():
                return SESS[v]
        return None

    def send(self, body, code=200, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode()
        self.send_response(code)
        hdrs = [("Content-Type", ctype), ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"),
                ("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"),
                ("Content-Length", str(len(data)))]
        for k, v in hdrs + list((extra or {}).items()):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def page(self, body, code=200):
        nav = "<a href='/phone'>Phone simulator</a><a href='/reports'>Reports</a><a href='/ledger'>Ledger</a><a href='/risk'>Risk</a>"
        self.send(f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
                  f"<title>YolaShield</title><style>{CSS}</style></head><body><header><b>YolaShield</b> &middot; Adamawa USSD early "
                  f"warning ({E(geo.cfg()['ussd_code'])}) {nav}</header><main>{body}</main></body></html>", code)

    def form(self):
        n = int(self.headers.get("Content-Length", 0))
        if n > 8192:
            return None
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode(), keep_blank_values=True).items()}

    def do_GET(self):
        s = self.sess()
        p = urllib.parse.urlparse(self.path).path
        if not s:
            return self.page("<div class='c' style='max-width:320px'><h3>Staff sign in</h3><form method='post' action='/login'>"
                             "User<br><input name='u'><br>Password<br><input type='password' name='p'><br><br><button>Sign in</button></form></div>")
        if p == "/reports":
            with ledger.db() as con:
                rows = con.execute("SELECT * FROM records ORDER BY ts DESC LIMIT 80").fetchall()
            t = "".join(f"<tr><td>{E(r['ref'])}</td><td>{time.strftime('%d %b %H:%M', time.localtime(r['ts']))}</td><td>{E(r['channel'])}</td>"
                        f"<td>{E(r['lga'])}</td><td>{E(r['type'])}</td><td class='{'bad' if r['urgent'] else ''}'>{'URGENT' if r['urgent'] else ''}</td>"
                        f"<td>{'block ' + str(r['block']) if r['block'] is not None else 'pending'}</td><td>{'ERASED' if r['erased'] else ''}</td></tr>" for r in rows)
            return self.page(f"<div class='c'><table><tr><th>Ref</th><th>Time</th><th>Channel</th><th>LGA</th><th>Type</th><th></th>"
                             f"<th>Ledger</th><th></th></tr>{t}</table></div>")
        if p == "/ledger":
            v = ledger.verify()
            with ledger.db() as con:
                blocks = con.execute("SELECT * FROM blocks ORDER BY height DESC LIMIT 30").fetchall()
            t = "".join(f"<tr><td>{b['height']}</td><td>{time.strftime('%d %b %H:%M', time.localtime(b['ts']))}</td>"
                        f"<td>{len(json.loads(b['items']))}</td><td><code>{b['hash'][:20]}</code></td><td><code>{b['prev'][:12]}</code></td></tr>" for b in blocks)
            status = (f"<p class='ok'>Ledger verified: {v['blocks']} blocks, {v['records']} reports, signatures, links, Merkle roots "
                      f"and the Peace Commission witness copy all match.</p>" if v["ok"] else
                      "<p class='bad'>LEDGER PROBLEMS:<br>" + "<br>".join(E(x) for x in v["problems"]) + "</p>")
            return self.page(f"<div class='c'>{status}<form method='post' action='/seal'><input type='hidden' name='csrf' value='{s['csrf']}'>"
                             f"<button>Seal pending reports now</button></form></div><div class='c'><table><tr><th>Height</th><th>Sealed</th>"
                             f"<th>Reports</th><th>Block hash</th><th>Previous</th></tr>{t}</table></div>")
        if p == "/risk":
            r = ledger.risk()
            t = "".join(f"<tr><td>{E(k)}</td><td>{v['score']}</td><td class='{'bad' if v['level'] in ('High', 'Severe') else ''}'>{v['level']}</td></tr>"
                        for k, v in sorted(r.items(), key=lambda x: -x[1]["score"]))
            return self.page(f"<div class='c'><table><tr><th>LGA</th><th>Score</th><th>Level (what USSD callers hear)</th></tr>{t}</table></div>")
        return self.page(f"""<div class='c'><p>Phone simulator. It sends the same request the telco gateway sends.</p><div class='phone'>
<div class='scr' id='scr'>Dial {E(geo.cfg()['ussd_code'])}</div><input id='inp' style='width:100%;margin:8px 0'>
<div class='keys'><button onclick='dial()'>Dial</button><button onclick='reply()'>Send</button><button onclick='reset()'>End</button></div></div></div>
<script>let path=[],sid='',csrf='{s['csrf']}';
function call(){{fetch('/sim',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
body:new URLSearchParams({{sessionId:sid,phoneNumber:'+2348030000001',text:path.join('*'),csrf:csrf}})}}).then(r=>r.text()).then(t=>{{
document.getElementById('scr').textContent=t.slice(4);if(t.startsWith('END'))path=[];}});}}
function dial(){{sid='SIM'+Date.now();path=[];call();}}
function reply(){{const v=document.getElementById('inp').value.trim();document.getElementById('inp').value='';path.push(v);call();}}
function reset(){{path=[];document.getElementById('scr').textContent='Dial {E(geo.cfg()['ussd_code'])}';}}</script>""")

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        f = self.form()
        if f is None:
            return self.send("too large", 413, "text/plain")
        if p == "/ussd":
            if self.client_address[0] not in geo.cfg()["gateway_allow"] or not hmac.compare_digest(
                    self.headers.get("X-Gateway-Token", ""), gateway_token()):
                return self.send("END Unauthorised", 401, "text/plain")
            return self.send(ussd.handle(f.get("sessionId", "")[:64], f.get("phoneNumber", "")[:20], f.get("text", "")[:120]),
                             ctype="text/plain")
        if p == "/login":
            ip = self.client_address[0]
            FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
            with ledger.db() as con:
                a = con.execute("SELECT * FROM admins WHERE name=?", (f.get("u", ""),)).fetchone()
            ok = a and hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", f.get("p", "").encode(), bytes.fromhex(a["salt"]),
                                                               300_000).hex(), a["hash"])
            if ok and len(FAILS[ip]) < 5:
                tok = secrets.token_urlsafe(32)
                SESS[tok] = {"user": a["name"], "csrf": secrets.token_urlsafe(16), "exp": time.time() + 1800}
                self.send_response(303)
                self.send_header("Location", "/phone")
                self.send_header("Set-Cookie", f"ys={tok}; HttpOnly; SameSite=Strict; Path=/")
                self.end_headers()
                return
            FAILS[ip].append(time.time())
            return self.page("<div class='c bad'>Sign-in failed.</div>", 401)
        s = self.sess()
        if not s or not secrets.compare_digest(f.get("csrf", ""), s["csrf"]):
            return self.send("Forbidden", 403, "text/plain")
        if p == "/sim":
            return self.send(ussd.handle(f.get("sessionId", "")[:64], f.get("phoneNumber", "")[:20], f.get("text", "")[:120]),
                             ctype="text/plain")
        if p == "/seal":
            ledger.seal_if_due(force=True)
            self.send_response(303)
            self.send_header("Location", "/ledger")
            self.end_headers()
            return
        self.send("Not found", 404, "text/plain")


def serve():
    def sealer():
        while True:
            ledger.seal_if_due()
            time.sleep(30)
    threading.Thread(target=sealer, daemon=True).start()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", geo.cfg()["port"]), H) as srv:
        print(f"YolaShield on http://127.0.0.1:{geo.cfg()['port']}  (USSD endpoint POST /ussd)")
        srv.serve_forever()
