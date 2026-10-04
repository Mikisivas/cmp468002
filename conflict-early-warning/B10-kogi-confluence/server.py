"""ConfluenceEWS hub web server (standard library only): POST /sync for tablets, staff pages for
devices, sync log, risk table and model card."""
import hashlib
import hmac
import html
import http.server
import json
import os
import secrets
import socketserver
import time
import urllib.parse

import geo
import hub

SESS, FAILS = {}, {}
E = html.escape
CSS = """body{margin:0;font-family:Verdana,Arial;background:#f0f9ff;color:#0c4a6e}header{background:#075985;color:#fff;padding:10px 16px}
header a{color:#bae6fd;margin-left:12px}main{max-width:1150px;margin:auto;padding:12px}.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #e0f2fe;text-align:left}
.Severe,.High,.bad{color:#b91c1c;font-weight:bold}.Moderate{color:#a16207}button{background:#075985;color:#fff;border:0;border-radius:5px;padding:6px 10px}"""


def add_admin(name, pw):
    salt = os.urandom(16).hex()
    with hub.db() as con:
        con.execute("INSERT OR REPLACE INTO admins VALUES(?,?,?)", (name, salt, hashlib.pbkdf2_hmac(
            "sha256", pw.encode(), bytes.fromhex(salt), 300_000).hex()))


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def out(self, body, code=200, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode()
        self.send_response(code)
        for k, v in [("Content-Type", ctype), ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"),
                     ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'"), ("Content-Length", str(len(data)))] \
                + list((extra or {}).items()):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def page(self, body, code=200):
        self.out(f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>ConfluenceEWS</title>"
                 f"<style>{CSS}</style></head><body><header><b>ConfluenceEWS</b> &middot; Kogi State offline-first early warning "
                 f"<a href='/'>Risk</a><a href='/devices'>Tablets</a><a href='/model'>Model</a></header><main>{body}</main></body></html>", code)

    def sess(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "ce" and v in SESS and SESS[v] > time.time():
                return True
        return False

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if not self.sess():
            return self.page("<div class='c' style='max-width:320px'><h3>Sign in</h3><form method='post' action='/login'>User<br><input name='u'><br>"
                             "Password<br><input type='password' name='p'><br><br><button>Sign in</button></form></div>")
        if p == "/devices":
            with hub.db() as con:
                devs = con.execute("SELECT * FROM devices").fetchall()
                log = con.execute("SELECT * FROM sync_log ORDER BY id DESC LIMIT 40").fetchall()
            d = "".join(f"<tr><td>{E(x['id'])}</td><td>{E(x['officer'])}</td><td>{E(x['lga'])}</td><td>{x['last_counter']}</td>"
                        f"<td>{time.strftime('%d %b %H:%M', time.localtime(x['last_sync'])) if x['last_sync'] else 'never'}</td></tr>" for x in devs)
            lg = "".join(f"<tr><td>{time.strftime('%d %b %H:%M:%S', time.localtime(x['ts']))}</td><td>{E(x['device'])}</td><td>{x['counter']}</td>"
                         f"<td class='{'bad' if x['result'] != 'ok' else ''}'>{E(x['result'])}</td><td>{x['new']} new, {x['updated']} updated, "
                         f"{x['duplicates']} duplicate</td></tr>" for x in log)
            return self.page(f"<div class='c'><h3>Field tablets</h3><table><tr><th>Device</th><th>Officer</th><th>LGA</th><th>Counter</th>"
                             f"<th>Last sync</th></tr>{d}</table></div><div class='c'><h3>Sync log</h3><table>{lg}</table></div>")
        if p == "/model":
            ev = json.load(open(hub.MODEL))["evaluation"]
            w = "".join(f"<tr><td>{E(k)}</td><td>{v}</td></tr>" for k, v in ev["weights"].items())
            return self.page(f"<div class='c'><h3>Model card</h3><p>Logistic regression (from scratch). Target: a violent incident in the "
                             f"LGA within 14 days. Trained on {ev['train_rows']} LGA-weeks, tested on the most recent {ev['test_rows']}.</p>"
                             f"<p>AUC {ev['auc_model']} (naive last-30-days rule: {ev['auc_naive_last30']}). Brier {ev['brier_model']} "
                             f"(always-average forecast: {ev['brier_climatology']}).</p><table><tr><th>Feature</th><th>Weight (standardised)</th></tr>{w}</table></div>")
        with hub.db() as con:
            rows = con.execute("SELECT * FROM risk ORDER BY prob DESC").fetchall()
        t = "".join(f"<tr><td>{E(r['lga'])}</td><td>{r['prob'] * 100:.0f}%</td><td class='{r['level']}'>{r['level']}</td></tr>" for r in rows)
        return self.page(f"<div class='c'><h3>Chance of a violent incident in the next 14 days</h3><table><tr><th>LGA</th><th>Probability</th>"
                         f"<th>Level</th></tr>{t}</table><p>Tablets receive this table on every sync, so it is available offline in the field.</p></div>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        if n > 1_000_000:
            return self.out('{"error":"too large"}', 413, "application/json")
        body = self.rfile.read(n)
        if self.path == "/sync":
            code, reply = hub.sync(body, self.headers.get("X-Sig"))
            return self.out(json.dumps(reply), code, "application/json")
        if self.path == "/login":
            f = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode()).items()}
            ip = self.client_address[0]
            FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
            with hub.db() as con:
                a = con.execute("SELECT * FROM admins WHERE name=?", (f.get("u", ""),)).fetchone()
            if len(FAILS[ip]) < 5 and a and hmac.compare_digest(hashlib.pbkdf2_hmac(
                    "sha256", f.get("p", "").encode(), bytes.fromhex(a["salt"]), 300_000).hex(), a["hash"]):
                tok = secrets.token_urlsafe(32)
                SESS[tok] = time.time() + 1800
                return self.out("", 303, extra={"Location": "/", "Set-Cookie": f"ce={tok}; HttpOnly; SameSite=Strict; Path=/"})
            FAILS[ip].append(time.time())
            return self.page("<div class='c bad'>Sign-in failed.</div>", 401)
        self.out("not found", 404, "text/plain")


def serve():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    bind = geo.cfg().get("bind", "127.0.0.1")  # set "0.0.0.0" in config.json so tablets on other computers can sync
    with socketserver.ThreadingTCPServer((bind, geo.cfg()["port"]), H) as srv:
        print(f"ConfluenceEWS hub on http://{bind}:{geo.cfg()['port']}  (tablets POST /sync)")
        srv.serve_forever()
