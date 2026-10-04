"""SahelStore read-only status page (standard library only).

Design choice: the web page cannot change anything. Backups, restores and syncs run
from the command line on the server itself, so a stolen browser session cannot wipe
or restore data. The page is protected with HTTP Basic authentication over a PBKDF2
password hash and should sit behind HTTPS on a real network.
"""
import base64
import hashlib
import hmac
import html
import http.server
import os
import socketserver
import threading
import time

import demo
import sahel


def add_viewer(name, pw):
    salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 300_000).hex()
    with sahel.db() as con:
        con.execute("INSERT OR REPLACE INTO viewers VALUES(?,?,?)", (name, salt, h))


def check(header):
    try:
        name, pw = base64.b64decode(header.split(" ", 1)[1]).decode().split(":", 1)
    except Exception:  # noqa: BLE001
        return False
    with sahel.db() as con:
        r = con.execute("SELECT * FROM viewers WHERE name=?", (name,)).fetchone()
    if not r:
        return False
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(r["salt"]), 300_000).hex()
    return hmac.compare_digest(h, r["hash"])


def render():
    e = html.escape
    with sahel.db() as con:
        snaps = con.execute("SELECT * FROM snaps ORDER BY id DESC LIMIT 12").fetchall()
        pw = con.execute("SELECT * FROM power ORDER BY rowid DESC LIMIT 1").fetchone()
        health = con.execute("SELECT * FROM health").fetchall()
        logs = con.execute("SELECT * FROM log ORDER BY id DESC LIMIT 15").fetchall()
        q = con.execute("SELECT COUNT(*) n FROM queue").fetchone()["n"]
        tr = con.execute("SELECT SUM(file_bytes) f, SUM(sent_bytes) s FROM transfers").fetchone()
    saved = 100 * (1 - (tr["s"] or 0) / tr["f"]) if tr["f"] else 0
    budget = sahel.cfg()["daily_budget_mb"]
    rows = "".join(f"<tr><td>{s['id']}</td><td>{e(s['at'])}</td><td>{e(s['kind'])}</td><td>{s['files']}</td>"
                   f"<td>{s['new_objects'] or 0}</td><td class='{'g' if s['ok'] else 'r'}'>{'ok' if s['ok'] else 'REFUSED'}"
                   f"</td><td>{e(s['why'] or '')}</td></tr>" for s in snaps)
    hl = "".join(f"<li class='{'g' if h['up'] else 'r'}'>{e(h['name'])}: {'UP' if h['up'] else 'DOWN'}</li>" for h in health)
    lg = "".join(f"<tr><td>{e(r['at'])}</td><td class='{'r' if r['level']=='critical' else ''}'>{e(r['level'])}</td>"
                 f"<td>{e(r['msg'])}</td></tr>" for r in logs)
    power = f"{pw['percent']:.0f}% {'mains' if pw['plugged'] else 'ON BATTERY'}: {pw['action']}" if pw else "-"
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="10">
<meta name="viewport" content="width=device-width"><title>SahelStore</title><style>
body{{font-family:Consolas,monospace;background:#fefce8;color:#422006;margin:0}}h1{{background:#a16207;color:#fff;margin:0;padding:10px 16px;font-size:20px}}
.w{{padding:14px;max-width:1100px;margin:auto}}.b{{display:inline-block;background:#fff;border:1px solid #fde68a;padding:10px;margin:4px;min-width:200px;vertical-align:top}}
table{{border-collapse:collapse;width:100%;background:#fff}}td,th{{padding:4px;border-bottom:1px solid #fef3c7;font-size:13px;text-align:left}}.g{{color:#15803d}}.r{{color:#b91c1c;font-weight:bold}}
</style></head><body><h1>SahelStore &middot; {e(sahel.cfg()['institution']['name'])} (read-only status)</h1><div class="w">
<div class="b"><b>Power</b><br>{e(power)}</div><div class="b"><b>Services</b><ul>{hl}</ul></div>
<div class="b"><b>Offsite link</b><br>queue: {q} files<br>sent today: {sahel.sent_today() // 1024} KiB of {budget} MiB<br>
bandwidth saved by delta: {saved:.0f}%<br>window: {e(sahel.cfg()['offsite_window'])}</div>
<h3>Snapshots</h3><table><tr><th>#</th><th>Time</th><th>Kind</th><th>Files</th><th>New</th><th>State</th><th>Reason</th></tr>{rows}</table>
<h3>Log (hash chain {'INTACT' if sahel.log_ok() else 'BROKEN'})</h3><table>{lg}</table></div></body></html>"""


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if not check(self.headers.get("Authorization", "")):
            time.sleep(1)  # slows password guessing
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="SahelStore"')
            self.end_headers()
            return
        body = render().encode()
        self.send_response(200)
        for k, v in (("Content-Type", "text/html; charset=utf-8"), ("X-Frame-Options", "DENY"),
                     ("X-Content-Type-Options", "nosniff"), ("Cache-Control", "no-store")):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def scheduler():
    state = {}
    while True:
        try:
            if sahel.tick(state) == "normal":
                with sahel.db() as con:
                    if con.execute("SELECT 1 FROM health WHERE up=0").fetchone():
                        demo.portal(sahel.cfg()["portal_port"], background=True)
        except Exception as exc:  # noqa: BLE001
            sahel.log("warning", f"scheduler: {exc}")
        time.sleep(sahel.cfg()["tick_seconds"])


def serve():
    threading.Thread(target=scheduler, daemon=True).start()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", sahel.cfg()["port"]), H) as s:
        print(f"SahelStore status on http://127.0.0.1:{sahel.cfg()['port']} (read-only). Ctrl+C to stop.")
        s.serve_forever()
