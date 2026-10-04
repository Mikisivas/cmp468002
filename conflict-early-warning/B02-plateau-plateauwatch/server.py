"""PlateauWatch web server (standard library only). The map is drawn on the server as SVG,
so it works with no internet connection: useful in Bokkos or Wase where data is poor.

Security: PBKDF2 passwords, random session tokens (HttpOnly, SameSite=Strict), CSRF token
on every POST, 5-failure lockout, roles (coordinator can import data; observer can only view),
strict Content-Security-Policy, and every input validated before it reaches SQL (parameterised).
"""
import hashlib
import hmac
import html
import http.server
import math
import os
import secrets
import socketserver
import threading
import time
import urllib.parse

import geo
import kde

SESS, FAILS = {}, {}
E = html.escape
STYLE = """body{margin:0;font-family:Georgia,serif;background:#fdf4ff;color:#3b0764}header{background:#6b21a8;color:#fff;padding:10px 16px}
header a{color:#f5d0fe;margin-left:12px}main{max-width:1250px;margin:auto;padding:12px}.c{background:#fff;border-radius:8px;padding:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px;border-bottom:1px solid #f3e8ff;text-align:left}
.em{color:#b91c1c;font-weight:bold}button{background:#6b21a8;color:#fff;border:0;border-radius:5px;padding:6px 10px}
textarea{width:100%;height:140px;font-family:Consolas,monospace}"""


def pw_hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 300_000).hex()


def add_user(name, pw, role):
    salt = os.urandom(16).hex()
    with kde.db() as con:
        con.execute("INSERT OR REPLACE INTO users VALUES(?,?,?,?)", (name, salt, pw_hash(pw, salt), role))


def svg_map(days, analysis):
    now = time.time()
    pts = kde.incidents(now - days * 86400, now)
    grid, h = kde.density(pts)
    s, w, dlat, dlon, rows, cols = kde.raster()
    W, H = 760, int(760 * rows / cols * (dlat * 110.57) / (dlon * 111.32 * math.cos(math.radians(s))))
    cw, ch = W / cols, H / rows
    top = max((v for row in grid for v in row), default=0) or 1
    X = lambda lon: (lon - w) / (dlon * cols) * W  # noqa: E731
    Y = lambda lat: H - (lat - s) / (dlat * rows) * H  # noqa: E731
    out = [f'<svg viewBox="0 0 {W} {H}" style="width:100%;background:#f8fafc" xmlns="http://www.w3.org/2000/svg">']
    for r in range(rows):
        for c in range(cols):
            v = grid[r][c] / top
            if v > 0.03:
                red = int(255)
                g = int(240 - 200 * v)
                out.append(f'<rect x="{c * cw:.1f}" y="{H - (r + 1) * ch:.1f}" width="{cw + .5:.1f}" height="{ch + .5:.1f}" '
                           f'fill="rgb({red},{g},{int(200 - 190 * v)})" fill-opacity="{0.25 + 0.65 * v:.2f}"/>')
    for name, line in geo.cfg()["routes"].items():
        pts_s = " ".join(f"{X(lo):.1f},{Y(la):.1f}" for la, lo in line)
        out.append(f'<polyline points="{pts_s}" fill="none" stroke="#7c2d12" stroke-width="2" stroke-dasharray="6 5"><title>{E(name)}</title></polyline>')
    for p in pts:
        out.append(f'<circle cx="{X(p["lon"]):.1f}" cy="{Y(p["lat"]):.1f}" r="2" fill="#111"/>')
    for g in geo.lgas():
        out.append(f'<circle cx="{X(g["lon"]):.1f}" cy="{Y(g["lat"]):.1f}" r="4" fill="#6b21a8"/>'
                   f'<text x="{X(g["lon"]) + 6:.1f}" y="{Y(g["lat"]) - 4:.1f}" font-size="12">{E(g["name"])}</text>')
    for hs in analysis["hotspots"]:
        col = "#dc2626" if hs["status"] == "emerging" else "#9333ea"
        out.append(f'<circle cx="{X(hs["lon"]):.1f}" cy="{Y(hs["lat"]):.1f}" r="14" fill="none" stroke="{col}" stroke-width="3">'
                   f'<title>{E(hs["status"])} hotspot near {E(hs["lga"])}</title></circle>')
    out.append(f'<text x="8" y="{H - 8}" font-size="11">Gaussian KDE, bandwidth {h:.1f} km (Silverman), last {days} days, '
               f'{len(pts)} incidents. Red ring = emerging hotspot, purple = persistent.</text></svg>')
    return "".join(out)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def sess(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "pw" and v in SESS and SESS[v]["exp"] > time.time():
                SESS[v]["exp"] = time.time() + 1800
                return SESS[v]
        return None

    def out(self, body, code=200, extra=None):
        data = (f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
                f"<title>PlateauWatch</title><style>{STYLE}</style></head><body><header><b>PlateauWatch</b> &middot; "
                f"Plateau State hotspot early warning <a href='/'>Map</a><a href='/hotspots'>Hotspots</a>"
                f"<a href='/data'>Data</a><a href='/logout'>Sign out</a></header><main>{body}</main></body></html>").encode()
        self.send_response(code)
        for k, v in [("Content-Type", "text/html; charset=utf-8"), ("X-Frame-Options", "DENY"),
                     ("X-Content-Type-Options", "nosniff"),
                     ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:"),
                     ("Content-Length", str(len(data)))] + list((extra or {}).items()):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def go(self, where, extra=None):
        self.send_response(303)
        self.send_header("Location", where)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        s = self.sess()
        if u.path == "/logout":
            for k in [k for k, v in SESS.items() if v is s]:
                SESS.pop(k)
            return self.go("/login", {"Set-Cookie": "pw=; Max-Age=0; Path=/"})
        if not s or u.path == "/login":
            return self.out("<div class='c' style='max-width:320px'><h3>Sign in</h3><form method='post' action='/login'>"
                            "User<br><input name='u'><br>Password<br><input type='password' name='p'><br><br>"
                            "<button>Sign in</button></form></div>")
        if u.path == "/hotspots":
            with kde.db() as con:
                hs = con.execute("SELECT * FROM hotspots ORDER BY density DESC").fetchall()
                al = con.execute("SELECT * FROM alerts ORDER BY at DESC LIMIT 20").fetchall()
            rows = "".join(f"<tr><td class='{'em' if h['status'] == 'emerging' else ''}'>{E(h['status'])}</td><td>{E(h['lga'])}</td>"
                           f"<td>{h['lat']}, {h['lon']}</td><td>{h['density'] * 1000:.2f}</td></tr>" for h in hs)
            alerts = "".join(f"<tr><td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(a['at']))}</td><td>{E(a['text'])}</td></tr>" for a in al)
            return self.out(f"<div class='c'><h3>Hotspots (last 30 days vs the 30 before)</h3><table><tr><th>Status</th><th>Near</th>"
                            f"<th>Location</th><th>Density x1000</th></tr>{rows}</table></div><div class='c'><h3>Alerts</h3><table>{alerts}</table></div>")
        if u.path == "/data":
            form = ""
            if s["role"] == "coordinator":
                form = (f"<div class='c'><h3>Import incidents (CSV)</h3><p>date,lga,type,severity[,lat,lon]. Types: "
                        f"{', '.join(geo.TYPES)}</p><form method='post' action='/import'><input type='hidden' name='csrf' "
                        f"value='{s['csrf']}'><textarea name='csv'>date,lga,type,severity\n</textarea><button>Import</button></form></div>")
            with kde.db() as con:
                rows = con.execute("SELECT * FROM incidents ORDER BY ts DESC LIMIT 40").fetchall()
            t = "".join(f"<tr><td>{time.strftime('%Y-%m-%d', time.localtime(r['ts']))}</td><td>{E(r['lga'])}</td><td>{E(r['type'])}</td>"
                        f"<td>{r['severity']}</td><td>{E(r['source'])}</td></tr>" for r in rows)
            return self.out(form + f"<div class='c'><h3>Latest incidents</h3><table>{t}</table></div>")
        try:
            days = int(q.get("days", ["30"])[0])
        except ValueError:
            days = 30
        days = days if days in (7, 30, 90) else 30
        an = kde.analyse()
        links = " ".join(f"<a href='/?days={d}'>{'<b>' if d == days else ''}last {d} days{'</b>' if d == days else ''}</a>" for d in (7, 30, 90))
        return self.out(f"<div class='c'>{links}</div><div class='c'>{svg_map(days, an)}</div>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        if n > 200_000:
            return self.out("too large", 413)
        f = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
        if self.path == "/login":
            ip = self.client_address[0]
            FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
            with kde.db() as con:
                u = con.execute("SELECT * FROM users WHERE name=?", (f.get("u", ""),)).fetchone()
            if len(FAILS[ip]) < 5 and u and hmac.compare_digest(pw_hash(f.get("p", ""), u["salt"]), u["hash"]):
                tok = secrets.token_urlsafe(32)
                SESS[tok] = {"user": u["name"], "role": u["role"], "csrf": secrets.token_urlsafe(16), "exp": time.time() + 1800}
                kde.audit(u["name"], "sign in")
                return self.go("/", {"Set-Cookie": f"pw={tok}; HttpOnly; SameSite=Strict; Path=/"})
            FAILS[ip].append(time.time())
            return self.out("<div class='c'>Sign-in failed. <a href='/login'>Try again</a></div>", 401)
        s = self.sess()
        if not s or not secrets.compare_digest(f.get("csrf", ""), s["csrf"]):
            return self.out("<div class='c'>Forbidden</div>", 403)
        if self.path == "/import" and s["role"] == "coordinator":
            r = kde.import_csv(f.get("csv", ""), s["user"])
            return self.out(f"<div class='c'>Imported {r['imported']} rows.<br>{'<br>'.join(E(x) for x in r['rejected'])}</div>")
        return self.out("<div class='c'>Forbidden</div>", 403)


def serve():
    def loop():
        while True:
            try:
                kde.analyse()
            except Exception as exc:  # noqa: BLE001
                print("analysis:", exc)
            time.sleep(300)
    threading.Thread(target=loop, daemon=True).start()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", geo.cfg()["port"]), H) as srv:
        print(f"PlateauWatch on http://127.0.0.1:{geo.cfg()['port']} (works offline). Ctrl+C to stop.")
        srv.serve_forever()
