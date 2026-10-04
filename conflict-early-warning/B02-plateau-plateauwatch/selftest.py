"""PlateauWatch end-to-end test. Resets demo data first. Results in results/selftest.json."""
import http.client
import json
import os
import re
import threading
import time
import urllib.parse

import geo
import kde
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    s = cli.setup()
    res["setup"] = s
    pts = [{"lat": 9.5, "lon": 9.0, "severity": 1}]
    grid, h = kde.density(pts, h=5.0)
    st, w, dlat, dlon, rows, cols = kde.raster()
    cell_area = (dlat * 110.57) * (dlon * 111.32 * 0.987)
    mass = sum(sum(r) for r in grid) * cell_area
    case("Gaussian kernel integrates to about 1 (correct normalisation)", 0.9 < mass < 1.1, f"{mass:.3f}")
    case("Silverman bandwidth computed from data", s["analysis"]["bandwidth_km"] > 2, s["analysis"]["bandwidth_km"])
    p = kde.pai()
    res["pai"] = p
    case("Predictive Accuracy Index above 1 (better than random)", p["pai"] and p["pai"] > 1, p)

    before = {h["lga"] for h in kde.analyse()["hotspots"]}
    t0 = time.time()
    after = cli.flare("Kanam")
    res["analysis_seconds"] = round(time.time() - t0, 3)
    res["flare"] = after
    em = [lga for lga, st_ in after["hotspots"] if st_ == "emerging"]
    case("New wave in quiet Kanam appears as an EMERGING hotspot", "Kanam" in em and "Kanam" not in before, after["hotspots"])
    with kde.db() as con:
        al = con.execute("SELECT * FROM alerts WHERE lga='Kanam'").fetchall()
    case("Emerging hotspot raises one alert", len(al) == 1, al[0]["text"] if al else "")
    kde.analyse()
    with kde.db() as con:
        case("No duplicate alert within 24 h", con.execute("SELECT COUNT(*) FROM alerts WHERE lga='Kanam'").fetchone()[0] == 1)

    r = kde.import_csv("date,lga,type,severity\n2026-09-01,Bokkos,armed_attack,4\n2026-09-02,Atlantis,threat,2\n"
                       "2026-09-03,Mangu,armed_attack,9\n2026-09-04,Mangu,threat,2,6.0,3.0\n2026-09-05,Riyom,'; DROP TABLE incidents;--,2", "test")
    case("CSV import accepts good rows and rejects bad ones with reasons", r["imported"] == 1 and len(r["rejected"]) == 4, r)
    with kde.db() as con:
        case("SQL injection attempt stored nothing harmful (table intact)", con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] > 100)

    import server
    srv = server.socketserver.ThreadingTCPServer(("127.0.0.1", 0), server.H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def req(method, path, body=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        hdr = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            hdr["Cookie"] = cookie
        c.request(method, path, urllib.parse.urlencode(body) if body else None, hdr)
        r = c.getresponse()
        return r.status, r.getheader("Set-Cookie"), r.read().decode()

    st_, ck, _ = req("POST", "/login", {"u": "observer", "p": "ChangeMe@468"})
    cookie = ck.split(";")[0]
    st2, _, page = req("GET", "/?days=30", cookie=cookie)
    case("Offline SVG map renders without any external resource", st2 == 200 and "<svg" in page and
         not re.search(r"(src|href)=[\"']https?:", page))
    _, _, data_page = req("GET", "/data", cookie=cookie)
    case("Observer sees no import form", "Import incidents" not in data_page)
    st3, _, _ = req("POST", "/import", {"csv": "x", "csrf": "wrong"}, cookie=cookie)
    case("Import without valid CSRF token is refused", st3 == 403)
    codes = [req("POST", "/login", {"u": "coordinator", "p": "bad"})[0] for _ in range(6)]
    st4, _, _ = req("POST", "/login", {"u": "coordinator", "p": "ChangeMe@468"})
    case("Login locks after 5 failures", st4 == 401, codes)
    srv.shutdown()

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
