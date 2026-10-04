"""Demo helpers: seed realistic records for the institution in config.json, run a
small "student portal" service to monitor, and simulate SAFE ransomware.

Every destructive action is restricted to the demo data folder inside this project.
"""
import csv
import hashlib
import http.server
import json
import os
import random
import socketserver
import subprocess
import sys
import threading

BASE = os.path.dirname(os.path.abspath(__file__))

SURNAMES = ["Adeyemi", "Okafor", "Bello", "Ibrahim", "Eze", "Ogunleye", "Musa", "Nwosu", "Abubakar", "Olawale",
            "Chukwu", "Danjuma", "Akinola", "Usman", "Obi", "Yakubu", "Adebayo", "Okonkwo", "Aliyu", "Ojo",
            "Garba", "Afolabi", "Sani", "Balogun", "Tiv", "Iorliam", "Ekpo", "Etim", "Lawal", "Shehu"]
FIRST = ["Tope", "Chiamaka", "Aisha", "Emeka", "Fatima", "Tunde", "Ngozi", "Yusuf", "Bisi", "Ifeanyi", "Halima",
         "Segun", "Amaka", "Sadiq", "Kemi", "Obinna", "Zainab", "Femi", "Chidi", "Hauwa", "Terver", "Ese"]


def _cfg():
    with open(os.path.join(BASE, "config.json")) as fh:
        return json.load(fh)


def source_dir():
    src = _cfg()["source"]
    return src if os.path.isabs(src) else os.path.join(BASE, src)


def _safe(root):
    root = os.path.realpath(root)
    if not root.startswith(os.path.realpath(BASE)):
        raise SystemExit("Safety stop: simulations only run inside the project folder.")
    return root


def seed(students=600, seed_value=468):
    inst = _cfg()["institution"]
    rnd = random.Random(seed_value)
    root = source_dir()
    for sub in ("registry", "bursary", "results", "lms", "staff"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    matric = [inst["matric_format"].format(year=2021 + i % 5, n=1000 + i) for i in range(students)]
    with open(os.path.join(root, "registry", "students.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["matric_no", "surname", "first_name", "department", "level", "state", "phone"])
        for m in matric:
            w.writerow([m, rnd.choice(SURNAMES), rnd.choice(FIRST), rnd.choice(inst["departments"]),
                        rnd.choice([100, 200, 300, 400, 500]), rnd.choice(inst["states"]),
                        "080" + str(rnd.randint(10000000, 99999999))])
    with open(os.path.join(root, "bursary", "fees_2025_2026.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["matric_no", "remita_rrr", "amount_ngn", "status"])
        for m in matric:
            w.writerow([m, rnd.randint(10**11, 10**12 - 1), rnd.choice([45000, 68000, 95000, 150000]),
                        rnd.choice(["PAID", "PAID", "PAID", "PENDING"])])
    for course in inst["courses"]:
        with open(os.path.join(root, "results", f"{course}_results.csv"), "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["matric_no", "ca", "exam", "total", "grade"])
            for m in matric[::3]:
                ca, ex = rnd.randint(10, 40), rnd.randint(20, 60)
                t = ca + ex
                w.writerow([m, ca, ex, t, "A" if t >= 70 else "B" if t >= 60 else "C" if t >= 50 else
                            "D" if t >= 45 else "F"])
    for n in range(1, 9):
        with open(os.path.join(root, "lms", f"{inst['courses'][0]}_lecture_{n:02d}.txt"), "w") as fh:
            fh.write(f"{inst['short']} {inst['courses'][0]} lecture {n}\n" + "Lecture notes text. " * 300)
    with open(os.path.join(root, "staff", "payroll.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["staff_id", "name", "grade", "net_pay_ngn"])
        for i in range(80):
            w.writerow([f"{inst['short']}-SP{3000 + i}", rnd.choice(FIRST) + " " + rnd.choice(SURNAMES),
                        f"CONUASS {rnd.randint(1, 7)}", rnd.randint(150000, 900000)])
    return root


def fingerprint(root=None):
    root = root or source_dir()
    out = {}
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            p = os.path.join(r, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root).replace("\\", "/")] = hashlib.sha256(fh.read()).hexdigest()
    return out


def attack(root=None):
    """Loud ransomware: encrypt, rename to .locked, drop a ransom note."""
    root = _safe(root or source_dir())
    hit = 0
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            if f.endswith(".locked"):
                continue
            p = os.path.join(r, f)
            with open(p, "rb") as fh:
                data = fh.read()
            with open(p + ".locked", "wb") as fh:
                fh.write(bytes(a ^ b for a, b in zip(data, os.urandom(len(data)))))
            os.remove(p)
            hit += 1
    with open(os.path.join(root, "READ_ME_TO_DECRYPT.txt"), "w") as fh:
        fh.write("Your files are encrypted. Pay 2 BTC. (CMP 468 classroom simulation, not real)\n")
    return hit


def stealth(root=None, n=6):
    """Quiet ransomware: overwrite CSV files with random bytes but keep their names."""
    root = _safe(root or source_dir())
    victims = []
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        victims += [os.path.join(r, f) for f in files if f.endswith(".csv")]
    for p in sorted(victims)[:n]:
        size = os.path.getsize(p)
        with open(p, "wb") as fh:
            fh.write(os.urandom(size))
    return min(n, len(victims))


class _Portal(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}' if self.path == "/health" else b"<h1>Student portal (demo)</h1>"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def portal(port, background=False, thread=False):
    if background:
        flags = 0x00000008 if os.name == "nt" else 0  # DETACHED_PROCESS on Windows
        subprocess.Popen([sys.executable, os.path.abspath(__file__), "portal", str(port)], cwd=BASE,
                         creationflags=flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return None
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), _Portal)
    if thread:  # used by selftest.py inside the same process
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv
    os.makedirs(os.path.join(BASE, "data"), exist_ok=True)
    with open(os.path.join(BASE, "data", "portal.pid"), "w") as fh:
        fh.write(str(os.getpid()))
    srv.serve_forever()


def stop_portal():
    """Simulate an outage by killing the demo portal process."""
    pid_file = os.path.join(BASE, "data", "portal.pid")
    if not os.path.exists(pid_file):
        return False
    with open(pid_file) as fh:
        pid = int(fh.read().strip())
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
        else:
            os.kill(pid, 15)
    except OSError:
        return False
    os.remove(pid_file)
    return True


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "portal":
    portal(int(sys.argv[2]))
