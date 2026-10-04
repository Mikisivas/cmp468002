"""IfeSentinel agent. Copy this file, demo.py, config.json and requirements.txt to any
computer (lab PC, bursary PC, registry server) and run:

    python agent.py enrol --name BURSARY-PC1 --server http://SERVER-IP:5104 --token <one-time token> --folder D:\\Bursary
    python agent.py run --name BURSARY-PC1

What the agent does on each cycle:
  1. reads CPU, memory and disk and sends a signed heartbeat;
  2. checks its canary (decoy) files; if one changed it reports at once and stops uploading;
  3. on the backup interval, zips the files that changed, encrypts them with AES-256-GCM using a
     key that never leaves this computer, and uploads the ciphertext.
"""
import argparse
import hashlib
import hmac
import io
import json
import os
import shutil
import time
import urllib.request
import uuid
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = os.path.dirname(os.path.abspath(__file__))
CANARY_NAMES = ["!000_Staff_Salaries_2026.xlsx", "!000_Admission_List_FINAL.docx"]


class Agent:
    def __init__(self, name, home=None):
        self.name = name
        self.home = home or os.path.join(BASE, "data", "agents", name)
        with open(os.path.join(self.home, "agent.json")) as fh:
            self.conf = json.load(fh)
        self.folder = self.conf["folder"]

    # ---------------------------------------------------------- transport
    def call(self, path, body=b"", headers=None, raw=False):
        ts, nonce = str(time.time()), uuid.uuid4().hex
        msg = f"POST|{path}|{ts}|{nonce}|{hashlib.sha256(body).hexdigest()}".encode()
        sig = hmac.new(bytes.fromhex(self.conf["secret"]), msg, "sha256").hexdigest()
        h = {"X-Agent": self.name, "X-Time": ts, "X-Nonce": nonce, "X-Sig": sig,
             "Content-Type": "application/octet-stream"}
        h.update(headers or {})
        req = urllib.request.Request(self.conf["server"] + path, data=body, headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
        return data if raw else json.loads(data)

    # ---------------------------------------------------------- canaries
    def deploy_canaries(self):
        hashes = {}
        for sub in [""] + [d for d in sorted(os.listdir(self.folder)) if os.path.isdir(os.path.join(self.folder, d))]:
            for n in CANARY_NAMES:
                pth = os.path.join(self.folder, sub, n)
                with open(pth, "wb") as fh:
                    fh.write(b"PK\x03\x04" + os.urandom(16) + b"decoy file, do not open" * 20)
                with open(pth, "rb") as fh:
                    hashes[os.path.relpath(pth, self.folder)] = hashlib.sha256(fh.read()).hexdigest()
        self.conf["canaries"] = hashes
        self.save()

    def canaries_ok(self):
        for rel, h in self.conf.get("canaries", {}).items():
            pth = os.path.join(self.folder, rel)
            if not os.path.exists(pth):
                return False, f"{rel} deleted or renamed"
            with open(pth, "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != h:
                    return False, f"{rel} modified"
        return True, ""

    def save(self):
        with open(os.path.join(self.home, "agent.json"), "w") as fh:
            json.dump(self.conf, fh, indent=1)

    # ---------------------------------------------------------- backup
    def scan(self):
        out = {}
        for root, dirs, files in os.walk(self.folder):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                p = os.path.join(root, f)
                with open(p, "rb") as fh:
                    out[os.path.relpath(p, self.folder).replace("\\", "/")] = hashlib.sha256(fh.read()).hexdigest()
        return out

    def backup(self, full=False):
        current = self.scan()
        prev = {} if full else self.conf.get("last_hashes", {})
        changed = [k for k, h in current.items() if prev.get(k) != h]
        garbled = []
        for rel in changed:
            if rel.lower().endswith((".csv", ".txt", ".sql")):
                try:
                    open(os.path.join(self.folder, rel), "rb").read().decode("utf-8")
                except UnicodeDecodeError:
                    garbled.append(rel)
        if len(garbled) >= 2:
            if not self.conf.get("tripped"):
                self.call("/agent/canary", json.dumps({"detail": f"{len(garbled)} text files became binary "
                                                                  f"(e.g. {garbled[0]})"}).encode())
                self.conf["tripped"] = True
                self.save()
            return {"status": "held", "garbled": len(garbled)}
        if not changed and not full:
            return {"status": "nothing changed"}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for rel in changed:
                z.write(os.path.join(self.folder, rel), rel)
            z.writestr("__manifest__.json", json.dumps(current))
        nonce = os.urandom(12)
        aad = self.name.encode()
        blob = nonce + AESGCM(bytes.fromhex(self.conf["data_key"])).encrypt(nonce, buf.getvalue(), aad)
        r = self.call("/agent/upload", blob, {"X-Kind": "full" if (full or not prev) else "incremental",
                                              "X-Files": str(len(changed))})
        if r["trusted"]:
            self.conf["last_hashes"] = current
            self.save()
        return {"status": "uploaded", "id": r["id"], "files": len(changed), "bytes": len(blob),
                "trusted": bool(r["trusted"])}

    def restore(self, target=None):
        """Replay the newest trusted full backup and every trusted incremental after it."""
        t0 = time.time()
        cat = [b for b in self.call("/agent/catalogue") if b["trusted"]]
        start = max(i for i, b in enumerate(cat) if b["kind"] == "full")
        staged, manifest = {}, {}
        aes = AESGCM(bytes.fromhex(self.conf["data_key"]))
        for b in cat[start:]:
            blob = self.call(f"/agent/blob/{b['id']}", raw=True)
            if hashlib.sha256(blob).hexdigest() != b["sha256"]:
                raise ValueError(f"blob {b['id']} damaged in transit")
            with zipfile.ZipFile(io.BytesIO(aes.decrypt(blob[:12], blob[12:], self.name.encode()))) as z:
                manifest = json.loads(z.read("__manifest__.json"))
                for n in z.namelist():
                    if n != "__manifest__.json":
                        staged[n] = z.read(n)
        target = target or self.folder
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), target).replace("\\", "/")
                if rel not in manifest:
                    os.remove(os.path.join(root, f))
        for rel, h in manifest.items():
            data = staged[rel]
            if hashlib.sha256(data).hexdigest() != h:
                raise ValueError(f"{rel} failed its hash check")
            out = os.path.join(target, *rel.split("/"))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "wb") as fh:
                fh.write(data)
        if target == self.folder:
            self.conf["last_hashes"] = manifest
            self.conf["tripped"] = False
            self.save()
        return {"files": len(manifest), "blobs_used": len(cat) - start, "seconds": round(time.time() - t0, 3)}

    # ---------------------------------------------------------- loop
    def heartbeat(self):
        try:
            import psutil
            cpu, mem = psutil.cpu_percent(interval=0.2), psutil.virtual_memory().percent
        except ImportError:
            cpu = mem = 0.0
        du = shutil.disk_usage(self.folder)
        body = json.dumps({"cpu": cpu, "mem": mem, "disk": round(du.used / du.total * 100, 1),
                           "files": len(self.scan())}).encode()
        return self.call("/agent/heartbeat", body)

    def cycle(self, do_backup):
        if os.path.exists(os.path.join(self.home, "PAUSED")):
            return "paused"  # demo switch: simulates a powered-off or disconnected computer
        ok, why = self.canaries_ok()
        if not ok:
            if not self.conf.get("tripped"):
                self.call("/agent/canary", json.dumps({"detail": why}).encode())
                self.conf["tripped"] = True
                self.save()
            return "isolated"
        state = self.heartbeat()["state"]
        if state != "isolated" and do_backup:
            self.backup()
        return state

    def run(self, heartbeat_s, backup_min, stop=None):
        last = 0.0
        while not (stop and stop.is_set()):
            try:
                due = time.time() - last > backup_min * 60
                self.cycle(due)
                if due:
                    last = time.time()
            except Exception as exc:  # noqa: BLE001
                print(f"[{self.name}] {exc}")
            time.sleep(heartbeat_s)


def enrol(name, server, token, folder, home=None):
    home = home or os.path.join(BASE, "data", "agents", name)
    os.makedirs(home, exist_ok=True)
    req = urllib.request.Request(server + "/agent/enrol", data=json.dumps({"token": token, "name": name}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        secret = json.loads(r.read())["secret"]
    with open(os.path.join(home, "agent.json"), "w") as fh:
        json.dump({"server": server, "secret": secret, "data_key": os.urandom(32).hex(), "folder": folder}, fh)
    a = Agent(name, home)
    a.deploy_canaries()
    return a


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="IfeSentinel agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enrol")
    for k in ("--name", "--server", "--token", "--folder"):
        e.add_argument(k, required=True)
    for n in ("run", "backup", "restore"):
        s = sub.add_parser(n)
        s.add_argument("--name", required=True)
    a = ap.parse_args()
    with open(os.path.join(BASE, "config.json")) as fh:
        c = json.load(fh)
    if a.cmd == "enrol":
        enrol(a.name, a.server, a.token, os.path.abspath(a.folder))
        print("enrolled; keep data/agents/<name>/agent.json safe: it holds this computer's data key")
    elif a.cmd == "run":
        Agent(a.name).run(c["heartbeat_seconds"], c["backup_minutes"])
    elif a.cmd == "backup":
        print(Agent(a.name).backup())
    elif a.cmd == "restore":
        print(Agent(a.name).restore())
