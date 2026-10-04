"""ConfluenceEWS field tablet (simulated). Each tablet keeps its own SQLite queue and works with no
network at all. `sync` sends the queue when a connection is available.

    python field.py add --device KG-TAB-03 --lga Omala --type armed_attack --severity 4 --note "..."
    python field.py sync --device KG-TAB-03
"""
import argparse
import json
import os
import sqlite3
import time
import urllib.error
import urllib.request
import uuid

import geo
import hub


class Tablet:
    def __init__(self, device, folder=None):
        self.device = device
        self.folder = folder or os.path.join(hub.DATA, "tablets", device)
        os.makedirs(self.folder, exist_ok=True)
        self.con = sqlite3.connect(os.path.join(self.folder, "tablet.db"))
        self.con.row_factory = sqlite3.Row
        self.con.executescript("""
        CREATE TABLE IF NOT EXISTS queue(uuid TEXT PRIMARY KEY, created REAL, edited REAL, version INT, lga TEXT, type TEXT, severity INT,
            note TEXT, synced INT DEFAULT 0);
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
        """)

    def meta(self, k, default=None):
        r = self.con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else default

    def set_meta(self, k, v):
        self.con.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, str(v)))
        self.con.commit()

    def add(self, lga_name, kind, severity, note="", created=None):
        u = str(uuid.uuid4())
        t = created or time.time()
        self.con.execute("INSERT INTO queue VALUES(?,?,?,?,?,?,?,?,0)", (u, t, t, 1, lga_name, kind, severity, note))
        self.con.commit()
        return u

    def edit(self, u, **changes):
        r = self.con.execute("SELECT * FROM queue WHERE uuid=?", (u,)).fetchone()
        sets = ", ".join(f"{k}=?" for k in changes)
        self.con.execute(f"UPDATE queue SET {sets}, version=?, edited=?, synced=0 WHERE uuid=?",
                         (*changes.values(), r["version"] + 1, time.time(), u))
        self.con.commit()

    def pending(self):
        return [dict(r) for r in self.con.execute("SELECT * FROM queue WHERE synced=0")]

    def build(self):
        counter = int(self.meta("counter", 0)) + 1
        self.set_meta("counter", counter)
        reps = [{k: r[k] for k in ("uuid", "created", "edited", "version", "lga", "type", "severity", "note")} for r in self.pending()]
        return json.dumps({"device": self.device, "counter": counter, "reports": reps}, sort_keys=True).encode()

    def apply_reply(self, reply):
        self.con.executemany("UPDATE queue SET synced=1 WHERE uuid=?", [(u,) for u in reply["acked"]])
        self.set_meta("risk", json.dumps(reply["risk"]))
        self.set_meta("last_sync", time.time())
        self.con.commit()

    def sync(self, url=None, transport=None, drop_reply=False):
        """Send the queue. `transport` lets tests call the hub directly; `drop_reply` simulates the
        network failing after the hub received the data but before the tablet heard back."""
        body = self.build()
        sig = hub.sign(self.meta("key"), body)
        if transport:
            code, reply = transport(body, sig)
        else:
            req = urllib.request.Request((url or self.meta("hub")) + "/sync", data=body, method="POST",
                                         headers={"Content-Type": "application/json", "X-Sig": sig})
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    code, reply = r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                code, reply = e.code, json.loads(e.read())
            except OSError as e:
                return {"offline": True, "error": str(e), "pending": len(self.pending())}
        if drop_reply:
            return {"lost_reply": True, "pending": len(self.pending())}
        if code == 200:
            self.apply_reply(reply)
        return {"code": code, **{k: v for k, v in reply.items() if k != "risk"}, "pending": len(self.pending())}


def provision(device, officer, lga_name, hub_url):
    key = hub.register(device, officer, lga_name)
    t = Tablet(device)
    t.set_meta("key", key)
    t.set_meta("hub", hub_url)
    return t


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="ConfluenceEWS field tablet")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a1 = sub.add_parser("add")
    a1.add_argument("--device", required=True)
    a1.add_argument("--lga", required=True)
    a1.add_argument("--type", required=True, choices=list(geo.TYPES))
    a1.add_argument("--severity", type=int, required=True)
    a1.add_argument("--note", default="")
    a2 = sub.add_parser("sync")
    a2.add_argument("--device", required=True)
    a3 = sub.add_parser("show")
    a3.add_argument("--device", required=True)
    a = ap.parse_args()
    t = Tablet(a.device)
    if a.cmd == "add":
        print("queued", t.add(a.lga, a.type, a.severity, a.note))
    elif a.cmd == "sync":
        print(t.sync())
    else:
        print({"pending": len(t.pending()), "last_sync": t.meta("last_sync"), "risk": json.loads(t.meta("risk", "{}"))})
