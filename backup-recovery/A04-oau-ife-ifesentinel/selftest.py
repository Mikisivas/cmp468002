"""IfeSentinel end-to-end test (server + 3 agents in one process). Resets demo data first."""
import hashlib
import json
import os
import time
import urllib.error
import urllib.request

import demo
import main as cli
import server
from agent import Agent

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def status(name):
    with server.db() as con:
        return con.execute("SELECT state FROM agents WHERE name=?", (name,)).fetchone()["state"]


def http_code(fn):
    try:
        fn()
        return 200
    except urllib.error.HTTPError as e:
        return e.code


def run():
    res = {}
    first = cli.setup(start_server=True)
    res["initial_full_backups"] = first
    agents = {a["name"]: Agent(a["name"]) for a in server.cfg()["demo_agents"]}
    reg, bur, lab = agents["REGISTRY-SRV"], agents["BURSARY-PC1"], agents["CSE-LAB-07"]
    for ag in agents.values():
        ag.cycle(False)
    case("Three agents enrolled and online", all(status(n) == "online" for n in agents))
    res["dataset_files_per_agent"] = len(reg.scan())

    url = server.cfg()["server_url"]
    case("Enrolment token cannot be reused", http_code(lambda: urllib.request.urlopen(urllib.request.Request(
        url + "/agent/enrol", data=b'{"token":"made-up","name":"EVIL"}', headers={"Content-Type": "application/json"},
        method="POST"))) == 403)
    fake = Agent("CSE-LAB-07")
    fake.conf = dict(fake.conf, secret="00" * 32)
    case("Forged signature rejected", http_code(lambda: fake.heartbeat()) == 401)
    def raw(ag, ts, nonce):
        import hmac
        body = json.dumps({"cpu": 1, "mem": 1, "disk": 1}).encode()
        msg = f"POST|/agent/heartbeat|{ts}|{nonce}|{hashlib.sha256(body).hexdigest()}".encode()
        sig = hmac.new(bytes.fromhex(ag.conf["secret"]), msg, "sha256").hexdigest()
        req = urllib.request.Request(url + "/agent/heartbeat", data=body, method="POST", headers={
            "X-Agent": ag.name, "X-Time": str(ts), "X-Nonce": nonce, "X-Sig": sig})
        return http_code(lambda: urllib.request.urlopen(req).read())
    case("Stale (captured and replayed later) request rejected", raw(lab, time.time() - 600, "n-old") == 401)
    raw(lab, time.time(), "n-same")
    code = raw(lab, time.time(), "n-same")
    case("Repeated nonce rejected", code == 409)

    with open(os.path.join(reg.folder, "registry", "students.csv"), "a") as fh:
        fh.write("CSC/2026/9999,New,Student,Chemistry,100,Osun,08000000000\n")
    inc = reg.backup()
    res["incremental_backup"] = inc
    case("Incremental upload carries only the changed file", inc["files"] == 1, inc)
    good = demo.fingerprint(reg.folder)

    blob_dir = os.path.join(server.SDATA, "blobs", "REGISTRY-SRV")
    sample = open(os.path.join(blob_dir, sorted(os.listdir(blob_dir))[0]), "rb").read()
    case("Server stores ciphertext only (no readable records)", b"matric_no" not in sample and b"students" not in sample)

    hit = demo.attack(reg.folder)
    st = reg.cycle(True)
    case("Loud attack trips a canary and the agent is isolated", st == "isolated" and status("REGISTRY-SRV") == "isolated")
    up = reg.backup(full=True)
    case("Uploads after the trip are marked untrusted", up.get("trusted") is False, up)
    t0 = time.time()
    r = reg.restore()
    rto = time.time() - t0
    same = demo.fingerprint(reg.folder) == good
    res["recovery"] = {"files_encrypted": hit, "files_restored": r["files"], "blobs_used": r["blobs_used"],
                       "rto_seconds": round(rto, 3), "byte_identical": same}
    case("Restore skips untrusted uploads and is byte-identical", same, f"RTO {rto:.3f} s")
    ok, _ = reg.canaries_ok()
    case("Canaries are intact again after restore", ok)

    bgood = demo.fingerprint(bur.folder)
    demo.stealth(bur.folder)
    held = bur.backup()
    case("Quiet attack (text files turned binary) is held and reported", held["status"] == "held" and
         status("BURSARY-PC1") == "isolated", held)
    bur.restore()
    case("Bursary restore is byte-identical", demo.fingerprint(bur.folder) == bgood)

    victim = os.path.join(server.SDATA, "blobs", "CSE-LAB-07", sorted(os.listdir(os.path.join(server.SDATA, "blobs",
                                                                                               "CSE-LAB-07")))[0])
    data = bytearray(open(victim, "rb").read())
    data[50] ^= 1
    open(victim, "wb").write(bytes(data))
    case("Tampered blob on the server is detected at restore", http_code(lambda: lab.restore()) == 500)

    with server.db() as con:
        con.execute("UPDATE agents SET last_seen=? WHERE name='CSE-LAB-07'", (time.time() - 3600,))
    server.sweep()
    case("Silent computer marked OFFLINE after 3 missed heartbeats", status("CSE-LAB-07") == "offline")
    lab.cycle(False)
    case("Computer back online after next heartbeat", status("CSE-LAB-07") == "online")

    server.app.secret_key = "t"
    cl = server.app.test_client()
    cl.post("/login", data={"u": "helpdesk", "p": "ChangeMe@468"})
    case("Read-only helpdesk cannot release an isolated computer",
         cl.post("/release", data={"agent": "REGISTRY-SRV"}).status_code == 403)
    with server.db() as con:
        res["blobs_on_server"] = con.execute("SELECT COUNT(*) n, SUM(size) s FROM blobs").fetchone()["n"]
    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(server.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(server.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")


if __name__ == "__main__":
    run()
    os._exit(0)
