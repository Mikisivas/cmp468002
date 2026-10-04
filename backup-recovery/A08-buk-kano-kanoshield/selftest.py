"""KanoShield end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import sqlite3
import time

import demo
import main as cli
import shield as s

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    first, secrets_ = cli.setup()
    src = demo.source_dir()
    good = demo.fingerprint()
    res["dataset_files"] = len(good)
    res["dataset_bytes"] = sum(os.path.getsize(os.path.join(src, k)) for k in good)
    res["backup"] = first
    case("Backup sealed into the WORM vault", first["status"] == "ok", first)

    case("RFC 6238 test vector (SHA-1, T=59 s) gives 287082",
         s.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", at=59) == "287082")
    sec = secrets_["ictdirector"]
    case("Admin sign-in fails without the authenticator code", s.authenticate("ictdirector", "ChangeMe@468", "") is None)
    case("Admin sign-in works with password + current code",
         s.authenticate("ictdirector", "ChangeMe@468", s.totp(sec)) == "admin")
    for _ in range(5):
        s.authenticate("deputyregistrar", "guess", "000000", "10.0.0.9")
    case("Brute force locks the account even with the right password",
         s.authenticate("deputyregistrar", "ChangeMe@468", s.totp(secrets_["deputyregistrar"]), "10.0.0.9") is None)
    with s.ops() as con:
        con.execute("DELETE FROM logins")

    msg = s.try_delete(first["id"])
    case("Deleting a locked backup is refused by the database trigger", "WORM" in msg, msg)
    try:
        with s.vault() as v:
            v.execute("UPDATE blobs SET data=x'00' WHERE backup_id=?", (first["id"],))
        edited = "edited"
    except sqlite3.DatabaseError as exc:
        edited = str(exc)
    case("Editing a backup blob is refused (write-once)", "WORM" in edited, edited)

    rid = s.request_action("release", first["id"], "ictdirector", "test early release")
    self_ok = s.decide(rid, "ictdirector", True)
    case("Requester cannot approve their own request", "four-eyes" in self_ok.get("error", ""))
    case("Auditor cannot approve", "only an admin" in s.decide(rid, "auditor", True).get("error", ""))
    ok = s.decide(rid, "deputyregistrar", True)
    case("Second admin approval releases the lock", ok.get("status") == "approved")
    case("Released backup can now be deleted", s.try_delete(first["id"]) == "deleted")

    b2 = s.backup("test")
    demo.stealth()
    r = s.backup("test")
    case("Quiet attack blocked (high-entropy CSV files)", r["status"] == "blocked", r)
    hit = demo.attack()
    r = s.backup("test")
    case("Loud attack blocked", r["status"] == "blocked", r)
    rid = s.request_action("restore", b2["id"], "deputyregistrar", "ransomware on registry share")
    t0 = time.time()
    out = s.decide(rid, "ictdirector", True)
    rto = time.time() - t0
    same = demo.fingerprint() == good
    res["recovery"] = {"files_encrypted": hit, "files_restored": out["result"]["files"], "rto_seconds": round(rto, 3),
                       "byte_identical": same, "approvals": 2}
    case("Approved restore after attack is byte-identical", same, f"RTO {rto:.3f} s")

    copies = s.replicate()
    con = sqlite3.connect(s.p(copies[1]))
    n = con.execute("SELECT COUNT(*) FROM blobs").fetchone()[0]
    con.close()
    case("Vault replicated to offline copy with SQLite backup API", n > 0, f"{n} blobs")
    v = s.verify()
    res["verify"] = v
    case("Vault verification clean", not v["problems"], v["blobs_checked"])

    srv = demo.portal(s.cfg()["portal_port"], thread=True)
    s.watch()
    with s.ops() as c2:
        up = {r["up"] for r in c2.execute("SELECT up FROM status")}
    srv.shutdown()
    srv.server_close()
    s.watch()
    with s.ops() as c2:
        down = {r["up"] for r in c2.execute("SELECT up FROM status")}
    case("Portal outage detected", up == {1} and down == {0})

    import app
    app.app.secret_key = "t"
    cl = app.app.test_client()
    cl.post("/login", data={"u": "auditor", "p": "ChangeMe@468"})
    case("Auditor cannot seal or request", cl.post("/backup", data={}).status_code == 403)

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(s.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(s.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
