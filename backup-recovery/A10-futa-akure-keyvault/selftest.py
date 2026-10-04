"""AkureKeyVault end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import time

import demo
import keyvault as kv
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def refused(fn):
    try:
        fn()
        return False
    except Exception:  # noqa: BLE001
        return True


def run():
    res = {}
    first, shares = cli.setup()
    src = demo.source_dir()
    good = demo.fingerprint()
    res["dataset_files"] = len(good)
    res["dataset_bytes"] = sum(os.path.getsize(os.path.join(src, k)) for k in good)
    res["backup"] = first
    case("Unattended backup sealed with only the public key", first["status"] == "ok", first)

    secret = os.urandom(32)
    parts = kv.split_secret(secret)
    case("Shamir: every pair of shares rebuilds the secret",
         all(kv.combine([parts[i], parts[j]]) == secret for i, j in ((0, 1), (0, 2), (1, 2))))
    def wrong_pair():
        try:
            return kv.combine([parts[0], (9, parts[1][1])]) != secret
        except ValueError:
            return True
    case("Shamir: a share paired with a forged one does not give the secret", wrong_pair())

    s = shares
    tmp = os.path.join(kv.DATA, "chk")
    for pair in (("registrar", "bursar"), ("bursar", "ict_director"), ("registrar", "ict_director")):
        kv.restore([s[pair[0]], s[pair[1]]], first["id"], tmp)
    case("Restore works with any two of the three custodians", demo.fingerprint(tmp) == good)
    case("One custodian alone cannot restore", refused(lambda: kv.restore([s["registrar"]], first["id"], tmp)))
    case("Same share typed twice is refused", refused(lambda: kv.restore([s["bursar"], s["bursar"]], first["id"], tmp)))
    typo = s["bursar"][:-8] + ("0" if s["bursar"][-8] != "0" else "1") + s["bursar"][-7:]
    case("A mistyped share is caught by its checksum", refused(lambda: kv.decode_share(typo)))

    demo.stealth()
    r = kv.backup("test")
    case("Quiet attack stops the backup (high entropy)", r["status"] == "stopped", r)
    hit = demo.attack()
    r = kv.backup("test")
    case("Loud attack stops the backup", r["status"] == "stopped", r)
    t0 = time.time()
    rr = kv.restore([s["ict_director"], s["registrar"]])
    rto = time.time() - t0
    same = demo.fingerprint() == good
    res["recovery"] = {"files_encrypted": hit, "files_restored": rr["files"], "rto_seconds": round(rto, 3),
                       "byte_identical": same, "custodians_needed": 2}
    case("Recovery after attack (2 custodians) is byte-identical", same, f"RTO {rto:.3f} s")

    b2 = kv.backup("test")
    rot = kv.rotate([s["registrar"], s["bursar"]])
    res["rotation"] = {"new_version": rot["new_version"], "rewrapped": rot["rewrapped"]}
    case("Key rotation re-wraps every data key", rot["rewrapped"] == 2, rot["rewrapped"])
    case("Old shares no longer open backups after rotation",
         refused(lambda: kv.restore([s["registrar"], s["bursar"]], b2["id"], tmp)))
    ns = rot["shares"]
    case("New shares open old backups (archives untouched)",
         kv.restore([ns["bursar"], ns["ict_director"]], first["id"], tmp)["files"] == len(good))

    kv.shred(first["id"], "test erasure")
    case("Crypto-shredded backup can never be restored",
         refused(lambda: kv.restore([ns["bursar"], ns["registrar"]], first["id"], tmp)))
    case("Other backups still restore after shredding one",
         kv.restore([ns["bursar"], ns["registrar"]], b2["id"], tmp)["files"] == len(good))

    with kv.db() as con:
        b = con.execute("SELECT * FROM backups WHERE id=?", (b2["id"],)).fetchone()
    pth = os.path.join(kv.p(kv.cfg()["store"]), b["file"])
    data = bytearray(open(pth, "rb").read())
    data[30] ^= 1
    open(pth, "wb").write(bytes(data))
    case("Damaged primary archive: restore falls back to an intact copy",
         kv.restore([ns["bursar"], ns["registrar"]], b2["id"], tmp)["files"] == len(good))

    srv = demo.portal(kv.cfg()["portal_port"], thread=True)
    kv.watch()
    with kv.db() as con:
        up = {r["up"] for r in con.execute("SELECT up FROM health")}
    srv.shutdown()
    srv.server_close()
    kv.watch()
    with kv.db() as con:
        down = {r["up"] for r in con.execute("SELECT up FROM health")}
    case("Portal outage detected", up == {1} and down == {0})

    import app
    app.app.secret_key = "t"
    cl = app.app.test_client()
    cl.post("/login", data={"u": "auditor", "p": "ChangeMe@468"})
    case("Auditor cannot run a restore", cl.post("/restore", data={"s1": "x", "s2": "y"}).status_code == 403)
    with kv.db() as con:
        res["ceremonies"] = con.execute("SELECT COUNT(*) n, SUM(ok) ok FROM ceremonies").fetchone()["n"]

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(kv.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(kv.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
