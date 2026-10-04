"""HarmonyVault end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import time

import demo
import history as h
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    c1 = cli.setup()
    src = demo.source_dir()
    original = demo.fingerprint()
    res["dataset_files"] = len(original)
    res["dataset_bytes"] = sum(os.path.getsize(os.path.join(src, k)) for k in original)
    res["first_commit"] = c1
    case("Initial signed commit", c1["status"] == "ok", c1)
    edits = []
    for i in range(4):
        with open(os.path.join(src, "registry", "students.csv"), "a") as fh:
            fh.write(f"2026/52HA{9000 + i},New,Student,Yoruba,100,Kwara,08000000000\n")
        edits.append(h.commit(f"daily backup {i + 1}", "test"))
    res["incremental_commits"] = edits[-1]
    case("Daily commits store only the changed blob", all(e["new_blobs"] == 1 for e in edits))
    good = demo.fingerprint()

    v = h.verify_chain()
    res["verify"] = v
    case("Whole history verifies (signatures, trees, blobs)", v["ok"] and v["commits"] == 5, v)

    demo.stealth()
    r = h.commit()
    case("Quiet attack refused by change-rate anomaly (z-score)", r["status"] == "refused", r.get("reasons"))
    h.checkout()
    case("Checkout after quiet attack is byte-identical", demo.fingerprint() == good)

    hit = demo.attack()
    r = h.commit()
    case("Loud attack refused (honey files + extensions + anomaly)", r["status"] == "refused", r.get("reasons"))
    t0 = time.time()
    rr = h.checkout()
    rto = time.time() - t0
    same = demo.fingerprint() == good
    res["recovery"] = {"files_encrypted": hit, "files_restored": rr["files"], "rto_seconds": round(rto, 3),
                       "byte_identical": same}
    case("Recovery after loud attack is byte-identical", same, f"RTO {rto:.3f} s")

    pth = os.path.join(src, "Exam_Questions_2026_CONFIDENTIAL", "CSC468_exam_paper.txt")
    open(pth, "a").write("copied\n")
    r = h.commit()
    case("A single edit to a honey file refuses the commit", r["status"] == "refused" and "honey" in r["reasons"][0])
    h.checkout()

    with h.db() as con:
        first = con.execute("SELECT id FROM commits ORDER BY rowid LIMIT 1").fetchone()["id"]
    tmp = os.path.join(h.DATA, "pit")
    h.checkout(first, tmp)
    case("Point-in-time checkout of the first commit", demo.fingerprint(tmp) == original)
    with h.db() as con:
        ids = [r["id"] for r in con.execute("SELECT id FROM commits ORDER BY rowid")]
    d = h.diff(ids[0], ids[-1])
    case("Diff lists exactly the edited file", d["changed"] == ["registry/students.csv"] and not d["added"], d)

    import json as _j
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    target = ids[2]
    raw = _j.loads(h.get("commit", target))
    raw["body"]["message"] = "tampered message"
    path = h.opath(target)
    n = os.urandom(12)
    open(path, "wb").write(n + AESGCM(h.okey()).encrypt(n, _j.dumps(raw).encode(), ("commit" + target).encode()))
    v2 = h.verify_chain()
    case("Re-encrypted, edited commit is caught (signature or id mismatch)", not v2["ok"], v2)

    good_head = h.head()
    forged = _j.loads(h.get("commit", ids[1]))
    forged["body"]["message"] = "forged by an insider who stole the storage key"
    fid, _ = h.put("commit", _j.dumps(forged).encode())
    with h.db() as con:
        con.execute("UPDATE refs SET commit_id=? WHERE name='main'", (fid,))
    v3 = h.verify_chain()
    case("Insider with the storage key still cannot forge a commit (Ed25519)", not v3["ok"] and
         v3["error"] == "InvalidSignature", v3)
    with h.db() as con:
        con.execute("UPDATE refs SET commit_id=? WHERE name='main'", (good_head,))

    srv = demo.portal(h.cfg()["portal_port"], thread=True)
    h.probe()
    with h.db() as con:
        up = {r["up"] for r in con.execute("SELECT up FROM services")}
    srv.shutdown()
    srv.server_close()
    h.probe()
    with h.db() as con:
        down = {r["up"] for r in con.execute("SELECT up FROM services")}
    case("Portal outage detected", up == {1} and down == {0})

    import web
    web.app.secret_key = "t"
    cl = web.app.test_client()
    cl.post("/login", data={"u": "reviewer", "p": "ChangeMe@468"})
    case("Reviewer cannot restore", cl.post("/restore", data={"id": first}).status_code == 403)
    c2 = web.app.test_client()
    c2.post("/login", data={"u": "custodian", "p": "ChangeMe@468"})
    case("Custodian POST without CSRF refused", c2.post("/commit", data={}).status_code == 403)

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(h.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(h.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
