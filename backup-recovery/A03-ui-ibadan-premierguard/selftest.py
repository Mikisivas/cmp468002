"""PremierGuard end-to-end test. Resets the demo data first. Results go to results/selftest.json."""
import json
import os
import time

import demo
import engine
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    s1 = cli.setup()
    src = demo.source_dir()
    original = demo.fingerprint()
    res["dataset_files"] = len(original)
    res["dataset_bytes"] = sum(os.path.getsize(os.path.join(src, k)) for k in original)
    res["first_snapshot"] = s1
    case("First snapshot stores all files", s1["status"] == "ok" and s1["files"] == len(original),
         f"{s1['bytes_in']} B -> {s1['bytes_new']} B, {s1['chunks']} chunks")
    s2 = engine.snapshot(note="unchanged")
    res["unchanged_snapshot"] = s2
    case("Unchanged snapshot writes zero new chunks", s2["new_chunks"] == 0, f"{s2['seconds']} s")

    import random
    rnd = random.Random(7)
    words = ["course", "student", "senate", "exam", "credit", "unit", "faculty", "result", "lecture", "hall",
             "registry", "bursary", "matric", "session", "semester", "grade", "venue", "ibadan", "policy"]
    lec = os.path.join(src, "lms", "student_handbook.txt")
    big = " ".join(rnd.choice(words) for _ in range(40000)).encode()
    open(lec, "wb").write(big)
    engine.snapshot(note="handbook added")
    before = len(engine.chunk(big))
    open(lec, "wb").write(b"ERRATUM: venue moved to Faculty of Science LT1.\n" + big)
    s3 = engine.snapshot(note="insert at start")
    res["cdc_insert_test"] = {"chunks_in_file": before, "new_chunks_after_insert": s3["new_chunks"]}
    case("Inserting text at the start changes only a few chunks (CDC)", s3["new_chunks"] <= 2,
         f"{s3['new_chunks']} new of about {before}")
    good = demo.fingerprint()

    demo.stealth()
    b = engine.snapshot()
    case("Quiet encryption of CSV files is blocked (incompressible content)", b["status"] == "blocked", b)
    engine.restore()
    case("Restore after quiet attack is byte-identical", demo.fingerprint() == good)

    hit = demo.attack()
    b = engine.snapshot()
    case("Loud attack is blocked", b["status"] == "blocked", b)
    t0 = time.time()
    r = engine.restore()
    rto = time.time() - t0
    same = demo.fingerprint() == good
    res["recovery"] = {"files_encrypted": hit, "files_restored": r["files"], "rto_seconds": round(rto, 3),
                       "byte_identical": same}
    case("Recovery after loud attack is byte-identical", same, f"RTO {rto:.3f} s")

    some = engine.load_tree(1)["registry/students.csv"]["chunks"][0]
    path = engine.chunk_path(some)
    blob = bytearray(open(path, "rb").read())
    blob[30] ^= 0x55
    open(path, "wb").write(bytes(blob))
    v = engine.verify()
    res["verify"] = {"snapshots": v["snapshots"], "chunks": v["chunks"]}
    case("Corrupted chunk detected and repaired from mirror", len(v["repaired"]) == 1 and not v["bad"], v["repaired"])

    anchors = os.path.join(engine.p(engine.cfg()["anchor_dir"]), "anchors.log")
    lines = open(anchors).read().splitlines()
    saved = list(lines)
    first = lines[0].split()
    lines[0] = " ".join(first[:-1] + ["0" * 64])
    open(anchors, "w").write("\n".join(lines) + "\n")
    v2 = engine.verify()
    case("Mismatched Merkle anchor is reported", 1 in v2["root_mismatch"])
    open(anchors, "w").write("\n".join(saved) + "\n")

    with engine.db() as con:
        total_in = con.execute("SELECT SUM(bytes_in) a FROM snapshots WHERE status='ok'").fetchone()["a"]
        stored = con.execute("SELECT SUM(stored) a FROM chunks").fetchone()["a"]
    res["dedup_saving_percent"] = round(100 * (1 - stored / total_in), 1)
    gc = engine.garbage_collect(2)
    res["gc"] = gc
    case("Garbage collection keeps newest snapshots restorable", gc["snapshots_dropped"] >= 1 and
         engine.restore(engine.latest()["id"], os.path.join(engine.DATA, "gc_check"))["files"] == len(good))

    srv = demo.portal(engine.cfg()["portal_port"], thread=True)
    engine.sample()
    with engine.db() as con:
        up = {r["up"] for r in con.execute("SELECT up FROM probes")}
    srv.shutdown()
    srv.server_close()
    engine.sample()
    with engine.db() as con:
        down = {r["up"] for r in con.execute("SELECT up FROM probes")}
    case("Portal outage detected", up == {1} and down == {0})

    import server
    server.app.secret_key = "t"
    cl = server.app.test_client()
    case("Wrong password refused", cl.post("/api/login", json={"u": "admin", "p": "x"}).status_code == 401)
    tok = cl.post("/api/login", json={"u": "admin", "p": "ChangeMe@468"}).get_json()["csrf"]
    case("POST without CSRF header refused", cl.post("/api/snapshot", json={}).status_code == 403)
    case("POST with CSRF header accepted", cl.post("/api/snapshot", json={}, headers={"X-CSRF-Token": tok}).status_code == 200)
    ob = server.app.test_client()
    ob.post("/api/login", json={"u": "observer", "p": "ChangeMe@468"})
    case("Observer cannot restore", ob.post("/api/restore", json={}).status_code == 403)

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(engine.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(engine.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
