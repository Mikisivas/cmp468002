"""End-to-end test of ZariaSafe. WARNING: it resets the demo data first.

Writes the measured results to results/selftest.json (used in Chapter Four of the report).
"""
import json
import os
import shutil
import time

import core
import demo
import main as cli


def run():
    res, cases = {}, []

    def case(name, passed, detail=""):
        cases.append({"test": name, "passed": bool(passed), "detail": str(detail)})
        print(("PASS " if passed else "FAIL ") + name, detail)

    cli.reset()
    core.init()
    demo.seed()
    original = demo.fingerprint()
    res["dataset_files"] = len(original)
    res["dataset_bytes"] = sum(os.path.getsize(os.path.join(demo.source_dir(), k)) for k in original)

    b1 = core.backup(actor="test")
    res["full_backup"] = b1
    case("First (full) backup stores every file", b1["status"] == "ok" and b1["changed"] == len(original),
         f"{b1['changed']} files in {b1['seconds']} s")

    with open(os.path.join(demo.source_dir(), "registry", "students.csv"), "a") as fh:
        fh.write("U2026CS9999,Test,Student,Computer Science,100,Kaduna,08000000000\n")
    b2 = core.backup(actor="test")
    res["incremental_backup"] = b2
    case("Incremental backup copies only the changed file", b2["changed"] == 1, f"changed={b2['changed']}")
    b3 = core.backup(actor="test")
    res["unchanged_backup"] = b3
    case("Unchanged run stores nothing new", b3["changed"] == 0, f"{b3['seconds']} s")
    good = demo.fingerprint()

    n = demo.stealth()
    held = core.backup(actor="test")
    case("Quiet in-place encryption is held by the mass-change detector", held["status"] == "held",
         "; ".join(held.get("reasons", [])))
    r = core.restore(actor="test")
    case("Restore after quiet attack is byte-identical", demo.fingerprint() == good, f"{n} files hit")

    hit = demo.attack()
    held2 = core.backup(actor="test")
    case("Loud attack (.locked + note) is held", held2["status"] == "held", "; ".join(held2.get("reasons", [])))
    t0 = time.time()
    r = core.restore(actor="test")
    rto = time.time() - t0
    same = demo.fingerprint() == good
    res["recovery"] = {"files_encrypted": hit, "files_restored": r["files"], "rto_seconds": round(rto, 3),
                       "byte_identical": same}
    case("Full recovery after loud attack is byte-identical and note removed",
         same and not os.path.exists(os.path.join(demo.source_dir(), "READ_ME_TO_DECRYPT.txt")), f"RTO {rto:.3f} s")

    tmp = os.path.join(core.DATA, "restore_check")
    core.restore(b1["version"], tmp, actor="test")
    case("Point-in-time restore of version 1 to a side folder", demo.fingerprint(tmp) == original)
    shutil.rmtree(tmp)

    vdir = os.path.join(core.vault(), b1["version"], "objects")
    obj = os.path.join(vdir, sorted(os.listdir(vdir))[0])
    with open(obj, "r+b") as fh:
        fh.seek(20)
        fh.write(b"\x00\x01")
    v = core.verify(repair=True)
    case("Tampered object detected and repaired from replica", len(v["repaired"]) == 1 and not v["bad"], v["repaired"])
    res["verify_checked_objects"] = v["checked"]

    mpath = os.path.join(core.vault(), b2["version"], "manifest.json")
    with open(mpath) as fh:
        m = json.load(fh)
    k = next(iter(m["files"]))
    m["files"][k]["size"] += 1
    with open(mpath, "w") as fh:
        json.dump(m, fh)
    try:
        core.read_manifest(b2["version"])
        detected = False
    except ValueError:
        detected = True
    case("Edited manifest is rejected (HMAC signature)", detected)
    shutil.copyfile(os.path.join(core.path(core.load_config()["replicas"][0]), b2["version"], "manifest.json"), mpath)

    with core.db() as con:
        con.execute("UPDATE audit SET detail='nothing happened' WHERE id=3")
    ok, row = core.audit_ok()
    case("Edited audit row breaks the signature chain", not ok, f"broken at row {row}")

    srv = demo.portal(core.load_config()["portal_port"], thread=True)
    core.monitor_once()
    with core.db() as con:
        up = con.execute("SELECT status FROM services").fetchall()
    srv.shutdown()
    srv.server_close()
    core.monitor_once()
    with core.db() as con:
        down = con.execute("SELECT status FROM services").fetchall()
    case("Service outage detected", all(s["status"] == "UP" for s in up) and all(s["status"] == "DOWN" for s in down))

    case("Wrong password is refused", core.check_user("admin", "guess") is None and
         core.check_user("admin", "ChangeMe@468") == "admin")

    res["tests"] = cases
    res["passed"] = sum(c["passed"] for c in cases)
    res["total"] = len(cases)
    os.makedirs(os.path.join(core.BASE, "results"), exist_ok=True)
    with open(os.path.join(core.BASE, "results", "selftest.json"), "w") as fh:
        json.dump(res, fh, indent=1)
    print(f"\n{res['passed']}/{res['total']} tests passed. Results in results/selftest.json")
    cli.reset()
    core.init()
    demo.seed()
    core.backup(actor="setup")
    return res


if __name__ == "__main__":
    run()
