"""LionKeep end-to-end test. Resets the demo data first. Results go to results/selftest.json."""
import datetime as dt
import json
import os
import time

import core
import demo
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    full = cli.setup()
    src = demo.source_dir()
    original = demo.fingerprint()
    res["dataset_files"] = len(original)
    res["dataset_bytes"] = sum(os.path.getsize(os.path.join(src, k)) for k in original)
    res["full_backup"] = full
    case("Full archive holds every file", full["files"] == len(original),
         f"{full['raw_bytes']} B -> {full['stored_bytes']} B in {full['seconds']} s")
    with open(os.path.join(src, "registry", "students.csv"), "a") as fh:
        fh.write("2026/999945,New,Student,Statistics,100,Enugu,08000000000\n")
    d1 = core.backup("diff", "test")
    with open(os.path.join(src, "staff", "payroll.csv"), "a") as fh:
        fh.write("UNN-SP9999,New Staff,CONUASS 1,150000\n")
    d2 = core.backup("diff", "test")
    res["differential_1"], res["differential_2"] = d1, d2
    case("Differentials are cumulative since the last full", d1["files"] == 1 and d2["files"] == 2,
         f"diff1={d1['files']} diff2={d2['files']}")
    good = demo.fingerprint()

    victim = os.path.join(src, "results", sorted(os.listdir(os.path.join(src, "results")))[0])
    with open(victim, "wb") as fh:
        fh.write(os.urandom(4000))
    d3 = core.backup("diff", "test")
    case("Single encrypted file is quarantined, rest still backed up", d3["status"] == "ok" and d3["quarantined"] == 1)
    core.restore(who="test")
    case("Restore brings back the last clean copy of the quarantined file", demo.fingerprint() == good)

    demo.stealth()
    held = core.backup("diff", "test")
    case("Quiet attack on 6 CSVs aborts the backup", held["status"] == "aborted", held)
    core.restore(who="test")
    case("Restore after quiet attack is byte-identical", demo.fingerprint() == good)

    hit = demo.attack()
    held = core.backup("diff", "test")
    case("Loud attack aborts the backup", held["status"] == "aborted", held)
    t0 = time.time()
    r = core.restore(who="test")
    rto = time.time() - t0
    same = demo.fingerprint() == good
    res["recovery"] = {"files_encrypted": hit, "files_restored": r["files"], "archives_used": r["chain"],
                       "rto_seconds": round(rto, 3), "byte_identical": same}
    case("Full + differential restore after loud attack is byte-identical", same, f"RTO {rto:.3f} s, chain {r['chain']}")

    with core.db() as con:
        row = con.execute("SELECT * FROM archives ORDER BY id LIMIT 1").fetchone()
    pth = os.path.join(core.p(core.cfg()["store"]), row["name"])
    data = bytearray(open(pth, "rb").read())
    data[100] ^= 0xFF
    open(pth, "wb").write(bytes(data))
    v = core.verify()
    case("Damaged archive detected and repaired from NAS copy", v["repaired"] == [row["name"]] and not v["lost"], v)

    case("GFS tiers (31 Oct = grandfather, Fri = father, Tue = son)",
         core.tier_for(dt.date(2026, 10, 31)) == "grandfather" and core.tier_for(dt.date(2026, 10, 2)) == "father"
         and core.tier_for(dt.date(2026, 10, 6)) == "son")

    with core.db() as con:
        con.execute("UPDATE log SET what='nothing' WHERE id=2")
    case("Edited activity log row is detected", not core.log_intact())

    srv = demo.portal(core.cfg()["portal_port"], thread=True)
    core.monitor_once()
    with core.db() as con:
        up = [s["status"] for s in con.execute("SELECT status FROM services")]
    srv.shutdown()
    srv.server_close()
    core.monitor_once()
    with core.db() as con:
        down = [s["status"] for s in con.execute("SELECT status FROM services")]
    case("Portal outage detected", set(up) == {"UP"} and set(down) == {"DOWN"})

    import app
    app.app.secret_key = "test"
    cl = app.app.test_client()
    codes = [cl.post("/login", data={"u": "admin", "p": "wrong"}).status_code for _ in range(5)]
    locked = b"locked" in cl.post("/login", data={"u": "admin", "p": "ChangeMe@468"}).data
    case("Account locks after 5 wrong passwords", locked, codes)
    cl2 = app.app.test_client()
    with core.db() as con:
        con.execute("UPDATE users SET failed=0, locked_until=0")
    cl2.post("/login", data={"u": "viewer", "p": "ChangeMe@468"})
    case("Viewer role cannot restore", cl2.post("/restore", data={"id": 1}).status_code == 403)
    case("POST without CSRF token is rejected", cl2.post("/backup", data={}).status_code in (400, 403))

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(core.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(core.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()
    return res


if __name__ == "__main__":
    run()
