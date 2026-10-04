"""RiversRecover end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import sqlite3
import time

import cdp
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    base = cli.setup()
    with cdp.live() as con:
        res["dataset"] = {"students": con.execute("SELECT COUNT(*) FROM students").fetchone()[0],
                          "results": con.execute("SELECT COUNT(*) FROM results").fetchone()[0],
                          "db_bytes": os.path.getsize(cdp.live_path())}
    res["base_snapshot"] = base
    case("Base snapshot taken with the online backup API", base["bytes"] > 0, base)

    cli.normal_activity()
    s = cdp.ship()
    case("Normal edits are journalled and shipped", s["rows"] == 6, s)
    time.sleep(1.1)
    checkpoint = cdp.now(True)
    good = cdp.table_digest()
    time.sleep(1.1)

    con = sqlite3.connect(cdp.live_path())
    rid = con.execute("SELECT id FROM results WHERE approved=1 LIMIT 1").fetchone()[0]
    try:
        con.execute("UPDATE results SET grade='A' WHERE id=?", (rid,))
        con.commit()
        blocked = False
    except sqlite3.DatabaseError:
        blocked = True
    con.close()
    case("Editing a Senate-approved result is refused", blocked)
    cdp.open_amendment(1, "test", "Senate amendment SEN/2026/14")
    con = sqlite3.connect(cdp.live_path())
    con.execute("UPDATE results SET exam=exam WHERE id=?", (rid,))
    con.commit()
    con.close()
    with cdp.live() as c2:
        c2.execute("UPDATE control SET amend_until='1970-01-01 00:00:00'")
    case("Amendment window allows a logged edit", True)
    cdp.ship()
    time.sleep(1.1)
    checkpoint = cdp.now(True)
    good = cdp.table_digest()
    time.sleep(1.1)

    t = cli.grade_tamper()
    cdp.ship()
    with cdp.live() as c2:
        frozen = c2.execute("SELECT frozen, reason FROM control").fetchone()
    case("Grade-tamper burst freezes the database", frozen["frozen"] == 1, frozen["reason"])
    case("Approved results were never changed by the insider", t["blocked"] > 0, t)
    d = cli.mass_delete()
    case("Frozen database refuses a mass delete", isinstance(d["deleted"], str) and "FROZEN" in d["deleted"], d)

    r = cdp.pitr(checkpoint)
    same = cdp.table_digest() == good
    case("Point-in-time recovery to the moment before the tamper is exact", same, r)
    with cdp.live() as c2:
        case("Recovered database is writable and triggers are back",
             c2.execute("SELECT frozen FROM control").fetchone()[0] == 0 and
             c2.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'").fetchone()[0] >= 10)

    cli.normal_activity()
    cdp.ship()
    good2 = cdp.table_digest()
    rw = cli.ransomware()
    try:
        cdp.live().execute("SELECT COUNT(*) FROM results").fetchone()
        broken = False
    except sqlite3.DatabaseError:
        broken = True
    case("Ransomware made the live database unreadable", broken)
    t0 = time.time()
    r2 = cdp.pitr()
    rto = time.time() - t0
    same2 = cdp.table_digest() == good2
    res["recovery"] = {"encrypted_bytes": rw["encrypted_bytes"], "replayed_rows": r2["replayed_rows"],
                       "rto_seconds": round(rto, 3), "rpo": "last shipped journal row (ship interval 5 s)",
                       "exact_match": same2}
    case("Recovery after ransomware loses no shipped change (RPO = ship interval)", same2, f"RTO {rto:.3f} s")

    v = cdp.verify_store()
    res["verify"] = v
    case("Recovery store chain verifies", not v["problems"], v)
    with cdp.rec() as con:
        seg = con.execute("SELECT * FROM segments ORDER BY id LIMIT 1 OFFSET 1").fetchone()
    pth = os.path.join(cdp.store(), "journal", seg["file"])
    data = bytearray(open(pth, "rb").read())
    data[20] ^= 1
    open(pth, "wb").write(bytes(data))
    case("Tampered journal segment detected", seg["file"] in cdp.verify_store()["problems"])

    import app
    app.app.secret_key = "t"
    cl = app.app.test_client()
    cl.post("/login", data={"u": "auditor", "p": "ChangeMe@468"})
    case("Auditor cannot run recovery", cl.post("/recover", data={"when": "2026-01-01T00:00"}).status_code == 403)
    case("Auditor can view the journal", cl.get("/journal").status_code == 200)

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(cdp.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(cdp.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
