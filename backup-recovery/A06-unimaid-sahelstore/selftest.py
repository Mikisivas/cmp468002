"""SahelStore end-to-end test. Resets demo data first. Results in results/selftest.json."""
import base64
import datetime as dt
import json
import os
import random
import time

import demo
import main as cli
import sahel

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def age(seconds):
    """Make every demo file look older, as if the data was created long ago."""
    old = time.time() - seconds
    for root, _, files in os.walk(demo.source_dir()):
        for f in files:
            os.utime(os.path.join(root, f), (old, old))


def run():
    res = {}
    s1 = cli.setup()
    src = demo.source_dir()
    age(3600)
    res["dataset_files"] = s1["files"]
    res["dataset_bytes"] = s1["bytes_in"]
    res["first_snapshot"] = s1
    case("Initial snapshot (LZMA + AES-GCM)", s1["ok"], f"{s1['bytes_in']} B -> {s1['bytes_stored']} B")

    rnd = random.Random(1)
    a = bytes(rnd.getrandbits(8) for _ in range(50000))
    b = a[:20000] + b"INSERTED RESULT CORRECTION" + a[20000:45000] + a[46000:]
    ops = sahel.delta(a, b)
    case("Delta algorithm rebuilds the new file exactly", sahel.patch(a, ops) == b)
    lit = sum(len(v) for k, v in ops if k == "L")
    case("Delta sends only the blocks around the two edits", lit <= 4 * sahel.BLOCK, f"{lit} literal bytes of {len(b)}")

    reg = os.path.join(src, "registry", "students.csv")
    with open(reg, "a") as fh:
        fh.write("2026/05/9999,New,Student,Nursing,100,Borno,08000000000\n")
    s2 = sahel.snapshot("manual")
    sy = sahel.sync(force=True)
    res["delta_sync"] = sy
    case("Changed 40 KB register synced as a small delta", sy["files"] == 1 and sy["sent_bytes"] < sy["file_bytes"] / 5,
         f"{sy['sent_bytes']} B sent for {sy['file_bytes']} B")
    age(3600)
    good = demo.fingerprint()

    state = {"snap": time.time(), "sync": time.time()}
    cli.ups(35, False)
    case("On battery at 35%: heavy jobs deferred", sahel.tick(state) == "deferred")
    cli.ups(12, False)
    with sahel.db() as con:
        before = con.execute("SELECT COUNT(*) n FROM snaps WHERE kind='emergency'").fetchone()["n"]
    r = sahel.tick(state)
    with sahel.db() as con:
        after = con.execute("SELECT COUNT(*) n FROM snaps WHERE kind='emergency'").fetchone()["n"]
    case("At 12% battery: one emergency snapshot", r == "emergency" and after == before + 1)
    r2 = sahel.tick(state)
    with sahel.db() as con:
        again = con.execute("SELECT COUNT(*) n FROM snaps WHERE kind='emergency'").fetchone()["n"]
    case("Next tick on low battery stays idle (no second snapshot)", r2 == "halted" and again == after)
    os.remove(os.path.join(sahel.DATA, "ups_override.json"))

    case("Off-peak window logic (01:00 in, 14:00 out)",
         sahel.in_window(dt.datetime(2026, 10, 4, 1, 0)) and not sahel.in_window(dt.datetime(2026, 10, 4, 14, 0)))

    demo.stealth()
    r = sahel.snapshot()
    case("Quiet attack refused (burst of modified files)", not r["ok"], r.get("why"))
    sahel.restore()
    case("Restore after quiet attack is byte-identical", demo.fingerprint() == good)
    age(3600)
    hit = demo.attack()
    r = sahel.snapshot()
    case("Loud attack refused (ransomware extension)", not r["ok"], r.get("why"))
    t0 = time.time()
    rr = sahel.restore()
    rto = time.time() - t0
    same = demo.fingerprint() == good
    case("Local recovery after loud attack is byte-identical", same, f"RTO {rto:.3f} s")

    demo.attack()
    import shutil
    shutil.rmtree(sahel.p(sahel.cfg()["local_store"]))
    t0 = time.time()
    ro = sahel.restore_offsite()
    rto_off = time.time() - t0
    same_off = demo.fingerprint() == good
    case("Local store destroyed: full recovery from offsite base + deltas", same_off, f"{rto_off:.3f} s")
    res["recovery"] = {"files_encrypted": hit, "files_restored": rr["files"], "rto_seconds": round(rto, 3),
                       "offsite_rto_seconds": round(rto_off, 3), "byte_identical": same and same_off}

    blob_dir = os.path.join(sahel.offsite_dir(), "files")
    some = os.path.join(blob_dir, sorted(os.listdir(blob_dir))[0], "base")
    data = bytearray(open(some, "rb").read())
    data[40] ^= 1
    open(some, "wb").write(bytes(data))
    try:
        sahel.restore_offsite(os.path.join(sahel.DATA, "chk"))
        caught = False
    except Exception:  # noqa: BLE001
        caught = True
    case("Tampered offsite object is rejected (GCM tag)", caught)

    srv = demo.portal(sahel.cfg()["portal_port"], thread=True)
    sahel.check_health()
    with sahel.db() as con:
        up = {r["up"] for r in con.execute("SELECT up FROM health")}
    srv.shutdown()
    srv.server_close()
    sahel.check_health()
    with sahel.db() as con:
        down = {r["up"] for r in con.execute("SELECT up FROM health")}
    case("Portal outage detected", up == {1} and down == {0})

    import status_page
    case("Status page refuses a wrong password", not status_page.check(
        "Basic " + base64.b64encode(b"ictstaff:guess").decode()))
    case("Status page accepts the right password", status_page.check(
        "Basic " + base64.b64encode(b"ictstaff:ChangeMe@468").decode()))
    with sahel.db() as con:
        con.execute("UPDATE log SET msg='edited' WHERE id=2")
    case("Edited log entry detected", not sahel.log_ok())

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(sahel.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(sahel.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
