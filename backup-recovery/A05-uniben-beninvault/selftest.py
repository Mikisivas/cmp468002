"""BeninVault end-to-end test. Resets the demo data first. Results in results/selftest.json."""
import json
import os
import shutil
import time

import demo
import main as cli
import vault

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    b1 = cli.setup()
    src = demo.source_dir()
    good = demo.fingerprint()
    res["dataset_files"] = len(good)
    res["dataset_bytes"] = sum(os.path.getsize(os.path.join(src, k)) for k in good)
    res["backup"] = b1
    case("Backup split into 3 shards, each about half the archive",
         b1["state"] == "ok" and abs(b1["shard_bytes"] * 2 - b1["cipher_bytes"]) <= 1,
         f"{b1['cipher_bytes']} B archive -> 3 x {b1['shard_bytes']} B")
    res["storage_overhead_percent"] = round(100 * (3 * b1["shard_bytes"] / b1["cipher_bytes"] - 1), 1)

    for site in ("A", "B", "P"):
        with vault.db() as con:
            row = con.execute("SELECT * FROM backups WHERE id=?", (b1["id"],)).fetchone()
        os.rename(vault.shard_path(b1["id"], site), vault.shard_path(b1["id"], site) + ".gone")
        r = vault.restore(b1["id"], os.path.join(vault.DATA, f"chk_{site}"))
        same = demo.fingerprint(os.path.join(vault.DATA, f"chk_{site}")) == good
        os.rename(vault.shard_path(b1["id"], site) + ".gone", vault.shard_path(b1["id"], site))
        shutil.rmtree(os.path.join(vault.DATA, f"chk_{site}"))
        case(f"Restore works with site {site} lost", same and site not in r["shards_used"], r["shards_used"])

    os.remove(vault.shard_path(b1["id"], "A"))
    os.remove(vault.shard_path(b1["id"], "B"))
    try:
        vault.restore(b1["id"], os.path.join(vault.DATA, "chk_two"))
        two = False
    except ValueError:
        two = True
    case("Losing two sites is reported, not silently wrong", two)
    with vault.db() as con:
        con.execute("DELETE FROM backups WHERE id=?", (b1["id"],))
    b1 = vault.backup("test")

    data = bytearray(open(vault.shard_path(b1["id"], "B"), "rb").read())
    data[10] ^= 0x01
    open(vault.shard_path(b1["id"], "B"), "wb").write(bytes(data))
    os.remove(vault.shard_path(b1["id"], "P"))
    with vault.db() as con:
        row = con.execute("SELECT * FROM backups WHERE id=?", (b1["id"],)).fetchone()
    s = vault.scrub()
    case("Scrub sees 1 healthy shard + 1 damaged + 1 missing as unrecoverable", b1["id"] in s["unrecoverable"])
    open(vault.shard_path(b1["id"], "B"), "wb").write(bytes(data[:10]) + bytes([data[10] ^ 1]) + bytes(data[11:]))
    s = vault.scrub()
    case("Scrub rebuilds a missing parity shard", f"{b1['id']}.P" in s["rebuilt"], s)
    case("All three shards healthy after scrub", len(vault.read_shards(row)) == 3)

    demo.stealth()
    r = vault.backup("test")
    case("Quiet attack refused (text files unreadable)", r["state"] == "refused", r.get("reasons"))
    vault.restore(who="test")
    case("Restore after quiet attack is byte-identical", demo.fingerprint() == good)
    hit = demo.attack()
    r = vault.backup("test")
    case("Loud attack refused (rename burst + ransom note)", r["state"] == "refused", r.get("reasons"))
    t0 = time.time()
    rr = vault.restore(who="test")
    rto = time.time() - t0
    same = demo.fingerprint() == good
    res["recovery"] = {"files_encrypted": hit, "files_restored": rr["files"], "rto_seconds": round(rto, 3),
                       "byte_identical": same}
    case("Recovery after loud attack is byte-identical", same, f"RTO {rto:.3f} s")

    srv = demo.portal(vault.cfg()["portal_port"], thread=True)
    for _ in range(3):
        vault.check_services()
    srv.shutdown()
    srv.server_close()
    vault.check_services()
    sla = vault.sla()
    res["sla_example"] = sla
    case("SLA computed: 3 of 4 checks up = 75%, below 99.5% target", sla[0]["uptime"] == 75.0 and not sla[0]["met"])

    with vault.db() as con:
        con.execute("UPDATE trail SET act='nothing' WHERE id=1")
    case("Edited trail entry detected", not vault.trail_ok())

    import app
    app.app.secret_key = "t"
    c = app.app.test_client()
    c.post("/login", data={"u": "auditor", "p": "ChangeMe@468"})
    case("Auditor cannot trigger restore", c.post("/act", data={"do": "restore", "id": "x"}).status_code == 403)
    c2 = app.app.test_client()
    c2.post("/login", data={"u": "admin", "p": "ChangeMe@468"})
    case("Admin POST without CSRF token refused", c2.post("/act", data={"do": "backup"}).status_code == 403)
    case("Pages render", all(c2.get(u).status_code == 200 for u in ("/", "/backups", "/trail")))

    res.update(tests=cases, passed=sum(x["passed"] for x in cases), total=len(cases))
    os.makedirs(os.path.join(vault.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(vault.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
