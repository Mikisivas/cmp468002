"""RiversRecover command line. `python main.py -h` for help."""
import argparse
import json
import os
import random
import shutil
import sqlite3

import cdp


def reset():
    shutil.rmtree(cdp.DATA, ignore_errors=True)


def setup():
    reset()
    cdp.init()
    import app
    pw = os.environ.get("RIVERSRECOVER_ADMIN_PASSWORD", "ChangeMe@468")
    app.add_staff("dba", pw, "dba")
    app.add_staff("auditor", pw, "auditor")
    cdp.seed()
    cdp.ship()
    return cdp.base_snapshot()


def grade_tamper(n=30):
    """Insider changes current-semester grades to A, then tries to edit approved ones."""
    changed, blocked = 0, 0
    con = sqlite3.connect(cdp.live_path())
    for rid, appr in con.execute("SELECT id, approved FROM results ORDER BY id LIMIT ?", (n * 2,)).fetchall():
        try:
            con.execute("UPDATE results SET ca=40, exam=55, total=95, grade='A' WHERE id=?", (rid,))
            con.commit()
            changed += 1
        except sqlite3.DatabaseError:
            blocked += 1
    con.close()
    return {"changed": changed, "blocked": blocked}


def mass_delete():
    con = sqlite3.connect(cdp.live_path())
    try:
        n = con.execute("DELETE FROM results WHERE approved=0").rowcount
        con.commit()
    except sqlite3.DatabaseError as exc:
        n = str(exc)
    con.close()
    return {"deleted": n}


def ransomware():
    path = cdp.live_path()
    size = os.path.getsize(path)
    open(path, "wb").write(os.urandom(size))
    return {"encrypted_bytes": size}


def normal_activity(n=5):
    con = sqlite3.connect(cdp.live_path())
    rows = con.execute("SELECT id FROM results WHERE approved=0 LIMIT ?", (n,)).fetchall()
    for (rid,) in rows:
        con.execute("UPDATE results SET exam=exam+1, total=total+1 WHERE id=?", (rid,))
    con.execute("INSERT INTO students VALUES(?,?,?,?,?)", (f"U2026/55{random.randint(10000, 99999)}", "New", "Student",
                                                           "Sociology", 100))
    con.commit()
    con.close()
    return {"updated": len(rows), "inserted": 1}


def main():
    ap = argparse.ArgumentParser(description="RiversRecover: continuous data protection for UNIPORT results")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "ship", "base", "verify", "unfreeze", "normal-activity", "grade-tamper", "mass-delete",
              "ransomware", "status", "reset"):
        sub.add_parser(n)
    r = sub.add_parser("recover", help="point-in-time recovery")
    r.add_argument("--to", help="YYYY-MM-DD HH:MM:SS (default: now)")
    a = ap.parse_args()
    out = None
    if a.cmd == "setup":
        out = setup()
        print("Login: dba / ChangeMe@468 (auditor is read-only)")
    elif a.cmd == "serve":
        import app
        app.serve()
    elif a.cmd == "ship":
        out = cdp.ship()
    elif a.cmd == "base":
        out = cdp.base_snapshot()
    elif a.cmd == "verify":
        out = cdp.verify_store()
    elif a.cmd == "unfreeze":
        cdp.unfreeze("cli")
        out = "unfrozen"
    elif a.cmd == "recover":
        out = cdp.pitr(a.to)
    elif a.cmd == "normal-activity":
        out = normal_activity()
    elif a.cmd == "grade-tamper":
        out = grade_tamper()
    elif a.cmd == "mass-delete":
        out = mass_delete()
    elif a.cmd == "ransomware":
        out = ransomware()
    elif a.cmd == "status":
        with cdp.live() as con:
            out = dict(con.execute("SELECT * FROM control").fetchone())
            out["results"] = con.execute("SELECT COUNT(*) FROM results").fetchone()[0]
    elif a.cmd == "reset":
        reset()
        out = "reset done"
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
