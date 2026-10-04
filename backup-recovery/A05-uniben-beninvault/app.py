"""BeninVault Flask console (Jinja templates in templates/) and scheduler."""
import os
import secrets
import threading
import time

from flask import Flask, abort, flash, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import demo
import vault

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
TRIES = {}


@app.context_processor
def inject():
    return {"inst": vault.cfg()["institution"]["name"]}


@app.after_request
def sec(r):
    r.headers.update({"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                      "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'"})
    return r


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u = request.form.get("u", "")
        TRIES[u] = [t for t in TRIES.get(u, []) if t > time.time() - 900]
        with vault.db() as con:
            r = con.execute("SELECT * FROM people WHERE name=?", (u,)).fetchone()
        if len(TRIES[u]) >= 5:
            msg = "Locked for 15 minutes."
        elif r and check_password_hash(r["hash"], request.form.get("p", "")):
            session.clear()
            session.update(user=u, role=r["role"], csrf=secrets.token_hex(16))
            vault.trail(u, "sign in")
            return redirect("/")
        else:
            TRIES[u].append(time.time())
            msg = "Wrong details."
    return render_template("login.html", msg=msg)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


def guard():
    if "user" not in session:
        abort(redirect("/login"))


@app.get("/")
def overview():
    guard()
    c = vault.cfg()
    sites = {}
    for s, path in c["sites"].items():
        files = len(os.listdir(vault.p(path))) if os.path.isdir(vault.p(path)) else 0
        with vault.db() as con:
            need = con.execute("SELECT COUNT(*) n FROM backups WHERE state='ok'").fetchone()["n"]
        sites[s] = {"name": c["site_names"][s], "files": files, "ok": files >= need}
    with vault.db() as con:
        notes = con.execute("SELECT * FROM notices ORDER BY id DESC LIMIT 12").fetchall()
    return render_template("overview.html", sites=sites, sla=vault.sla(), notices=notes)


@app.get("/backups")
def backups():
    guard()
    with vault.db() as con:
        rows = con.execute("SELECT * FROM backups ORDER BY created DESC LIMIT 40").fetchall()
    health = {r["id"]: len(vault.read_shards(r)) for r in rows if r["state"] == "ok"}
    return render_template("backups.html", rows=rows, health=health)


@app.get("/trail")
def trail():
    guard()
    with vault.db() as con:
        rows = con.execute("SELECT * FROM trail ORDER BY id DESC LIMIT 80").fetchall()
    return render_template("trail.html", rows=rows, ok=vault.trail_ok())


@app.post("/act")
def act():
    guard()
    if session["role"] != "admin" or request.form.get("csrf") != session["csrf"]:
        abort(403)
    do = request.form.get("do")
    if do == "backup":
        flash(str(vault.backup(session["user"])))
    elif do == "scrub":
        flash(str(vault.scrub()))
    elif do == "restore":
        flash(str(vault.restore(request.form["id"], who=session["user"])))
        return redirect("/backups")
    return redirect("/")


def add_person(name, pw, role):
    with vault.db() as con:
        con.execute("INSERT OR REPLACE INTO people VALUES(?,?,?)", (name, generate_password_hash(pw), role))


def worker():
    c = vault.cfg()
    last_b = last_s = time.time()
    while True:
        try:
            vault.check_services()
            with vault.db() as con:
                down = con.execute("SELECT service FROM checks WHERE up=0 AND rowid IN "
                                   "(SELECT MAX(rowid) FROM checks GROUP BY service)").fetchall()
            if down:
                demo.portal(c["portal_port"], background=True)
            if time.time() - last_b > c["backup_minutes"] * 60:
                vault.backup()
                last_b = time.time()
            if time.time() - last_s > c["scrub_hours"] * 3600:
                vault.scrub()
                last_s = time.time()
        except Exception as exc:  # noqa: BLE001
            vault.notice("warning", f"worker: {exc}")
        time.sleep(c["check_seconds"])


def serve():
    app.secret_key = os.environ.get("BENINVAULT_SECRET") or secrets.token_hex(32)
    threading.Thread(target=worker, daemon=True).start()
    app.run(host="127.0.0.1", port=vault.cfg()["port"])
