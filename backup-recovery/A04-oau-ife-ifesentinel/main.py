"""IfeSentinel command line. On the server computer: setup, then serve.
On other computers use agent.py (see README Part C)."""
import argparse
import json
import os
import shutil
import threading
import time

import demo
import server
from agent import Agent, enrol


def reset():
    for d in ("data",):
        shutil.rmtree(os.path.join(server.BASE, d), ignore_errors=True)


def _bg_server():
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    c = server.cfg()
    server.app.secret_key = "setup"
    t = threading.Thread(target=lambda: server.app.run(host="127.0.0.1", port=c["server_port"], threaded=True),
                         daemon=True)
    t.start()
    time.sleep(1.5)


def setup(start_server=True):
    reset()
    c = server.cfg()
    server.db()
    pw = os.environ.get("IFESENTINEL_ADMIN_PASSWORD", "ChangeMe@468")
    server.add_staff("admin", pw, "admin")
    server.add_staff("helpdesk", pw, "viewer")
    if start_server:
        _bg_server()
    out = []
    for a in c["demo_agents"]:
        folder = os.path.join(server.BASE, "data", "agents", a["name"], "protected")
        demo.seed(students=300, seed_value=a["seed"], root=folder)
        tok = server.make_token(a["location"])
        ag = enrol(a["name"], c["server_url"], tok, folder)
        out.append({a["name"]: ag.backup(full=True)})
    return out


def fleet(stop=None):
    c = server.cfg()
    for a in c["demo_agents"]:
        ag = Agent(a["name"])
        threading.Thread(target=ag.run, args=(c["heartbeat_seconds"], c["backup_minutes"], stop), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description="IfeSentinel: agent-server monitoring and zero-knowledge backup (OAU)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("setup", "serve", "server-only", "status", "reset"):
        sub.add_parser(n)
    t = sub.add_parser("token", help="create a one-time enrolment token for a new computer")
    t.add_argument("--location", required=True)
    for n in ("attack", "stealth", "backup", "restore", "outage", "reconnect"):
        s = sub.add_parser(n)
        s.add_argument("--agent", default="REGISTRY-SRV")
    a = ap.parse_args()
    if a.cmd == "setup":
        print(json.dumps(setup(), indent=1))
        print("Login: admin / ChangeMe@468 (helpdesk is read-only)")
    elif a.cmd == "serve":
        fleet()
        server.serve()
    elif a.cmd == "server-only":
        server.serve()
    elif a.cmd == "token":
        print("One-time token:", server.make_token(a.location))
    elif a.cmd == "status":
        with server.db() as con:
            for r in con.execute("SELECT name,state,location,files FROM agents"):
                print(dict(r))
    elif a.cmd == "reset":
        reset()
    else:
        ag = Agent(a.agent)
        if a.cmd == "attack":
            print(demo.attack(ag.folder), "files encrypted on", a.agent)
        elif a.cmd == "stealth":
            print(demo.stealth(ag.folder), "CSV files overwritten on", a.agent)
        elif a.cmd == "backup":
            print(ag.backup())
        elif a.cmd == "restore":
            print(ag.restore())
        elif a.cmd == "outage":
            open(os.path.join(ag.home, "PAUSED"), "w").close()
            print(a.agent, "stops sending heartbeats (simulated power cut)")
        elif a.cmd == "reconnect":
            os.remove(os.path.join(ag.home, "PAUSED"))
            print(a.agent, "reconnected")


if __name__ == "__main__":
    main()
