"""YolaShield USSD menu (Africa's Talking style).

The gateway posts sessionId, phoneNumber and text, where text holds every choice so far
joined by '*' (for example "2*1*3*1"). The menu is rebuilt from that path on each request,
so no session state is kept on the server. Replies start with CON (more input expected)
or END (session over). Every screen fits in 160 characters per line block.
"""
import json
import os

import geo
import ledger

LANGS = ["en", "ha", "pcm"]
PAGE = 5


def lang(code):
    return json.load(open(os.path.join(geo.BASE, "lang", f"{code}.json"), encoding="utf-8"))


def lga_page(page, L):
    names = [g["name"] for g in geo.lgas()]
    chunk = names[page * PAGE:(page + 1) * PAGE]
    lines = [f"{i + 1}. {n}" for i, n in enumerate(chunk)]
    if (page + 1) * PAGE < len(names):
        lines.append(L["more"])
    return names, chunk, "\n".join(lines)


def pick_lga(steps, L):
    """Consume LGA choices (with 0 = next page). Returns (lga or None, remaining steps, screen)."""
    page = 0
    while steps:
        s = steps.pop(0)
        names, chunk, screen = lga_page(page, L)
        if s == "0" and (page + 1) * PAGE < len(names):
            page += 1
            continue
        if s.isdigit() and 1 <= int(s) <= len(chunk):
            return chunk[int(s) - 1], steps, None
        return None, [], "BAD"
    return None, [], f"{L['lga_q']}\n{lga_page(page, L)[2]}"


def handle(session, phone, text):
    steps = [s for s in text.split("*")] if text else []
    if not steps:
        return "CON YolaShield\n1. English\n2. Hausa\n3. Pidgin"
    if steps[0] not in ("1", "2", "3"):
        return "END Invalid choice."
    L = lang(LANGS[int(steps.pop(0)) - 1])
    if not steps:
        return f"CON {L['welcome']}\n{L['menu']}"
    choice = steps.pop(0)
    if choice == "1":
        if not steps:
            return f"CON {L['type_q']}\n" + "\n".join(f"{i + 1}. {t}" for i, t in enumerate(L["types"]))
        t = steps.pop(0)
        if not (t.isdigit() and 1 <= int(t) <= len(L["types"])):
            return f"END {L['bad']}"
        lga_name, steps, screen = pick_lga(steps, L)
        if screen == "BAD":
            return f"END {L['bad']}"
        if screen:
            return f"CON {screen}"
        if not steps:
            return f"CON {L['urgent_q']}"
        urgent = steps.pop(0) == "1"
        if not steps:
            return "CON " + L["confirm"].format(type=L["types"][int(t) - 1], lga=lga_name,
                                                urgent=L["urgent_word"] if urgent else "")
        if steps.pop(0) != "1":
            return f"END {L['cancel']}"
        ref = ledger.add("ussd", session, phone, lga_name, ledger.TYPE_CODES[int(t) - 1], urgent)
        return "END " + L["sent"].format(ref=ref)
    if choice == "2":
        lga_name, steps, screen = pick_lga(steps, L)
        if screen == "BAD":
            return f"END {L['bad']}"
        if screen:
            return f"CON {screen}"
        r = ledger.risk()[lga_name]
        return "END " + L["level"].format(lga=lga_name, level=r["level"], advice=L["advice"][r["level"]])
    if choice == "3":
        return "END " + L["tips"]
    if choice == "4":
        lga_name, steps, screen = pick_lga(steps, L)
        if screen == "BAD":
            return f"END {L['bad']}"
        if screen:
            return f"CON {screen}"
        import hashlib
        import time
        ref = "MD" + hashlib.sha256(session.encode()).hexdigest()[:6].upper()
        with ledger.db() as con:
            con.execute("INSERT OR IGNORE INTO mediation VALUES(?,?,?,?,?)",
                        (ref, time.time(), lga_name, ledger.fernet().encrypt(phone.encode()).decode(), "open"))
        return "END " + L["mediator"].format(ref=ref)
    return f"END {L['bad']}"
