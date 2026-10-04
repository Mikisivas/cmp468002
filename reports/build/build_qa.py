"""Builds a study / defence question-and-answer document (Word) for each of the 20 systems.

Usage:  python build_qa.py            (all)
        python build_qa.py A03 B07    (selected)
Output: reports/study-qa/<ID>_<Name>_Study_QA.docx
"""
import json
import os
import re
import sys

import content_a
import content_b
import docx_helpers
import literature as lit

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(os.path.dirname(HERE), "study-qa")
FAMILY = {"A": ("backup-recovery", lit.A_REFS), "B": ("conflict-early-warning", lit.B_REFS)}

GENERAL_A = [
    ("What is the CIA triad and how does this project use it?",
     "Confidentiality, Integrity and Availability. Encryption keeps backups confidential, hashes, MACs or signatures detect any change "
     "(integrity), and multiple copies plus tested restores keep records available after failure or attack."),
    ("What are RPO and RTO?",
     "The Recovery Point Objective is the most data, measured in time, the university accepts to lose (for example 60 minutes). The "
     "Recovery Time Objective is the longest acceptable time to restore service. The self-test measures the real restore time."),
    ("Why is ransomware a backup problem and not only an antivirus problem?",
     "Modern ransomware encrypts live files and then targets backups. If a backup job copies encrypted files over the last good "
     "copies, the history is poisoned. The backup system must therefore detect suspicious data and protect clean copies."),
    ("What is the difference between hashing and encryption?",
     "Hashing (for example SHA-256) is one-way: it produces a fixed fingerprint and cannot be reversed, so it proves integrity. "
     "Encryption (for example AES-256-GCM) is two-way with a key: it hides content and the right key recovers it."),
    ("What does the 'GCM' in AES-256-GCM add?",
     "Galois/Counter Mode is authenticated encryption. Besides hiding data it adds a 16-byte tag, so any changed bit makes "
     "decryption fail. That is why tampered backup objects are detected automatically."),
    ("Why store passwords as slow salted hashes (PBKDF2, scrypt) instead of plain SHA-256?",
     "A random salt stops precomputed tables, and thousands of iterations make each guess slow, so a stolen password database is "
     "expensive to crack. Plain SHA-256 is fast, which helps the attacker."),
    ("What is CSRF and how is it prevented here?",
     "Cross-site request forgery tricks a logged-in browser into sending an unwanted request. Every form or API call must carry a "
     "random per-session token that another site cannot read, and cookies are SameSite."),
    ("What is the 3-2-1-1-0 backup rule?",
     "Three copies, on two kinds of media, one offsite, one offline or immutable, and zero errors after verification "
     "(Lysetskyi, 2025)."),
    ("Which law applies to student data in Nigeria?",
     "The Nigeria Data Protection Act 2023. The university is a data controller and must keep personal data secure, accurate and "
     "available, and be able to show the controls it uses."),
]

GENERAL_B = [
    ("What is a conflict early warning system?",
     "A system that collects signals of rising risk, analyses them, warns the right people early, and supports a response "
     "before violence happens or spreads."),
    ("Why is an early warning system a computer security problem?",
     "It holds sensitive data (who reported what), it can be fed false data, its messages can be forged or replayed, and its "
     "records can be altered. Each of these can cost lives, so confidentiality, integrity and availability all matter."),
    ("What is pseudonymisation and why use it for reporters?",
     "Replacing an identity with a code. Here an HMAC of the phone number lets analysts count repeat reporters without seeing "
     "the number; only someone with the secret key can link the code to a phone."),
    ("What is a replay attack?",
     "Capturing a valid message and sending it again later. Timestamps with a short window, nonces or increasing counters stop it."),
    ("What is HMAC?",
     "A keyed hash. HMAC-SHA256(key, message) proves the message came from someone holding the key and was not changed."),
    ("Why is the data synthetic, and is that acceptable?",
     "Real incident and informant data are sensitive and not public. Synthetic data that follows documented patterns lets us test "
     "every function and security control safely. It proves the design works, not that its forecasts are accurate in the field."),
    ("Which law protects reporters' personal data?",
     "The Nigeria Data Protection Act 2023: phone numbers and identities are personal data and must be protected, minimised and, "
     "where lawful, erasable."),
    ("What is role-based access control?",
     "Permissions are given to roles (for example analyst, responder, auditor) and users get roles, so each person can do only "
     "what their job needs (least privilege)."),
]


def sentences(text, n=2):
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return " ".join(parts[:n])


def qa_for(s, family, res, spec):
    folder, refs = FAMILY[family]
    metrics = [[a, str(b).replace("True", "yes").replace("False", "no")] for a, b in s["metrics"](res)]
    place = ("the " + s["place"]) if s["place"].startswith(("University", "Federal")) else s["place"]
    secs = []

    secs.append(("Section A: The project", [
        (f"What is {s['name']} in one sentence?", f"{s['name']} is a system for {place}: {s['subtitle'][0].lower() + s['subtitle'][1:]}."),
        ("What problem does it solve?", " ".join(s["problems"])),
        ("What is the aim and what are the objectives?",
         f"The aim is to design, implement and evaluate {s['name']}. Objectives: " + " ".join(f"({i + 1}) {o}" for i, o in enumerate(s["objectives"]))),
        (f"Why was it designed for {place}?", sentences(s["context"], 3)),
        (f"How is {s['name']} different from the earlier " + ("VarsityShield" if family == "A" else "Zaman Lafiya") + " project?",
         "It keeps the same aim but uses a different design: " + " ".join(re.sub(r"\*\*", "", d) for d in spec["design"][:3])),
        ("What is the scope and what are the limitations?", s["scope"]),
    ]))

    secs.append(("Section B: Design and algorithms", [
        ("Describe the architecture.", "From top to bottom: " + "; then ".join(", ".join(l) for l in s["layers"]) + ". " +
         " ".join(f"{c[0]}: {c[1]}." for c in s["components"]))]
        + [(f"Explain the {h.lower()} step.", t) for h, t in s["algorithms"]]
        + [("Which tools and technologies did you use and why?",
            "Python 3.10+ (free, runs on Windows and Linux, easy for an ICT unit to maintain), SQLite (no database server needed), and "
            "the packages in requirements.txt. Windows batch launchers let non-programmers set it up.")]
        + ([("Which keys protect the data?", s["keys_used"])] if family == "A" else [])))

    secs.append(("Section C: Security", [
        (f"How does {s['name']} handle this threat: {t[0].lower()}?", t[1] + ".") for t in s["threats"]]
        + [("Map the system to the CMP 468 course outline.",
            "Encryption and decryption, hashing and integrity, authentication and access control, defence methods (preventive, "
            "detective, corrective), classes of attack (" + ", ".join(t[0].lower() for t in s["threats"][:3]) + "), and security "
            "policy (retention, roles, NDPA 2023). Table 1 in the report gives the full mapping.")]))

    tests = res["tests"]
    secs.append(("Section D: Testing and results", [
        ("How did you test the system?",
         f"With an automated program, selftest.py, which resets the demo data and runs {res['total']} tests covering normal use, "
         f"attacks and failures. All {res['passed']} passed. The numbers are saved to results/selftest.json and quoted in Chapter Four."),
        ("Give three tests and what they proved.", " ".join(f"'{t['test']}' passed ({t['detail'][:80]})." if t["detail"] else
                                                            f"'{t['test']}' passed." for t in tests[:3])),
        ("What were the key measurements?", "; ".join(f"{a}: {b}" for a, b in metrics) + "."),
        ("What did the results teach you? Did anything fail during development?", s["discussion"]),
        ("How would you demonstrate the system live?", " ".join(f"Step {i + 1}: {x[0]} ({x[1]}), the panel sees {x[2].rstrip('.')}."
                                                               for i, x in enumerate(spec["script"][:5]))),
    ]))

    secs.append(("Section E: Literature", [
        ("Name related work and say how your design differs.", s["closest_text"]),
        ("What research gap does the project address?", s["gap"]),
    ] + [(f"What did {refs[k][1].split(' (')[0]} find?", refs[k][1]) for k in s["closest"][:3]]))

    secs.append(("Section F: Limitations and future work", [
        ("What would you do before real deployment?", " ".join(s["recommendations"])),
        ("What further work would improve it?", " ".join(s["further"])),
        ("What is the biggest weakness of your design?", sentences(s["discussion"].split(". ", 1)[-1], 2)),
    ]))
    secs.append(("Section G: General CMP 468 questions", GENERAL_A if family == "A" else GENERAL_B))
    return secs


def build(s, family):
    folder, _ = FAMILY[family]
    sysdir = os.path.join(ROOT, folder, s["folder"])
    res = json.load(open(os.path.join(sysdir, "results", "selftest.json")))
    spec = json.load(open(os.path.join(HERE, "specs", f"{s['id']}.json"), encoding="utf-8"))
    r = docx_helpers.Report()
    r.center("CMP 468: COMPUTER SECURITY", 13, True)
    r.center("STUDY QUESTIONS AND ANSWERS FOR THE PROJECT DEFENCE", 13, True, 18)
    r.center(s["title"], 14, True, 12)
    r.center(f"Companion to report {s['id']}_{s['name']}_Report.docx", 11, False, 24)
    r.p("How to use this document: read each question, answer it aloud in your own words, then check the model answer. "
        "The answers use this system's own design and its real test results, so learn the numbers in Section D.")
    n = 0
    for title, qas in qa_for(s, family, res, spec):
        r.h1(title)
        for q, a in qas:
            n += 1
            r.p(f"**Q{n}. {q}**")
            r.p(f"Answer: {a}")
    os.makedirs(OUT, exist_ok=True)
    name = f"{s['id']}_{s['name']}_Study_QA.docx"
    r.save(os.path.join(OUT, name))
    return name, n


if __name__ == "__main__":
    wanted = set(sys.argv[1:])
    for family, items in (("A", content_a.A), ("B", content_b.B)):
        for s in items:
            if not wanted or s["id"] in wanted:
                print("wrote %s (%d questions)" % build(s, family))
