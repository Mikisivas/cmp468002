"""Builds the 20 CMP 468 project reports (Word .docx) from:
  * content_a.py / content_b.py  (system-specific text),
  * literature.py                (verified 2021-2026 sources),
  * each system's results/selftest.json (measured results).

Usage:  pip install python-docx matplotlib
        python build_reports.py            (all reports)
        python build_reports.py A03 B07    (selected reports)
"""
import json
import os
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

import content_a  # noqa: E402
import content_b  # noqa: E402
import docx_helpers  # noqa: E402
import literature as lit  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.dirname(HERE)
FIGS = os.path.join(OUT, "figures")
docx_helpers.FIG_DIR = FIGS
FAMILY = {"A": ("backup-recovery", lit.A_REFS, lit.A_REVIEW, content_a.COMMON_CMP),
          "B": ("conflict-early-warning", lit.B_REFS, lit.B_REVIEW, content_b.COMMON_CMP)}
COLOURS = ["#dbeafe", "#dcfce7", "#fef3c7", "#fce7f3", "#ede9fe", "#e0f2fe"]


def diagram(s, path):
    """Layered architecture diagram: each layer is a row, arrows connect consecutive layers."""
    layers = s["layers"]
    fig, ax = plt.subplots(figsize=(9, 1.25 * len(layers) + 0.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, len(layers))
    ax.axis("off")
    centres = []
    for i, layer in enumerate(layers):
        y = len(layers) - i - 0.5
        w = min(2.9, 9.2 / len(layer) - 0.3)
        row = []
        for j, name in enumerate(layer):
            x = (j + 0.5) * 10 / len(layer)
            ax.add_patch(FancyBboxPatch((x - w / 2, y - 0.28), w, 0.56, boxstyle="round,pad=0.04",
                                        facecolor=COLOURS[i % len(COLOURS)], edgecolor="#334155", linewidth=1))
            ax.text(x, y, name, ha="center", va="center", fontsize=8.5, wrap=True)
            row.append((x, y))
        centres.append(row)
    for upper, lower in zip(centres, centres[1:]):
        for (x1, y1) in upper:
            for (x2, y2) in lower:
                if len(upper) * len(lower) > 6 and abs(x1 - x2) > 4:
                    continue
                ax.add_patch(FancyArrowPatch((x1, y1 - 0.3), (x2, y2 + 0.3), arrowstyle="-|>", mutation_scale=9,
                                             color="#64748b", linewidth=0.8))
    ax.set_title(f"{s['name']} architecture", fontsize=11, fontweight="bold")
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def results_chart(s, res, path):
    """Bar chart of test outcomes by group (security, recovery or detection, function)."""
    groups = {"Security controls": 0, "Detection / analytics": 0, "Recovery / function": 0}
    sec = re.compile(r"refus|reject|forg|replay|signature|password|lock|csrf|role|cannot|sign-in|plain text|token|tamper|edited|"
                     r"spoof|stored|encrypt|deleted|forged|privacy|k=|never", re.I)
    det = re.compile(r"detect|held|block|abort|anomal|spike|hotspot|alert|flag|escalat|warn|outage|offline|relapse|breach|"
                     r"approach|deviation|probable|watch|risk|auc|pai|back-test|spearman|chance", re.I)
    for t in res["tests"]:
        key = "Security controls" if sec.search(t["test"]) else "Detection / analytics" if det.search(t["test"]) else "Recovery / function"
        groups[key] += 1
    fig, ax = plt.subplots(figsize=(6.5, 2.6))
    ax.barh(list(groups), list(groups.values()), color=["#3b82f6", "#f59e0b", "#10b981"])
    for i, v in enumerate(groups.values()):
        ax.text(v + 0.1, i, str(v), va="center", fontsize=9)
    ax.set_xlabel("automated tests passed")
    ax.set_title(f"{s['name']}: {res['passed']} of {res['total']} automated tests passed", fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return groups


EXCERPTS = {
    "A01": ("core.py", "detect_ransomware"), "A02": ("core.py", "validate"), "A03": ("engine.py", "chunk"),
    "A04": ("server.py", "signed"), "A05": ("vault.py", "split"), "A06": ("sahel.py", "delta"),
    "A07": ("history.py", "verify_chain"), "A08": ("shield.py", "decide"), "A09": ("cdp.py", "detect"),
    "A10": ("keyvault.py", "combine"), "B01": ("grid.py", "ahp"), "B02": ("kde.py", "density"),
    "B03": ("pipeline.py", "merge"), "B04": ("fence.py", "accept"), "B05": ("hawkes.py", "loglik"),
    "B06": ("ledger.py", "seal_if_due"), "B07": ("tpi.py", "tpi_value"), "B08": ("cases.py", "can"),
    "B09": ("trust.py", "credibility"), "B10": ("hub.py", "sync"),
}


def excerpt(path, func):
    import ast
    src = open(path, encoding="utf-8").read()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == func:
            lines = src.splitlines()[node.lineno - 1 - len(node.decorator_list):node.end_lineno]
            return "\n".join(lines)
    raise KeyError(func)


def fill(template, refs):
    return re.sub(r"\{(\w+)\}", lambda m: refs[m.group(1)][1], template)


def build(s, family):
    folder, refs, review, common_cmp = FAMILY[family]
    sysdir = os.path.join(ROOT, folder, s["folder"])
    res = json.load(open(os.path.join(sysdir, "results", "selftest.json")))
    fig_arch = f"{s['id']}_architecture.png"
    fig_res = f"{s['id']}_tests.png"
    diagram(s, os.path.join(FIGS, fig_arch))
    groups = results_chart(s, res, os.path.join(FIGS, fig_res))
    metrics = [[a, str(b).replace("True", "yes").replace("False", "no")] for a, b in s["metrics"](res)]
    place = ("the " + s["place"]) if s["place"].startswith(("University", "Federal")) else s["place"]
    design_line = f"Its design combines {s['subtitle'][0].lower() + s['subtitle'][1:]}."
    short = [m for m in metrics if len(m[1]) <= 70][:4]
    spec = json.load(open(os.path.join(HERE, "specs", f"{s['id']}.json"), encoding="utf-8"))
    used = set()
    r = docx_helpers.Report()
    r.title_page(s["title"], s["subtitle"])

    r.h1("DECLARATION")
    r.p("I declare that this project report and the accompanying software were written by me as part of the requirements of CMP 468 "
        "(Computer Security). Every source used has been cited. All literature cited in this report was published between 2021 and "
        "2026. All test results reported in Chapter Four were produced by the automated test program supplied with the software.")
    r.p("Signature: ____________________          Date: ____________________")
    r.page_break()

    r.h1("ABSTRACT")
    if family == "A":
        r.p(f"Universities in Nigeria run admissions, fees, results, learning and payroll on computers that can fail or be attacked. "
            f"This project designed, built and tested {s['name']} for {place}. {design_line} "
            f"The system was implemented in Python and evaluated with an automated test suite that simulates outages, quiet and loud "
            f"ransomware, tampering and misuse. All {res['total']} tests passed. Key measurements: "
            + "; ".join(f"{m[0]}: {m[1]}" for m in short) + ". "
            f"The design shows that a Nigerian university ICT unit can protect its records with free software on ordinary hardware.")
    else:
        r.p(f"Farmer-herder conflict in Nigeria destroys lives, livelihoods and food supply. Early warning helps only when it is timely, "
            f"trusted and secure. This project designed, built and tested {s['name']} for {place}. {design_line} "
            f"The system was implemented in Python and evaluated with an automated test suite on synthetic data that follows "
            f"documented conflict patterns, including attacks on the system itself. All {res['total']} tests passed. Key measurements: "
            + "; ".join(f"{m[0]}: {m[1]}" for m in short) + ". "
            f"The results show the design works as specified; field validation with real data is the next step.")
    r.p("**Keywords:** " + (", ".join(["backup and recovery", "ransomware", "encryption", "integrity", "monitoring", "RTO", "Nigerian universities", "NDPA 2023"])
                            if family == "A" else ", ".join(["early warning", "farmer-herder conflict", "GIS", "information security", "privacy", "Nigeria", "NDPA 2023"])) + ".")
    r.page_break()
    r.h1("TABLE OF CONTENTS")
    r.toc()
    r.page_break()

    # ---------------------------------------------------------------- chapter 1
    r.h1("CHAPTER ONE: INTRODUCTION")
    r.h2("1.1 Background of the Study")
    r.p(s["context"])
    if family == "A":
        r.p("Ransomware changed what backup means. Older plans assumed that disks fail by accident; modern attackers encrypt "
            "production data and then go after the backups. Recovery is therefore a security function, matching the Recover "
            "function of the NIST Cybersecurity Framework 2.0 (2024). The Nigeria Data Protection Act 2023 also makes the university "
            "a data controller that must keep personal data confidential, accurate and available.")
    else:
        r.p("Nigerian farmer-herder conflict is driven by competition for land and water, changing herd mobility, weak institutions "
            "and perceived injustice. Early warning systems try to detect rising risk early enough for mediation, patrols or "
            "community action. They handle sensitive data (who reported what) and are themselves targets of manipulation, so they "
            "are a computer security problem as much as a data problem.")
    r.h2("1.2 Statement of the Problem")
    r.bullets(s["problems"])
    r.h2("1.3 Aim and Objectives")
    r.p(f"The aim is to design, implement and evaluate {s['name']}, a secure system for {place}. The objectives are to:")
    r.bullets(s["objectives"], numbered=True)
    r.h2("1.4 Scope and Limitations")
    r.p(s["scope"] + " The system was tested on one computer; the README describes deployment on other computers.")
    r.h2("1.5 Significance of the Study")
    r.p(f"{s['name']} gives {place} a free, auditable tool that runs on ordinary hardware, and turns CMP 468 topics into working "
        f"controls. Its automated test suite lets any future maintainer prove that the controls still work.")
    r.h2("1.6 Relation to the CMP 468 Course Outline")
    rows = [list(x) for x in common_cmp]
    rows[5][1] = s.get("keys_used", rows[5][1]) if family == "A" else rows[5][1]
    r.table(f"Mapping of CMP 468 topics to {s['name']}", ["CMP 468 topic", f"Where it appears in {s['name']}"], rows, widths=[5, 11])
    r.page_break()

    # ---------------------------------------------------------------- chapter 2
    r.h1("CHAPTER TWO: LITERATURE REVIEW")
    r.p("This review covers only studies published from 2021 to 2026. Every source was checked against a publisher or index page.")
    r.h2("2.1 Conceptual Framework")
    if family == "A":
        r.p("The study rests on the Confidentiality, Integrity and Availability (CIA) triad. A backup that an attacker can read fails "
            "confidentiality; one that can be silently altered fails integrity; one that cannot be restored in time fails "
            "availability. Two measures turn availability into numbers: the Recovery Point Objective (how much data may be lost) and "
            "the Recovery Time Objective (how long restoration may take).")
    else:
        r.p("The study uses the early warning chain: collect signals, analyse risk, warn the right people, and respond. Each link "
            "has security needs: signals must be authentic, analysis must be on untampered data, warnings must reach people quickly, "
            "and the identities of informants must stay confidential.")
    for i, (heading, keys, text) in enumerate(review, 2):
        r.h2(f"2.{i} {heading}")
        r.p(fill(text, refs))
        used.update(keys)
    n = len(review) + 2
    r.h2(f"2.{n} Work Closest to This Design")
    r.p(s["closest_text"])
    used.update(s["closest"])
    r.h2(f"2.{n + 1} Summary of Reviewed Works and Research Gap")
    rows = []
    for k in sorted(used, key=lambda k: refs[k][0].lower()):
        author = refs[k][0].split(". (")[0]
        year = re.search(r"\((\d{4})\)", refs[k][0]).group(1)
        rows.append([f"{author.split(',')[0]} ({year})", refs[k][1].split(") ", 1)[-1][:160]])
    r.table("Summary of reviewed works", ["Study", "What it contributes"], rows, widths=[4, 12])
    r.p("**Research gap.** " + s["gap"])
    r.page_break()

    # ---------------------------------------------------------------- chapter 3
    r.h1("CHAPTER THREE: METHODOLOGY AND SYSTEM DESIGN")
    r.h2("3.1 Research Methodology")
    r.p("The project follows Design Science Research: identify the problem, define objectives, design and build an artefact, "
        "demonstrate it, and evaluate it. Evaluation uses an automated test program (selftest.py) that resets the system, runs "
        "normal use, simulated attacks and failures, and records each outcome and measurement in results/selftest.json. "
        + ("Data are synthetic university records." if family == "A" else
           "Data are synthetic, generated to follow documented seasonal and retaliation patterns, so results show how the system "
           "behaves, not how accurate it would be in the field."))
    r.h2("3.2 Requirements")
    r.table("Functional requirements", ["#", "Requirement"], [[f"FR{i + 1}", x] for i, x in enumerate(s["fr"])], widths=[1.5, 14.5])
    r.table("Non-functional requirements", ["#", "Requirement"], [[f"NFR{i + 1}", x] for i, x in enumerate(s["nfr"])], widths=[1.5, 14.5])
    r.h2("3.3 System Architecture")
    r.figure(fig_arch, f"{s['name']} architecture (data flows from top to bottom)", 15)
    r.table("Software components", ["File", "Responsibility"], s["components"], widths=[4, 12])
    r.p("The main design decisions, and how they differ from the earlier VarsityShield and Zaman Lafiya projects, are:")
    r.bullets(spec["design"])
    r.h2("3.4 Security Design")
    r.p("Each threat considered is matched to the control that addresses it. Tests in Chapter Four exercise these controls.")
    r.table("Threats and controls", ["Threat", "Control in " + s["name"]], s["threats"], widths=[6, 10])
    if family == "A":
        r.p("Cryptographic keys: " + s["keys_used"])
    r.h2("3.5 Algorithms")
    for i, (h, text) in enumerate(s["algorithms"], 1):
        r.h3(f"3.5.{i} {h}")
        r.p(text)
    r.h2("3.6 Tools and Technologies")
    req = open(os.path.join(sysdir, "requirements.txt")).read().strip()
    pkgs = [l.split(">=")[0] for l in req.splitlines() if l and not l.startswith("#")]
    r.p("Language: Python 3.10 or newer. Storage: SQLite. Third-party packages: " + (", ".join(pkgs) if pkgs else "none (standard library only)")
        + ". Launchers: Windows batch files (1_SETUP, 2_START, 3_DEMO_MENU, 4_SELFTEST) and run.sh for Linux and macOS.")
    r.page_break()

    # ---------------------------------------------------------------- chapter 4
    r.h1("CHAPTER FOUR: IMPLEMENTATION, TESTING AND RESULTS")
    r.h2("4.1 Implementation Environment")
    r.p(f"The system was developed and tested with Python 3.11 on Linux and is written to run unchanged on Windows 10/11. Its web "
        f"interface runs at http://127.0.0.1:{s['port']}. Setup takes about ten minutes with 1_SETUP.bat; the README in the project "
        f"folder gives every step and a defence demonstration script.")
    r.h2("4.2 Operation and Demonstration")
    r.p(spec["intro"])
    r.table("Demonstration scenario used for the defence", ["Step", "Command (python main.py ...)", "What is observed"],
            [[x[0], x[1], x[2]] for x in spec["script"]], widths=[5, 4.5, 6.5])
    r.h2("4.3 Test Plan and Results")
    r.p(f"The automated test program ran {res['total']} tests. {res['passed']} passed.")
    r.table("Automated test results", ["#", "Test", "Result", "Evidence"],
            [[str(i + 1), t["test"], "PASS" if t["passed"] else "FAIL", t["detail"][:120]] for i, t in enumerate(res["tests"])],
            widths=[1, 7, 1.6, 6.4])
    r.figure(fig_res, "Automated tests by category", 12)
    r.h2("4.4 Measured Results")
    r.table("Key measurements", ["Measure", "Result"], metrics, widths=[7, 9])
    r.h2("4.5 Discussion")
    r.p(s["discussion"])
    r.p(f"Of the tests, {groups['Security controls']} exercised security controls, {groups['Detection / analytics']} exercised "
        f"detection or analytics, and {groups['Recovery / function']} exercised recovery or core function.")
    r.page_break()

    # ---------------------------------------------------------------- chapter 5
    r.h1("CHAPTER FIVE: SUMMARY, CONCLUSION AND RECOMMENDATIONS")
    r.h2("5.1 Summary")
    r.p(f"This project built {s['name']} for {place}. {design_line} It met its objectives and "
        f"passed all {res['total']} automated tests.")
    r.h2("5.2 Conclusion")
    r.p(f"{s['name']} shows that the security problem described in Chapter One can be addressed with free software and modest "
        f"hardware, provided the design treats " + ("recovery" if family == "A" else "the warning data") + " as something attackers "
        f"will target. The limits stated in Section 1.4 still apply.")
    r.h2("5.3 Recommendations")
    r.bullets(s["recommendations"])
    r.h2("5.4 Contribution to Knowledge")
    r.p(s["gap"].replace("None of the reviewed systems", "This project provides a design that the reviewed systems do not")
        if s["gap"].startswith("None") else "This project addresses the gap identified in Chapter Two: " + s["gap"])
    r.h2("5.5 Suggestions for Further Work")
    r.bullets(s["further"])
    r.page_break()

    r.h1("REFERENCES")
    r.references([refs[k][0] for k in used])
    r.h2("Standards and Legal Instruments Consulted")
    r.references(lit.STANDARDS)
    r.page_break()
    r.h1("APPENDIX A: HOW TO RUN THE SYSTEM")
    r.bullets([f"Copy the folder {folder}/{s['folder']} to the computer.", "Install Python 3.10 or newer with 'Add python.exe to PATH' ticked.",
               "Double-click 1_SETUP.bat, then 2_START.bat, and open " + f"http://127.0.0.1:{s['port']}.",
               "Use 3_DEMO_MENU.bat for the defence demonstration and 4_SELFTEST.bat to regenerate the results in Chapter Four."], numbered=True)
    r.h1("APPENDIX B: SOURCE CODE STRUCTURE")
    r.table(f"{s['name']} source files", ["File", "Purpose"], s["components"], widths=[4, 12])
    file_, func = EXCERPTS[s["id"]]
    r.h1("APPENDIX C: CODE EXCERPT")
    r.p(f"The function {func} from {file_}, the heart of the design described in Section 3.5.")
    r.code(excerpt(os.path.join(sysdir, file_), func))
    name = f"{s['id']}_{s['name']}_Report.docx"
    path = os.path.join(OUT, name)
    r.save(path)
    return name, res["passed"], res["total"]


def main(wanted):
    os.makedirs(FIGS, exist_ok=True)
    for family, items in (("A", content_a.A), ("B", content_b.B)):
        for s in items:
            if wanted and s["id"] not in wanted:
                continue
            name, p, t = build(s, family)
            print(f"wrote {name}  ({p}/{t} tests)")


if __name__ == "__main__":
    main(set(sys.argv[1:]))
