# KwaraHarmony: Early Response and Mediation Case Management with Attribute-Based Access Control for Kwara State

An early warning that nobody acts on prevents nothing. KwaraHarmony follows each incident from report to closure: verification, mediator assignment, mediation, written agreement, 30 days of monitoring, and closure. It flags missed response deadlines, treats a new incident during monitoring as a relapse that reopens mediation, and ranks LGAs by open cases and relapses. Officers only see their own LGAs, mediators only their own cases, field notes are encrypted per case, and the public map export cannot reveal any single family's location.

Built for: **Kwara State (Baruten, Kaiama, Moro, Edu, Patigi, Asa, Ifelodun and 5 other LGAs)**. Project folder: `B08-kwara-harmony`.

Default login after setup: password ChangeMe@468 for supervisor, officer_north, officer_south, mediator_aisha, mediator_tunde, auditor

## What makes this design different

- **Workflow state machine** with an explicit table of allowed moves and the roles allowed to make each one. Skipping a step is impossible.
- **Business rules**: an agreement needs written terms and a compensation figure. A case cannot close before 30 days of monitoring.
- **Attribute-based access control (ABAC)**: decisions use the user's role, their LGAs, the case's LGA and whether they are the assigned mediator. Every refusal is logged.
- **Per-case encryption** of field notes with AES-256-GCM, keys derived by HKDF from a master key and the case number.
- **Relapse detection**: a new case in an LGA with an agreement under monitoring reopens mediation and alerts the supervisor.
- **Service-level monitoring**: verify within 24 h, assign within 48 h, first meeting within 7 days.
- **Privacy-preserving GeoJSON export**: locations snapped to a 10 km grid and cells with fewer than 3 cases suppressed (k-anonymity).

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B08-kwara-harmony`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5208 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | Sign in as officer_north. | `python main.py serve` | Only northern LGA cases are listed |
| 2 | Open a case and push it through the workflow. | `python main.py (case page)` | Each role sees only the moves it may make |
| 3 | The mediator writes a confidential note. | `python main.py (case page, as mediator_aisha)` | Note readable by her; mediator_tunde and the auditor are refused |
| 4 | Trouble returns in a community under monitoring. | `python main.py relapse` | Dashboard: RELAPSE alert, case back in mediation, LGA risk rises |
| 5 | Share data with NGOs safely. | `python main.py export` | Grid-snapped counts only; small cells suppressed |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Users with LGA attributes and 60 synthetic cases |
| `python main.py serve` | Web app |
| `python main.py relapse` | Simulate a relapse |
| `python main.py kpis` | Performance indicators |
| `python main.py sla` | Service-level breaches |
| `python main.py risk` | LGA risk |
| `python main.py export` | Public GeoJSON |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`cases.py` workflow, ABAC policy, encrypted notes, relapse detection, SLA, risk, export. `app.py` Flask app. `geo.py` geography helpers. `main.py` commands and synthetic history. `selftest.py` tests. `config.json` LGAs, SLA targets, export settings.

## Data notice

Cases, names of mediators and LGA positions are fictional or approximate.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
