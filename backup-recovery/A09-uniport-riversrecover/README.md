# RiversRecover: Continuous Data Protection and Point-in-Time Recovery for the University of Port Harcourt Results Database

RiversRecover protects a live examination results database instead of a folder of files. Every insert, update and delete is captured by database triggers, shipped every 5 seconds to an encrypted recovery store, and can be replayed to rebuild the database as it was at any second. Senate-approved results cannot be edited without a logged amendment window, and a burst of grade changes freezes the whole database until a DBA investigates.

Built for: **University of Port Harcourt, Choba, Rivers State**. Project folder: `A09-uniport-riversrecover`.

Default login after setup: dba / ChangeMe@468 (auditor / ChangeMe@468 is read-only)

## What makes this design different

- **Continuous data protection.** SQLite triggers write a row image of every change into a journal. Recovery point objective is the 5-second ship interval, not the last nightly backup.
- **Point-in-time recovery** to any second: newest encrypted base snapshot before that moment + replay of the journal. A recovery starts a new timeline, so rolled-back changes are never replayed by mistake.
- **Hash-chained, encrypted journal segments** (AES-256-GCM with the previous segment's SHA-256 bound as associated data).
- **Senate lock.** Database triggers refuse any edit or delete of an approved result unless a DBA opens a short, logged amendment window.
- **Freeze switch.** 40 result changes in 60 seconds, or 10 results turned into an A, freezes every table through triggers.
- **Online base snapshots** with SQLite's backup API (no downtime), copied to two other locations.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A09-uniport-riversrecover`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5109 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | This is UNIPORT's live results database. | `python main.py serve` | Writable, row counts, changes-per-minute chart |
| 2 | A staff member edits a Senate-approved grade. | `python main.py grade-tamper` | Approved rows refused. After 33 current grades become A: FROZEN |
| 3 | They try to delete the evidence. | `python main.py mass-delete` | DATABASE FROZEN error |
| 4 | We roll back to 2 minutes ago. | `python main.py (Point-in-time recovery page)` | Pick a time before the tamper. Database rebuilt and writable |
| 5 | Ransomware encrypts the database file. | `python main.py ransomware` | Dashboard: LIVE DATABASE UNREADABLE |
| 6 | We recover to the last second. | `python main.py recover` | Rebuilt from base + journal, no shipped change lost |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Create and seed the live database, ship the journal, take a base snapshot |
| `python main.py serve` | Console and journal shipper |
| `python main.py recover [--to TIME]` | Point-in-time recovery (default: now) |
| `python main.py ship / base` | Ship journal now / take a base snapshot |
| `python main.py verify` | Check the journal chain and base hashes |
| `python main.py unfreeze` | Lift a freeze after investigation |
| `python main.py normal-activity / grade-tamper / mass-delete / ransomware` | Simulations |
| `python main.py status` | Freeze state and row count |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`cdp.py` triggers, journal shipping, freeze, base snapshots, PITR. `app.py` Flask console and shipper. `main.py` commands and simulations. `selftest.py` tests. `config.json` thresholds and locations.



## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
