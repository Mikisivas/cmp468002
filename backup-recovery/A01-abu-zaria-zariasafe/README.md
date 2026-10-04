# ZariaSafe: Versioned-Mirror Backup, Monitoring and Recovery for Ahmadu Bello University

ZariaSafe monitors the university's servers and student portal, keeps encrypted point-in-time versions of registry, bursary, results, LMS and payroll files, refuses to back up data that looks ransomware-encrypted, and restores any version with a measured recovery time.

Built for: **Ahmadu Bello University, Zaria, Kaduna State**. Project folder: `A01-abu-zaria-zariasafe`.

Default login after setup: admin / ChangeMe@468 (auditor / ChangeMe@468 is read-only)

## What makes this design different

- **No web framework.** The console uses Python's built-in `http.server`, so the only packages are `cryptography` and `psutil`.
- **Versioned mirror store.** Each backup is a dated version folder. Only changed files are copied in. A signed manifest records where every file of that version lives, so any point in time can be rebuilt.
- **AES-256-GCM per file** with the file path bound as associated data, so an attacker cannot swap two encrypted files.
- **HMAC-signed manifests** and an **HMAC-chained audit trail**, keyed from a 256-bit master key.
- **Mass-change ransomware detector.** If 30% or more of protected files change or vanish in one interval, or ransomware extensions or ransom notes appear, the backup is held and the clean history is protected.
- **Self-healing.** The scheduler restarts the student portal when it goes down.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A01-abu-zaria-zariasafe`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5101 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | This is ABU's live status. | `python main.py serve` | CPU, memory, disk, portal UP, last backup ok |
| 2 | The student portal crashes. | `python main.py outage` | Within 15 s a critical alert, then the portal is restarted and shows UP |
| 3 | Ransomware encrypts result files quietly. | `python main.py stealth` | Click Run backup now: status HELD, 40% of files changed |
| 4 | A loud attack follows. | `python main.py attack` | Open sample_data: .locked files and a ransom note. Backup is HELD again |
| 5 | We recover. | `python main.py restore` | Versions page, Restore on the newest ok version. Files back, note gone, RTO shown |
| 6 | Prove backups cannot be secretly altered. | `python main.py verify` | Checked objects, zero bad. Audit page shows chain INTACT |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Create keys, users and demo data, then take the first backup |
| `python main.py serve` | Start the console and the scheduler |
| `python main.py backup` | Back up now |
| `python main.py restore [--version V] [--to FOLDER]` | Restore a version |
| `python main.py verify` | Decrypt-check every object, repair from replicas |
| `python main.py list` | List versions |
| `python main.py prune --keep N` | Delete old versions no longer needed |
| `python main.py monitor` | One monitoring cycle |
| `python main.py attack / stealth` | SAFE ransomware simulations on the demo folder only |
| `python main.py outage / portal` | Stop or start the demo student portal |
| `python main.py reset` | Delete all demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`core.py` backup, detector, monitor, audit. `web.py` console and scheduler. `demo.py` demo data and simulations. `main.py` commands. `selftest.py` automatic tests. `config.json` policy (thresholds, RPO, replicas).

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
