# LionKeep: Full and Differential Encrypted Backup with GFS Rotation for the University of Nigeria

LionKeep protects UNN registry, bursary, results, LMS and payroll files with classic full + differential encrypted archives, three storage copies and Grandfather-Father-Son retention. It checks every file's signature and entropy before backup, keeps suspicious files out of the archives, and watches the student portal.

Built for: **University of Nigeria, Nsukka, Enugu State**. Project folder: `A02-unn-nsukka-lionkeep`.

Default login after setup: admin / ChangeMe@468 (operator and viewer have the same demo password)

## What makes this design different

- **Flask web dashboard** with three roles: admin (restore), operator (backup and verify), viewer (read only).
- **Full + differential archives.** A full ZIP holds everything. Each differential holds only files changed since the last full, so a restore never needs more than two archives.
- **Fernet encryption** (AES-128-CBC with HMAC-SHA256) under a key derived by PBKDF2 with 600,000 iterations and a random salt.
- **Grandfather-Father-Son retention**: 7 daily sons, 5 Friday fathers, 12 month-end grandfathers.
- **File-signature and entropy validation.** PDFs must start with %PDF, CSVs must still be UTF-8 text, and plain files above 7.2 bits per byte are treated as encrypted. Suspicious files are quarantined instead of overwriting the clean copy. Three or more aborts the backup.
- **SHA-256 hash-linked activity log** and per-account lockout after 5 wrong passwords.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A02-unn-nsukka-lionkeep`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5102 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | This is UNN's ICT overview. | `python main.py serve` | CPU, memory, disk, services UP, last archive |
| 2 | The portal goes down. | `python main.py outage` | Critical alert, the scheduler restarts it |
| 3 | Ransomware quietly encrypts results. | `python main.py stealth` | Click Differential backup now: aborted. Quarantine page lists 6 files |
| 4 | Full attack. | `python main.py attack` | sample_data shows .locked files and a note |
| 5 | Recover from full + differential. | `python main.py restore` | Archives page, Restore. Files back, restore time shown on Overview |
| 6 | Prove the archives are intact. | `python main.py verify` | Verify all archives: ok count, zero lost. Activity log hash chain INTACT |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Keys, users, demo data, first full archive |
| `python main.py serve` | Dashboard and scheduler |
| `python main.py full / diff` | Take a full or differential archive |
| `python main.py restore [--id N] [--to FOLDER]` | Restore full + differential chain |
| `python main.py verify` | Hash and decrypt every archive, repair from copies |
| `python main.py rotate` | Apply Grandfather-Father-Son retention |
| `python main.py list` | List archives |
| `python main.py monitor` | One monitoring cycle |
| `python main.py attack / stealth` | SAFE ransomware simulations |
| `python main.py outage / portal` | Stop or start the demo portal |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`core.py` archives, validation, GFS, monitoring, log. `app.py` Flask dashboard and scheduler. `demo.py` demo data and simulations. `main.py` commands. `selftest.py` tests. `config.json` policy.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
