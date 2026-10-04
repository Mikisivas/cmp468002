# HarmonyVault: Signed, Git-Style Backup History with Honey Directories for the University of Ilorin

HarmonyVault stores UNILORIN's records the way Git stores source code: encrypted blobs, trees and commits, each commit pointing to its parent. Every commit is signed with an Ed25519 key, so nobody (not even an insider who steals the storage key) can insert, remove or edit a backup without detection. It watches decoy 'honey' folders that attract intruders, and it flags unusual change rates with a z-score against past backups.

Built for: **University of Ilorin, Kwara State**. Project folder: `A07-unilorin-harmonyvault`.

Default login after setup: custodian / ChangeMe@468 (reviewer / ChangeMe@468 is read-only)

## What makes this design different

- **Git-style object model**: blob (file), tree (folder listing) and commit (tree + parent + author + message). Identical files are stored once.
- **Ed25519 digital signatures** on every commit, with the public-key fingerprint shown on screen. Verification walks HEAD back to the first commit.
- **AES-256-GCM** per object with keyed object IDs (HMAC-SHA256).
- **Timeline interface** with 'what changed' diffs between backups and per-file history.
- **Honey directories** (Exam_Questions_2026_CONFIDENTIAL, Senate_Approved_Results). One edit refuses the commit.
- **Change-rate anomaly**: z-score of changed files against the last 30 commits (share-of-files rule while history is short).

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A07-unilorin-harmonyvault`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5107 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | UNILORIN's backups form a signed timeline. | `python main.py serve` | Timeline with commits, key fingerprint, portal UP |
| 2 | Someone opens the exam questions folder and copies a file. | `python main.py peek-honey` | Commit backup now: refused, honey file touched |
| 3 | Ransomware quietly encrypts 6 result files. | `python main.py stealth` | Refused: 6 files changed, z = 5 against history |
| 4 | We roll back. | `python main.py restore` | Restore this point on the newest commit. Files byte-identical |
| 5 | Show exactly what changed between two days. | `python main.py (click 'what changed')` | Diff page lists students.csv only |
| 6 | Prove the history is genuine. | `python main.py verify` | Every signature, tree and blob verified |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Keys, users, demo data, honey folders, first commit |
| `python main.py serve` | Console and scheduler |
| `python main.py commit -m TEXT` | Commit a backup |
| `python main.py restore [--commit ID] [--to FOLDER]` | Check out any commit |
| `python main.py diff A B` | Files changed between two commits |
| `python main.py verify` | Verify signatures and every object |
| `python main.py log` | List commits |
| `python main.py peek-honey` | Simulate an intruder editing a honey file |
| `python main.py attack / stealth` | SAFE ransomware simulations |
| `python main.py outage / portal` | Stop or start the demo portal |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`history.py` object store, signatures, detection, restore. `web.py` timeline console and scheduler. `demo.py` demo data and simulations. `main.py` commands. `selftest.py` tests. `config.json` settings.



## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
