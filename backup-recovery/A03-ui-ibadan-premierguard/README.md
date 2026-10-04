# PremierGuard: De-duplicated, Merkle-Verified Snapshot Backup for the University of Ibadan

PremierGuard cuts every protected file into content-defined chunks, stores each unique chunk once (encrypted with ChaCha20-Poly1305), and seals each snapshot with a Merkle root that is copied to a separate anchor location. It blocks snapshots when files stop compressing like text, which is how encrypted ransomware output behaves, and it monitors the student portal with an adaptive CPU baseline.

Built for: **University of Ibadan, Oyo State**. Project folder: `A03-ui-ibadan-premierguard`.

Default login after setup: admin / ChangeMe@468 (observer / ChangeMe@468 is read-only)

## What makes this design different

- **Single-page dashboard over a JSON API.** The browser calls the API with fetch(). Every POST needs an X-CSRF-Token header.
- **Content-defined chunking** with a Gear rolling hash (2 KiB to 64 KiB chunks, about 8 KiB average). Inserting one line at the start of a 250 KB file changed 1 chunk out of 31 in testing.
- **De-duplication with keyed chunk IDs** (HMAC-SHA256), so the store does not reveal whether a known file is inside.
- **ChaCha20-Poly1305** per chunk, keys derived from one root key with HKDF-SHA256 (separate keys for chunk IDs, chunk data and snapshot trees).
- **Merkle tree per snapshot.** The root is written to an anchor log kept elsewhere (the Registrar's office in the demo). Restore refuses a tree whose root does not match.
- **Compressibility detector.** CSV and text files normally compress to under 40%. Ciphertext does not compress. Three or more incompressible text files block the snapshot.
- **EWMA CPU baseline** instead of a fixed threshold.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A03-ui-ibadan-premierguard`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5103 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | This is UI's live dashboard. | `python main.py serve` | CPU with its normal level, portal UP, de-dup saving |
| 2 | The portal fails. | `python main.py outage` | DOWN event within 15 s, then UP after automatic restart |
| 3 | Quiet ransomware. | `python main.py stealth` | Snapshot now: status blocked, 6 files look encrypted |
| 4 | Loud ransomware. | `python main.py attack` | .locked files and a ransom note in sample_data |
| 5 | Recover. | `python main.py restore` | Restore on the newest ok snapshot. Files back byte-for-byte |
| 6 | Prove nothing was altered. | `python main.py verify` | Snapshots and chunks verified against the Merkle anchors |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Keys, accounts, demo data, first snapshot |
| `python main.py serve` | Dashboard, API and scheduler |
| `python main.py snapshot` | Snapshot now |
| `python main.py restore [--id N] [--to FOLDER]` | Restore a snapshot |
| `python main.py verify` | Check Merkle roots and every chunk, repair from mirrors |
| `python main.py gc --keep N` | Expire old snapshots and delete unreferenced chunks |
| `python main.py list` | List snapshots |
| `python main.py monitor` | One monitoring sample |
| `python main.py attack / stealth` | SAFE ransomware simulations |
| `python main.py outage / portal` | Stop or start the demo portal |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`engine.py` chunking, encryption, Merkle trees, detector, monitoring. `server.py` API, page and scheduler. `demo.py` demo data and simulations. `main.py` commands. `selftest.py` tests. `config.json` policy.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
