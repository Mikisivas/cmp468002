# BeninVault: Erasure-Coded Encrypted Backup and Service-Level Monitoring for the University of Benin

BeninVault encrypts each backup and splits it into two data shards and one parity shard stored in three different places (Ugbowo ICT Centre, Ekehuan campus, and a cloud bucket). Any one place can burn, flood or be stolen and the backup still restores. It refuses backups that show a rename burst, a ransom note or unreadable text files, and it reports each service's uptime against its SLA target.

Built for: **University of Benin, Benin City, Edo State**. Project folder: `A05-uniben-beninvault`.

Default login after setup: admin / ChangeMe@468 (auditor / ChangeMe@468 is read-only)

## What makes this design different

- **2 + 1 XOR erasure coding** across three sites. Storage cost is 1.5 times the archive, instead of 3 times for three full copies.
- **Scrubbing**: a scheduled job checks every shard's SHA-256 and rebuilds a missing or damaged shard from the other two.
- **AES-256-GCM** with the backup ID bound as associated data, key derived by **scrypt** (n = 2^15, r = 8).
- **Rename-burst detector**: old file names that reappear with a new extension (students.csv to students.csv.locked) in one interval.
- **Printable-text check** for CSV and TXT files, plus ransom-note detection.
- **SLA uptime chart** per service over 24 hours against a target (99.5% for the portal).
- **Flask with Jinja template files** and a SHA-256 linked activity trail.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A05-uniben-beninvault`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5105 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | UNIBEN's backups live in three buildings. | `python main.py serve` | Three site cards, SLA bars green |
| 2 | The ICT Centre server room burns. | `python main.py lose-site A` | Site A card shows missing shards |
| 3 | We still restore everything. | `python main.py restore` | Restore uses shards B and P. Files byte-identical |
| 4 | And we rebuild the lost site. | `python main.py scrub` | Scrub rebuilt N shards. Site A healthy again |
| 5 | Ransomware renames our files. | `python main.py attack` | Back up now: refused, rename burst and ransom note |
| 6 | The portal goes down for a while. | `python main.py outage` | SLA bar for the portal turns red below the 99.5% line |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Keys, users, demo data, first backup |
| `python main.py serve` | Console and scheduler |
| `python main.py backup` | Back up now |
| `python main.py restore [--id ID] [--to FOLDER]` | Restore from any two healthy shards |
| `python main.py scrub` | Check shards and rebuild missing ones |
| `python main.py lose-site A|B|P` | Wipe one storage site (simulation) |
| `python main.py sla / check` | Show uptime against target / run one check |
| `python main.py list` | List backups |
| `python main.py attack / stealth` | SAFE ransomware simulations |
| `python main.py outage / portal` | Stop or start the demo portal |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`vault.py` encryption, erasure coding, scrubbing, detection, SLA. `app.py` Flask console and scheduler. `templates/` page templates. `demo.py` demo data and simulations. `main.py` commands. `selftest.py` tests. `config.json` sites, SLA targets, thresholds.



## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
