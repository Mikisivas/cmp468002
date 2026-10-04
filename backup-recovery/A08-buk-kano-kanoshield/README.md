# KanoShield: WORM Backup Vault with Four-Eyes Approval and Two-Factor Sign-In for Bayero University Kano

KanoShield treats backup as a governance problem. Backups are sealed into a write-once vault that the database itself protects. Restoring over live records or releasing a retention lock early needs two different administrators. Administrators sign in with a password and a 6-digit authenticator code. The system also blocks ransomware-looking data and watches the student portal.

Built for: **Bayero University, Kano, Kano State**. Project folder: `A08-buk-kano-kanoshield`.

Default login after setup: ictdirector or deputyregistrar / ChangeMe@468 + authenticator code (run `python main.py code --user ictdirector` to see it). auditor / ChangeMe@468 is read-only.

## What makes this design different

- **WORM vault in SQLite.** Database triggers refuse any UPDATE of a sealed backup and any DELETE before its retention date (30 days by default).
- **Four-eyes rule.** Restore and early release are requests. A second, different admin must approve. Self-approval raises a critical alert.
- **TOTP two-factor sign-in** implemented from RFC 6238 (checked against the RFC test vector) and compatible with phone authenticator apps.
- **scrypt password hashing** and brute-force lock after 5 failures in 15 minutes, with an alert.
- **AES-256-GCM per file** with backup ID and path bound as associated data, HMAC-sealed manifests.
- **Vault replication** with SQLite's online backup API to a second campus and an offline USB copy.
- **Entropy screening** blocks a backup when three or more files look encrypted.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A08-buk-kano-kanoshield`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5108 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | Admins need a password and a phone code. | `python main.py code --user ictdirector` | Sign in with ictdirector + the 6 digits |
| 2 | Can an angry insider delete our backups? | `python main.py try-delete --id 1` | WORM: retention lock still active |
| 3 | Ransomware hits the registry share. | `python main.py attack` | Seal a backup now: BLOCKED |
| 4 | The ICT Director requests a restore. | `python main.py (WORM vault page, Request restore)` | Approvals shows 1 pending; ictdirector cannot approve it |
| 5 | The Deputy Registrar approves. | `python main.py (sign in as deputyregistrar, Approve)` | Files restored, alert names both people |
| 6 | Prove the vault is intact. | `python main.py verify` | All blobs checked, zero problems |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Keys, users with TOTP secrets, demo data, first sealed backup |
| `python main.py serve` | Console and scheduler |
| `python main.py code --user NAME` | Current 6-digit code (demo without a phone) |
| `python main.py backup` | Seal a backup |
| `python main.py verify` | Decrypt and hash-check the vault |
| `python main.py replicate` | Copy the vault to the other locations |
| `python main.py try-delete --id N` | Show the WORM lock in action |
| `python main.py list` | List sealed backups |
| `python main.py attack / stealth` | SAFE ransomware simulations |
| `python main.py outage / portal` | Stop or start the demo portal |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`shield.py` vault, WORM triggers, TOTP, approvals, monitoring. `app.py` Flask console and scheduler. `demo.py` demo data and simulations. `main.py` commands. `selftest.py` tests. `config.json` retention, limits, services.



## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
