# AkureKeyVault: Split-Key Envelope-Encrypted Backup with Custodian Shares for the Federal University of Technology, Akure

AkureKeyVault answers the question 'who can read our backups?'. Backups are sealed automatically with a public key, so the backup server itself cannot decrypt them. The matching private key exists only as three Shamir shares held by the Registrar, the Bursar and the ICT Director. Any two of them together can restore. Keys can be rotated without re-encrypting archives, and a single backup can be crypto-shredded for an NDPA erasure request.

Built for: **Federal University of Technology, Akure, Ondo State**. Project folder: `A10-futa-akure-keyvault`.

Default login after setup: operator / ChangeMe@468 (auditor / ChangeMe@468 is read-only). Demo custodian shares are printed by setup and stored in data/shares_to_print/.

## What makes this design different

- **Envelope encryption.** Each backup gets a fresh AES-256-GCM data key. The data key is wrapped for an X25519 recovery public key (ephemeral ECDH + HKDF-SHA256 + AES-GCM).
- **Shamir's Secret Sharing (2 of 3)** over the prime field 2^521 - 1. Shares carry a checksum so typing mistakes are caught.
- **Unlock ceremony** in the browser: two custodians type their shares. Every ceremony, successful or not, is recorded.
- **Key rotation** issues a new key pair and new shares, then re-wraps every data key. Archives stay untouched and old shares become useless.
- **Crypto-shredding.** Destroying one wrapped data key makes that backup permanently unreadable on every copy, including tape.
- **Three copies** (main store, Obakekere campus, offline tape). Restore falls back to an intact copy if one is damaged.
- **Entropy and extension screening** stops a backup when data looks encrypted.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A10-futa-akure-keyvault`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5110 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | Backups run with no human and no secret key. | `python main.py serve` | Overview: key v1 fingerprint, scheduler backing up |
| 2 | Ransomware hits the bursary share. | `python main.py attack` | Back up now: stopped |
| 3 | The operator alone cannot decrypt. | `python main.py (Backups page, one share only)` | Restore refused |
| 4 | Registrar and Bursar unlock together. | `python main.py restore` | Files restored, ceremony recorded |
| 5 | The ICT Director leaves the university. | `python main.py rotate` | Key v2, data keys re-wrapped, old shares void |
| 6 | A student asks for erasure under NDPA. | `python main.py shred --id 1` | Backup 1 marked SHREDDED and can never be read |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Key pair, shares, users, demo data, first backup |
| `python main.py serve` | Console and scheduler |
| `python main.py backup` | Back up now |
| `python main.py restore [--id N] [--custodians a,b]` | Restore using two demo shares |
| `python main.py rotate` | Rotate the recovery key |
| `python main.py shred --id N` | Crypto-shred one backup |
| `python main.py shares` | Print demo shares |
| `python main.py verify` | Check archive copies |
| `python main.py list` | List backups |
| `python main.py attack / stealth` | SAFE ransomware simulations |
| `python main.py outage / portal` | Stop or start the demo portal |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`keyvault.py` Shamir, envelope encryption, rotation, shredding, monitoring. `app.py` Flask console with unlock ceremony. `demo.py` demo data and simulations. `main.py` commands. `selftest.py` tests. `config.json` settings.



## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
