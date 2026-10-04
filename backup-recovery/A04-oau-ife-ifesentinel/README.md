# IfeSentinel: Agent-Based Monitoring and Zero-Knowledge Backup Across OAU Computers

IfeSentinel is built for many computers at once. A small agent runs on each registry server, bursary PC or lab machine. It sends signed heartbeats to one central console, watches decoy (canary) files, and uploads backups that it encrypts itself, so the central server stores only ciphertext. When ransomware touches a computer, that computer is isolated and its clean backup history is frozen. The demo runs three agents (Registry, Bursary, CSE lab) on one laptop. Note: selftest.py leaves test data behind, so run 1_SETUP.bat again after it.

Built for: **Obafemi Awolowo University, Ile-Ife, Osun State**. Project folder: `A04-oau-ife-ifesentinel`.

Default login after setup: admin / ChangeMe@468 (helpdesk / ChangeMe@468 is read-only)

## What makes this design different

- **Agent and central server.** One console shows every enrolled computer as a card: online, offline or isolated.
- **One-time enrolment tokens.** A computer joins with a token that works once. The server then issues it a 256-bit secret.
- **Signed requests with replay protection.** Each agent request carries HMAC-SHA256 over method, path, timestamp, nonce and body hash. Requests older than 120 s or with a reused nonce are refused.
- **Zero-knowledge storage.** The AES-256-GCM data key is created on the agent and never sent. A stolen server disk exposes no student record.
- **Canary (decoy) files** named to be hit first by ransomware ("!000_Staff_Salaries_2026.xlsx"). Any change isolates the computer. Text files turning binary also isolates it.
- **Trusted versus untrusted uploads.** Anything uploaded after isolation is kept as evidence but never used for restore.
- **Offline detection** after three missed heartbeats (for example a power cut).

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A04-oau-ife-ifesentinel`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5104 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | Every OAU computer we protect is on this screen. | `python main.py serve` | Three green cards with CPU, RAM, disk and backup counts |
| 2 | The CSE lab loses power. | `python main.py outage --agent CSE-LAB-07` | After about 30 s the card turns grey: OFFLINE incident |
| 3 | Ransomware hits the Registry server. | `python main.py attack --agent REGISTRY-SRV` | Card turns red: CANARY TRIPPED, isolated |
| 4 | Ransomware quietly encrypts bursary CSVs. | `python main.py stealth --agent BURSARY-PC1` | Bursary card turns red: text files became binary |
| 5 | Recover the Registry from trusted backups only. | `python main.py restore --agent REGISTRY-SRV` | Files back byte-for-byte. Admin clicks Release after clean-up |
| 6 | The server cannot read our data. | `python main.py (open data/server/blobs)` | Blobs are random-looking ciphertext |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Create server database, staff accounts and three demo agents, then take full backups |
| `python main.py serve` | Run the console plus the three demo agents |
| `python main.py server-only` | Run only the console (real deployment) |
| `python main.py token --location "Bursary PC 2"` | One-time enrolment token for a new computer |
| `python main.py attack / stealth --agent NAME` | SAFE ransomware simulation on one agent folder |
| `python main.py backup / restore --agent NAME` | Back up or restore one agent |
| `python main.py outage / reconnect --agent NAME` | Simulate a power cut and recovery |
| `python main.py status` | Print agent states |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`server.py` central console and signed agent API. `agent.py` the program that runs on each protected computer. `demo.py` demo data and simulations. `main.py` commands. `selftest.py` tests. `config.json` settings.

## Part C. Using IfeSentinel on several real computers

1. On the server computer, set `"server_bind": "0.0.0.0"` in `config.json`, allow TCP port 5104 in Windows Firewall, and run `python main.py server-only`.
2. On the server, create one token per computer: `python main.py token --location "Bursary PC 2"`.
3. Copy `agent.py`, `demo.py`, `config.json` and `requirements.txt` to the other computer, install the requirements, then run
   `python agent.py enrol --name BURSARY-PC2 --server http://SERVER-IP:5104 --token THE-TOKEN --folder D:\Bursary`
4. Start it with `python agent.py run --name BURSARY-PC2`, or add that line to Task Scheduler at start-up.
5. Back up `data/agents/<name>/agent.json` to a USB stick kept in a safe. It holds that computer's data key. Without it, its backups cannot be decrypted.
6. For a real network, put the console behind HTTPS (for example a reverse proxy with a university certificate). The HMAC signatures already stop tampering and replay, and backups are already encrypted.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
