# SahelStore: Low-Bandwidth, Power-Aware Backup and Recovery for the University of Maiduguri

SahelStore is designed for a campus where the internet link is slow and expensive and mains power drops often. It keeps compressed, encrypted snapshots on the local server, sends only the changed parts of files to an offsite mirror at night within a daily data budget, and changes its behaviour when the inverter battery runs low. If the local server room is lost, everything comes back from the offsite copy.

Built for: **University of Maiduguri, Borno State**. Project folder: `A06-unimaid-sahelstore`.

Default login after setup: status page: ictstaff / ChangeMe@468 (read-only by design; all actions run from the command line)

## What makes this design different

- **Read-only web page** (standard library, HTTP Basic login over a PBKDF2 hash). Nothing on the web page can delete or restore data. That shrinks the attack surface.
- **rsync-style delta sync.** A weak rolling checksum and SHA-256 per 2 KiB block find the parts already offsite. In testing a changed 38 KB student register went offsite as 756 bytes.
- **Daily bandwidth budget and off-peak window** (00:00 to 05:30 by default). Files that do not fit wait in a queue for the next night.
- **Power-aware scheduler.** On inverter battery below 40% heavy jobs wait. At 15% it takes one emergency snapshot, then stays idle until mains power returns.
- **LZMA compression + AES-256-GCM**, content-addressed objects so identical files are stored once.
- **Burst detector**: many existing files modified within 60 seconds, or ransomware extensions, refuse the snapshot.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\A06-unimaid-sahelstore`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5106 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | This is UNIMAID's backup status. | `python main.py serve` | Power on mains, services UP, offsite queue and bandwidth saved |
| 2 | NEPA takes the light. | `python main.py power-cut` | Within 20 s: battery 35%, heavy jobs deferred |
| 3 | The inverter is nearly flat. | `python main.py battery-critical` | Emergency snapshot logged once |
| 4 | Ransomware strikes. | `python main.py attack` | snapshot: REFUSED, ransomware extension |
| 5 | The server room floods too. | `python main.py lose-local` | Local store gone |
| 6 | We still recover from Abuja. | `python main.py restore-offsite` | All files rebuilt from offsite base + deltas, byte-identical |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Keys, viewer account, demo data, first snapshot and offsite sync |
| `python main.py serve` | Status page and scheduler |
| `python main.py snapshot` | Snapshot now |
| `python main.py sync` | Send the offsite queue now (ignores the window) |
| `python main.py restore` | Restore newest local snapshot |
| `python main.py restore-offsite` | Disaster recovery from the offsite mirror |
| `python main.py power-cut / battery-critical / power-back` | Simulate the inverter |
| `python main.py lose-local` | Delete the local store (simulation) |
| `python main.py status` | Text status |
| `python main.py verify-log` | Check the log hash chain |
| `python main.py attack / stealth` | SAFE ransomware simulations |
| `python main.py outage / portal` | Stop or start the demo portal |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`sahel.py` snapshots, delta sync, power logic, detection, monitoring. `status_page.py` read-only page and scheduler. `demo.py` demo data and simulations. `main.py` commands. `selftest.py` tests. `config.json` window, budget, power limits.



## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
