# ConfluenceEWS: Offline-First Field Reporting with Secure Synchronisation and a Logistic Risk Model for Kogi State

Many Kogi communities along the Niger and Benue have no reliable network. ConfluenceEWS lets police, peace officers and extension workers record incidents on a tablet with no signal at all. When they reach a town, the tablet syncs: every upload is signed, cannot be replayed, never duplicates on retry, and resolves offline edits. The hub then rescores a logistic regression that gives each LGA's chance of a violent incident in the next 14 days, and the tablet carries that risk table back to the field for offline use. The hub needs only Python, with no extra packages.

Built for: **Kogi State (Omala, Bassa, Dekina, Ibaji, Kotonkarfe, Ankpa and 6 other LGAs)**. Project folder: `B10-kogi-confluence`.

Default login after setup: hub_admin / ChangeMe@468. Tablets: python field.py add | sync | show --device KG-TAB-01

## What makes this design different

- **Offline-first tablets** with their own SQLite queue. A failed sync keeps everything queued.
- **Signed sync protocol**: HMAC-SHA256 per tablet key. A strictly increasing counter blocks replay of captured uploads.
- **Idempotent uploads**: each report has a UUID created on the tablet, so a retry after a lost reply creates no duplicates.
- **Conflict resolution**: offline edits carry a version number. The highest version wins and a late older copy cannot overwrite newer data.
- **Two-way sync**: the reply returns the latest LGA risk table, so the field has risk levels without network.
- **Logistic regression from scratch** (gradient descent, L2) on 7 features. It is tested on the most recent 90 days and reported with AUC and Brier score against simple baselines.
- **Standard library only** on the hub and tablets: no pip install needed, which suits low-bandwidth sites.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B10-kogi-confluence`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5210 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | This is the 14-day risk for every Kogi LGA. | `python main.py serve` | Risk table with probabilities |
| 2 | Officers in Omala and Bassa have no network. | `python main.py field-day` | Tablets queue reports, then sync: new reports, an offline edit, risk table returned |
| 3 | What if the network drops mid-upload? | `python main.py (selftest)` | Retry gives 0 new and 2 duplicates recognised: no double counting |
| 4 | Can someone replay a captured upload? | `python main.py (Tablets page, Sync log)` | replay refused, bad signature rows |
| 5 | How good is the model? | `python main.py (Model page)` | AUC and Brier against the naive rule and the average forecast |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Admin, 420 days of synthetic history, 4 tablets, model training |
| `python main.py serve` | Hub web server and /sync endpoint |
| `python main.py field-day` | Two tablets record offline and sync with the running hub |
| `python main.py train` | Retrain and evaluate the model |
| `python main.py score` | Rescore every LGA |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`hub.py` storage, sync protocol, conflict rules, scoring. `field.py` tablet app with offline queue. `model.py` features, logistic regression, AUC. `server.py` standard-library web server. `geo.py` geography and synthetic history. `main.py` commands. `selftest.py` tests. `config.json` LGAs and model settings.

## Using real tablets

1. On the hub computer set the port in `config.json` and open it in the firewall. Put HTTPS in front for real use.
2. For each officer: `python -c "import field; field.provision('KG-TAB-05','Officer name','Ankpa','http://HUB-IP:5210')"` creates the tablet's key.
3. Copy `field.py`, `hub.py`, `geo.py`, `model.py`, `config.json` and the tablet folder `data/tablets/KG-TAB-05` to the tablet (any device with Python, for example a Windows tablet or Pydroid on Android).

## Data notice

Incidents are synthetic and LGA positions approximate. The AUC on synthetic data says the pipeline works, not that it predicts real violence.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
