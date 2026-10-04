# ZamfaraGuard: Trust-Weighted Verification of Crowdsourced Conflict Reports Against Disinformation in Zamfara State

Open reporting lines are attacked with rumours: one false 'they have killed many people, share this' message can start a reprisal. ZamfaraGuard treats every report as evidence of uncertain quality. Each anonymous reporter earns a reputation from past verified reports, reports about the same event are grouped in space and time, independent sources are combined, and copy-paste floods from new SIM cards are flagged. Only well-supported events trigger a dispatch. The rest go to a verifier or stay on watch.

Built for: **Zamfara State (Gusau, Maru, Anka, Tsafe, Zurmi, Shinkafi and 6 other LGAs)**. Project folder: `B09-zamfara-guard`.

Default login after setup: verifier / ChangeMe@468 (records true/false verdicts), analyst / ChangeMe@468. Public form at /report.

## What makes this design different

- **Beta reputation** per pseudonymous reporter: trust = (1 + confirmed) / (2 + confirmed + false). In the demo, reliable informants reach 0.87 and rumour spreaders fall to 0.11.
- **DBSCAN space-time clustering** (5 km and 6 hours) groups reports of one event.
- **Noisy-OR credibility** over distinct reporters. The same person repeating counts once.
- **Sybil cap**: brand-new numbers together can add at most 0.60 credibility.
- **Copy-paste flood detection** with word-set Jaccard similarity. Flagged clusters lose half their credibility.
- **Two-source rule**: a dispatch alert needs credibility of at least 0.80 and two independent reporters.
- **Privacy**: phones become HMAC pseudonyms and are never stored. Locations are rounded to about 100 m. 4 reports per number per hour.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B09-zamfara-guard`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5209 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | Our informants have track records. | `python main.py serve` | Reporters page: trust per pseudonym |
| 2 | Two things happen at once. | `python main.py scenario` | Maru: 3 trusted informants, PROBABLE, alert. Gusau: 6 new numbers, same text, flagged, WATCH |
| 3 | Why not believe the Gusau messages? | `python main.py (Clusters page)` | Flag: near-identical texts from new numbers; credibility 0.30 |
| 4 | The verifier checks Gusau: it was false. | `python main.py (Verify False)` | Those 6 numbers lose trust for next time |
| 5 | Can one person trigger a dispatch? | `python main.py (selftest)` | No: two-source rule gives VERIFY |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Users and 30 days of past reports with verdicts |
| `python main.py serve` | Web app |
| `python main.py scenario` | Send the real-plus-rumour scenario |
| `python main.py clusters` | Today's clusters |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`trust.py` reputation, DBSCAN, credibility, flood detection, verdicts. `app.py` Flask app and map. `geo.py` geography helpers. `main.py` commands and scenario. `selftest.py` tests. `config.json` LGAs and thresholds. `static/leaflet` map library.

## Data notice

All reports are synthetic. Thresholds (5 km, 6 h, 0.80, 0.60) are starting values to tune with real verified data.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
