# PlateauWatch: Offline Kernel-Density Hotspot Early Warning for Farmer-Herder Conflict in Plateau State

PlateauWatch turns incident points into a heat surface with kernel density estimation, finds the hotspots, and compares the last 30 days with the 30 days before to say which hotspots are emerging, persistent or fading. An emerging hotspot raises an alert for an assessment team. The whole system runs on Python's standard library plus one package, and the map is drawn on the server as SVG, so it works with no internet at all.

Built for: **Plateau State (Bokkos, Barkin Ladi, Mangu, Riyom, Bassa, Wase and 6 other LGAs)**. Project folder: `B02-plateau-plateauwatch`.

Default login after setup: coordinator / ChangeMe@468 (can import data), observer / ChangeMe@468 (view only)

## What makes this design different

- **Offline-first.** No map tiles, no JavaScript. The server draws the density surface, LGAs, corridors, incidents and hotspot rings as SVG. The Content-Security-Policy blocks every external resource.
- **Gaussian kernel density estimation** on a 3 km raster, weighted by incident severity, with the kernel normalised so each incident's weight integrates to 1.
- **Silverman's rule of thumb** for bandwidth, capped at 10 km because the rule assumes one cluster and over-smooths multi-cluster conflict data.
- **Emerging hotspot analysis**: local maxima above the 90th percentile, compared with the previous 30-day window.
- **Predictive Accuracy Index (PAI)** evaluation: share of next-month incidents inside the top 10% density area, divided by that area's share.
- **Validated CSV import** for police and NGO data: unknown LGAs, bad severities, locations outside the state and unknown types are rejected with a reason.
- **Standard-library web server** with PBKDF2 passwords, session tokens, CSRF tokens and login lockout.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B02-plateau-plateauwatch`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5202 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | This map needs no internet. | `python main.py serve` | Heat surface, LGAs, corridors. Switch last 7, 30, 90 days |
| 2 | Where are the hotspots and are they growing? | `python main.py (Hotspots page)` | Mangu persistent (intensifying), others |
| 3 | Attacks start in Kanam, a quiet LGA. | `python main.py flare --lga Kanam` | Kanam appears as EMERGING with a red ring, alert written |
| 4 | Is KDE better than guessing? | `python main.py pai` | PAI above 1: the top 10% area holds far more than 10% of next-month incidents |
| 5 | Police send data as a spreadsheet. | `python main.py (Data page, paste CSV)` | Good rows imported, bad rows rejected with reasons |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Users and 240 days of synthetic history |
| `python main.py serve` | Offline web server (analysis every 5 minutes) |
| `python main.py analyse` | Hotspot analysis now |
| `python main.py flare --lga NAME` | Simulate a wave of attacks |
| `python main.py pai` | Predictive Accuracy Index back-test |
| `python main.py import FILE.csv` | Import incidents |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`kde.py` density, bandwidth, hotspots, emerging analysis, PAI, CSV import. `server.py` standard-library web server and SVG map. `geo.py` geography and synthetic history. `main.py` commands. `selftest.py` tests. `config.json` LGAs, corridors, cell size, bandwidth.

## Data notice

LGA positions are approximate and all incidents are synthetic. Replace them with official boundaries and verified incident data before real use.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
