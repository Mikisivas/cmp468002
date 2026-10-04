# BenuePeaceGrid: AHP-Weighted Hexagon Risk Grid for Farmer-Herder Conflict Early Warning in Benue State

BenuePeaceGrid covers Benue State with about 435 hexagonal cells, each about 9 km across. Every cell gets a risk score from five factors: recent incidents, collared herds nearby, closeness to a stock route, farmland exposure, and closeness to water points. The factor weights come from the Analytic Hierarchy Process, so stakeholders can see and argue about them. When a cell crosses the alert line, the LGA's police DPO, peace committee and chairman are alerted.

Built for: **Benue State (Makurdi, Guma, Agatu, Logo, Kwande and 7 other LGAs)**. Project folder: `B01-benue-peacegrid`.

Default login after setup: admin, analyst or responder / ChangeMe@468. The public report form at /report needs no login.

## What makes this design different

- **Hexagonal grid** instead of LGA boundaries, so risk can be located to within a few kilometres.
- **Analytic Hierarchy Process (AHP).** A Saaty pairwise matrix in config.json becomes weights by power iteration. The consistency ratio is computed and an inconsistent matrix (CR 0.10 or more) is refused.
- **Five factors**: severity-weighted incidents with a 21-day half-life, herd heads within 10 km, stock-route distance, farmland count, water-point distance. A seasonal multiplier lifts the dry season.
- **HMAC-signed GPS collar pings** with a 5-minute freshness window, so a fake device cannot move herds on the map.
- **Community report form** with an arithmetic check, a 5-per-hour limit per address, Fernet-encrypted phone numbers and HMAC pseudonyms for reporters.
- **Back-test** that scores the grid as it was 60 days ago and measures how many later incidents fell in the top 20% of cells.
- **Leaflet map** with OpenStreetMap tiles, farms, corridors, incidents and live herds.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B01-benue-peacegrid`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5201 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | This is Benue's risk grid today. | `python main.py serve` | Coloured hexagons, highest-risk cells listed on the right |
| 2 | Why does Guma score high? | `python main.py (click a Guma hexagon)` | Popup shows each factor value |
| 3 | The weights are not a black box. | `python main.py ahp` | AHP page: matrix, weights, CR = 0.015 (acceptable) |
| 4 | Herds start moving. Two leave the corridor. | `python main.py simulate --steps 30 --interval 2` | Purple herd markers move toward Guma farms |
| 5 | The grid reacts. | `python main.py score` | Guma cells turn High or Severe; Alerts page shows the SMS text and recipients |
| 6 | Does it actually predict? | `python main.py backtest` | Top 20% of cells caught most next-month incidents (lift above 1) |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Keys, users, grid, contacts, synthetic history, devices, first scoring |
| `python main.py serve` | Web app and 60-second scorer |
| `python main.py simulate` | Live herd and report feed (needs serve running) |
| `python main.py score` | Score all cells now |
| `python main.py top` | Top 15 cells |
| `python main.py ahp` | AHP weights and consistency ratio |
| `python main.py backtest` | Hit rate of the top 20% cells |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`grid.py` hexagons, AHP, factors, alerts, signatures, back-test. `geo.py` geography helpers and synthetic history. `app.py` Flask web app. `main.py` commands and live feed. `selftest.py` tests. `config.json` LGAs, corridors, AHP matrix. `static/leaflet` map library.

## Data notice

LGA positions are approximate headquarters coordinates and all incidents are synthetic, generated to follow the seasonal pattern described in the literature. Replace them with official boundaries (GRID3 or OCHA) and verified incident data before real use. The map background needs internet. Without it, the cells still draw on a blank background.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
