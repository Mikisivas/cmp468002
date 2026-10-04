# NigerBasinWatch: Seasonal Transhumance Pressure Forecasting from Vegetation and Rainfall Data for Niger State

NigerBasinWatch works weeks ahead instead of hours ahead. It reads weekly vegetation (NDVI) and rainfall for each LGA and for the Sahel zone that herds come from, combines northern dryness, local pasture and water, stock routes and the crop calendar into a Transhumance Pressure Index, and projects it 8 weeks forward as a colour-coded calendar. Planners can then open routes, agree water-point timetables and place mediators before herds arrive. Every dataset version carries a sealed SHA-256 fingerprint, so a quietly edited file is caught before it misleads the forecast.

Built for: **Niger State (Mokwa, Mariga, Rafi, Shiroro, Borgu, Agwara, Mashegu and 5 other LGAs)**. Project folder: `B07-niger-basinwatch`.

Default login after setup: analyst / ChangeMe@468 (imports datasets), planner / ChangeMe@468

## What makes this design different

- **Transhumance Pressure Index** = sqrt(northern dryness) x local pull (pasture, water, route) x share of crops in the field.
- **8-week projection**: current NDVI anomalies decay toward the weekly climatology (persistence 0.85 per week) while the crop calendar moves forward.
- **Risk calendar heatmap** (LGA x week) and per-LGA NDVI charts drawn as SVG.
- **Validated dataset import**: area names, ISO dates, NDVI range and rainfall range are checked. A file with more than 5% bad rows is refused.
- **Data provenance**: each dataset version's SHA-256 is sealed with HMAC. The calendar page shows a red integrity warning if any stored file or fingerprint record changes.
- **Simulation-study validation** with Spearman rank correlation between monthly TPI and incident counts.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B07-niger-basinwatch`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5207 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | This is the next 8 weeks for Niger State. | `python main.py serve` | Calendar heatmap with TPI per LGA and week |
| 2 | Why is Mokwa red in week 4? | `python main.py (click Mokwa)` | Chart: Mokwa green but the northern source zone is drying |
| 3 | A new satellite week shows drought in the Sahel. | `python main.py drought` | Projected pressure rises in every LGA; seasonal warnings issued |
| 4 | Someone edits the NDVI file to hide the drought. | `python main.py verify-data` | File changed after import: the calendar shows a red integrity warning |
| 5 | Does TPI follow conflict? | `python main.py validate` | Spearman rho between monthly TPI and incidents |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Users, 3 years of synthetic NDVI and rainfall, simulated incidents, first calendar |
| `python main.py serve` | Web app |
| `python main.py forecast` | Recompute the calendar (top 10 printed) |
| `python main.py drought` | Import a drought week and compare peaks |
| `python main.py validate` | Spearman correlation |
| `python main.py verify-data` | Check dataset fingerprints |
| `python main.py import FILE.csv` | Import a dataset |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`tpi.py` index, climatology, forecast, dataset import and sealing, validation. `app.py` Flask app. `geo.py` geography helpers. `main.py` commands and simulation. `selftest.py` tests. `config.json` LGAs, routes, water, crop calendar.

## Data notice

NDVI, rainfall and incidents are synthetic. The validation is a simulation study: it shows the pipeline recovers a signal that was built into the data, not that the index predicts real conflict. Real use needs MODIS or Sentinel NDVI (for example from the FEWS NET or Copernicus portals), CHIRPS rainfall, and verified incident data.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
