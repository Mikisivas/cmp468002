# MambillaWatch: Signed-Collar Geofencing and Crop-Calendar Early Warning for Herds in Taraba State

MambillaWatch prevents the most common trigger of farmer-herder violence: cattle entering a farm while the crop is still in the field. GPS collars on herds send signed positions. The system knows each farm's crop and its season, so it warns when a herd is heading toward an in-season farm, estimates how many minutes until it arrives, and sends the same warning to the farmers' leader and the herders' Ardo. It also spots herds leaving the agreed corridor, entering a protected park, and collars that look spoofed.

Built for: **Taraba State (Wukari, Takum, Bali, Gassol, Sardauna/Mambilla and 7 other LGAs)**. Project folder: `B04-taraba-mambillawatch`.

Default login after setup: coordinator / ChangeMe@468 (registers collars), ranger / ChangeMe@468

## What makes this design different

- **Geofencing with ray-casting point-in-polygon** for farms and great-circle distance for corridors (3 km buffer), grazing reserves and the protected park.
- **Crop calendar.** Yam March to October, rice June to November, and so on (config.json). A herd in a harvested field is not an alert.
- **APPROACH alerts with ETA** from the herd's closing speed toward the farm. In the test, the warning came 30 minutes before the breach.
- **Dual notification.** Every farm alert goes to both the farmers' union chair and the herders' Ardo of the LGA, so neither side hears it second-hand.
- **Counter-based replay protection.** Each collar signs collar|counter|lat|lon|battery with its own HMAC key. A ping with an old counter is refused, so no clock is needed on the collar.
- **Spoofing detection.** A jump faster than 12 km/h (cattle walk 2 to 5 km/h) marks the collar suspect and the position is ignored.
- **Live Leaflet map** with in-season farms highlighted, corridors, reserves, herd tracks and an alert feed refreshed every 4 seconds.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B04-taraba-mambillawatch`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5204 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | These are Taraba's collared herds and in-season farms. | `python main.py serve` | Map: brown in-season farms, green corridors, purple herds |
| 2 | Ardo Musa's herd drifts toward a Bali farm. | `python main.py simulate --interval 3` | APPROACH alert with ETA, then BREACH, sent to both leaders |
| 3 | Another herd leaves the corridor. | `python main.py (same run)` | DEVIATION alert for TRB-003, low-battery warning |
| 4 | Someone fakes a collar position. | `python main.py (same run)` | TRB-004 jumps 120 km: SPOOF alert, position ignored, collar marked suspect |
| 5 | Can a recorded ping be replayed? | `python main.py (Collars page)` | Rejected pings: replayed counter, bad signature |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Users, 4 collars with keys, LGA leaders |
| `python main.py serve` | Web app and ping API |
| `python main.py simulate --interval S` | Send the scenario to the running server |
| `python main.py season` | Crops in the field this month |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`fence.py` signatures, replay and spoofing checks, geofencing rules, dual alerts. `app.py` Flask app, live map, ping API. `geo.py` geography helpers. `main.py` commands and scenario. `selftest.py` tests. `config.json` LGAs, corridors, reserves, crop calendar, thresholds. `static/leaflet` map library.

## Data notice

Farm polygons, corridors, reserves and the park boundary are illustrative. Use surveyed farm boundaries and gazetted routes before real use.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
