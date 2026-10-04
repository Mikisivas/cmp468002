# KadunaCorridor: Hawkes Self-Exciting Process Forecasting of Retaliatory Farmer-Herder Violence in Southern Kaduna

In Southern Kaduna one attack often triggers a reprisal, which triggers another. KadunaCorridor models that directly with a Hawkes self-exciting process: every violent event temporarily raises the chance of more events in the same LGA, and the boost fades over days. The system fits the model by maximum likelihood, shows each LGA's current intensity against its normal background, forecasts the next 7 days, and lists retaliation chains so mediators know which cycle to break.

Built for: **Kaduna State (Jema'a, Kachia, Kauru, Kajuru, Zangon Kataf, Kaura, Sanga and 5 other LGAs)**. Project folder: `B05-kaduna-corridor`.

Default login after setup: analyst / ChangeMe@468 (can refit the model), commander / ChangeMe@468

## What makes this design different

- **Hawkes process** with an exponential kernel: intensity = background + alpha x beta x sum of exp(-beta x time since each past event).
- **Maximum likelihood fitting** by grid search over the branching ratio alpha and memory 1/beta, with an O(n) recursive likelihood. Background rates per LGA use a closed-form estimate.
- **Validated fitter**: on data simulated with Ogata's thinning algorithm (alpha 0.5, memory 3 days) it recovered alpha 0.45 and memory 3.0 days.
- **Held-out comparison** with a plain Poisson model on the last 60 days.
- **Escalation status**: intensity at least 3x background = ESCALATING, with the probability of at least one more violent event in the next 7 days.
- **Retaliation chains**: violent events within 72 hours and 25 km of an earlier one are linked.
- **Server-drawn SVG intensity charts** for the four most elevated LGAs.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B05-kaduna-corridor`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5205 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | Every LGA has a normal level of violence. | `python main.py serve` | Forecast table: mostly background, ratio near 1 |
| 2 | How much does one attack provoke? | `python main.py (Model page)` | alpha about 0.25: each violent event triggers about a quarter of another; memory 5 days |
| 3 | An attack in Sanga, then two reprisals. | `python main.py flare --lga Sanga` | Sanga ESCALATING, about 6x background, 7-day risk jumps |
| 4 | Which cycle should mediators break? | `python main.py (Retaliation chains page)` | Chain of events linked within 72 h and 25 km |
| 5 | Is this better than counting? | `python main.py fit` | Held-out log-likelihood: Hawkes beats Poisson |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Users, 400 days of synthetic history, first fit and forecast |
| `python main.py serve` | Web app |
| `python main.py fit` | Refit the Hawkes model |
| `python main.py forecast` | Forecast every LGA |
| `python main.py flare --lga NAME` | Simulate an attack and two reprisals |
| `python main.py chains` | Top retaliation chains |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`hawkes.py` likelihood, fitting, simulation, forecast, chains. `app.py` Flask app with SVG charts. `geo.py` geography and synthetic history. `main.py` commands. `selftest.py` tests. `config.json` LGAs and thresholds.

## Data notice

Incidents are synthetic, generated with a retaliation mechanism. Feed verified police, NEMA or ACLED records before real use. LGA positions are approximate.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
