# YolaShield: USSD Incident Reporting with a Signed, Tamper-Evident Ledger for Adamawa State

YolaShield lets anyone with a basic phone, no data and no smartphone report an incident by dialling *347*22# in English, Hausa or Pidgin. Callers can also hear the alert level for their LGA, get safety advice, or ask for a mediator. Every report is fingerprinted into a hash-chained, Ed25519-signed ledger whose block hashes are also held by the State Peace Commission, so no official can quietly delete or change a report. Personal data stays outside the chain and can be lawfully erased.

Built for: **Adamawa State (Numan, Demsa, Lamurde, Girei, Guyuk, Song and 6 other LGAs)**. Project folder: `B06-adamawa-yolashield`.

Default login after setup: commission / ChangeMe@468 (staff pages and the phone simulator)

## What makes this design different

- **USSD menu** in Africa's Talking format (CON/END, cumulative text like 2*1*3*2*1*1). The menu is rebuilt from the path, so the server keeps no session state. A telco retry of the same session never duplicates a report.
- **Three languages** in editable JSON packs (lang/en.json, ha.json, pcm.json). A Fulfulde pack can be added by copying en.json.
- **Every screen fits 182 characters** for basic phones, with LGA lists paged 5 at a time.
- **Tamper-evident ledger**: blocks of report fingerprints with Merkle roots, previous-block hash links and Ed25519 signatures. Block hashes are copied to an outside witness file.
- **Verification** detects edited reports, deleted reports, deleted blocks and rewritten blocks.
- **Privacy by design**: phone numbers and details are Fernet-encrypted off-chain. Erasure on request keeps the chain valid.
- **Gateway protection**: shared token plus IP allow-list on the USSD endpoint. The phone simulator needs a staff session and CSRF token.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B06-adamawa-yolashield`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5206 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | A farmer in Lamurde has only a basic phone. | `python main.py (Phone simulator page)` | Dial, choose Hausa, report an attack in 6 key presses |
| 2 | Several callers report from Lamurde. | `python main.py demo-calls` | Calls run through the gateway; reports appear with refs |
| 3 | Reports are sealed. | `python main.py seal` | Ledger page: blocks with hashes, all checks green |
| 4 | An insider changes a report to hide it. | `python main.py tamper` | Ledger page turns red: content changed after sealing |
| 5 | Callers hear the alert level. | `python main.py (simulator: 1, 2, Lamurde)` | Alert level and advice in their language |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Keys, staff account, 60 days of synthetic history |
| `python main.py serve` | USSD endpoint, simulator and staff pages |
| `python main.py demo-calls` | Six gateway calls against the running server |
| `python main.py seal` | Seal pending reports |
| `python main.py verify` | Verify the ledger |
| `python main.py tamper` | Simulate an insider edit |
| `python main.py erase REF` | Lawful erasure of one report's personal data |
| `python main.py risk` | LGA levels |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`ussd.py` menu state machine. `ledger.py` records, blocks, Merkle roots, signatures, verification, erasure, risk. `server.py` standard-library web server. `lang/` language packs. `geo.py` geography and synthetic history. `main.py` commands. `selftest.py` tests. `config.json` LGAs, USSD code, gateway settings.

## Language and data notice

The Hausa and Pidgin texts should be reviewed by native speakers before field use. LGA positions and incidents are synthetic and approximate. A real USSD code is leased from a telco through an aggregator.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
