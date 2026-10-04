# LafiaAlert: SMS-Based Multilingual Early Warning with Naive Bayes Classification for Nasarawa State

LafiaAlert is built around the phone most rural people already have. Community members text what they see in English, Hausa or Pidgin. A Naive Bayes classifier written from scratch decides what kind of incident it is, a gazetteer finds the village and LGA, and reports about the same village are merged into one event so the situation room sees corroboration, not noise. A Poisson test flags an LGA when today's events are far above its normal daily rate.

Built for: **Nasarawa State (Lafia, Keana, Doma, Awe, Obi, Toto and 5 other LGAs)**. Project folder: `B03-nasarawa-lafiaalert`.

Default login after setup: supervisor (verify events), operator (send test SMS), viewer (read only) / ChangeMe@468

## What makes this design different

- **SMS gateway webhook** with HMAC-SHA256 signature and a 5-minute timestamp window, the same pattern Termii and Africa's Talking use. Forged or replayed calls are refused.
- **Multinomial Naive Bayes from scratch** (unigrams + bigrams, Laplace smoothing) over 6 classes including 'noise' for irrelevant texts. Precision, recall, F1 and the confusion matrix are shown on the Model page.
- **Three languages**: English, Hausa ('an kai hari ... yanzu da bindigogi') and Pidgin ('cow don chop my yam').
- **Urgency detection** in all three languages (now/yanzu, gun/bindiga, killed/an kashe).
- **Village gazetteer geocoding** for messages without GPS.
- **Event merging and corroboration**: same village + same type within 6 hours = one event. A second, different sender upgrades an UNCONFIRMED alert to CORROBORATED. The same sender repeating does not count.
- **Poisson spike test** per LGA against a 60-day baseline (alert when p < 0.01).
- **Privacy**: phone numbers are Fernet-encrypted. Staff see only an HMAC pseudonym.

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\CMP468\B03-nasarawa-lafiaalert`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens http://127.0.0.1:5203 . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
| 1 | People text us in their own language. | `python main.py demo-feed` | Inbox fills: Hausa, Pidgin and English messages classified, noise greyed out |
| 2 | Two people report the same attack in Giza. | `python main.py (Events page)` | One event, 2 senders, alert upgraded to CORROBORATED |
| 3 | Is Keana unusual today? | `python main.py spikes` | Keana p-value below 0.01: SPIKE alert to the State Security Council |
| 4 | How good is the classifier? | `python main.py (Model page)` | Accuracy, precision, recall per class |
| 5 | Can someone fake the SMS gateway? | `python main.py (selftest)` | Forged and replayed webhooks are refused |

## All commands

| Command | What it does |
|---------|--------------|
| `python main.py setup` | Keys, model training, users, 120 days of synthetic history |
| `python main.py serve` | Webhook and dashboard |
| `python main.py demo-feed` | Send 10 signed demo SMS to the running server |
| `python main.py classify "TEXT"` | Classify one message |
| `python main.py train` | Retrain the classifier |
| `python main.py spikes` | Poisson spike test for every LGA |
| `python main.py reset` | Delete demo data |
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

`nlp.py` Naive Bayes, training corpus, urgency, gazetteer. `pipeline.py` webhook check, ingest, merge, Poisson test, alerts. `app.py` Flask dashboard and webhook. `geo.py` geography and synthetic history. `main.py` commands. `selftest.py` tests. `config.json` LGAs, gazetteer, thresholds.

## Data notice

The training messages are generated from templates, so accuracy on them is higher than you should expect on real texts. Retrain on labelled messages from the real hotline before use. LGA positions and incidents are synthetic and approximate.

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
