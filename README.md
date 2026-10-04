# CMP 468 Computer Security: 20 Projects

This repository extends the two projects on branch `claude/optimistic-johnson-37n8ql` of CMP468-001
(VarsityShield and Zaman Lafiya). It keeps the same two aims and builds **ten new, different designs for each aim**,
each one for a different Nigerian institution or state, each one runnable on its own computer, and each one with
its own Word report.

* **Aim 1 (folder `backup-recovery/`)**: automated monitoring, backup and recovery for university digital infrastructure.
* **Aim 2 (folder `conflict-early-warning/`)**: GIS-based early warning and response for farmer-herder conflict.

## Aim 1: monitoring, backup and recovery (10 universities)

| # | System | For | Design in one line | Tests passed | Port | Report |
|---|---|---|---|---|---|---|
| A01 | [ZariaSafe](backup-recovery/A01-abu-zaria-zariasafe/README.md) | Ahmadu Bello University, Zaria, Kaduna State | Point-in-time encrypted versions with a mass-change ransomware detector, built on Python's standard web server | 13/13 | 5101 | [report](reports/A01_ZariaSafe_Report.docx) |
| A02 | [LionKeep](backup-recovery/A02-unn-nsukka-lionkeep/README.md) | University of Nigeria, Nsukka, Enugu State | Signature and entropy validation keeps suspicious files out of the archives | 15/15 | 5102 | [report](reports/A02_LionKeep_Report.docx) |
| A03 | [PremierGuard](backup-recovery/A03-ui-ibadan-premierguard/README.md) | University of Ibadan, Oyo State | Content-defined chunking, ChaCha20-Poly1305 and a compressibility-based ransomware detector | 15/15 | 5103 | [report](reports/A03_PremierGuard_Report.docx) |
| A04 | [IfeSentinel](backup-recovery/A04-oau-ife-ifesentinel/README.md) | Obafemi Awolowo University, Ile-Ife, Osun State | Signed heartbeats, replay protection, canary files and backups the central server cannot read | 17/17 | 5104 | [report](reports/A04_IfeSentinel_Report.docx) |
| A05 | [BeninVault](backup-recovery/A05-uniben-beninvault/README.md) | University of Benin, Benin City, Edo State | Two data shards and one XOR parity shard over three sites, with scrubbing and SLA tracking | 17/17 | 5105 | [report](reports/A05_BeninVault_Report.docx) |
| A06 | [SahelStore](backup-recovery/A06-unimaid-sahelstore/README.md) | University of Maiduguri, Borno State | rsync-style delta transfer to an offsite mirror, a daily data budget and an inverter-aware scheduler | 18/18 | 5106 | [report](reports/A06_SahelStore_Report.docx) |
| A07 | [HarmonyVault](backup-recovery/A07-unilorin-harmonyvault/README.md) | University of Ilorin, Kwara State | Ed25519-signed commits, content-addressed encrypted objects and change-rate anomaly detection | 15/15 | 5107 | [report](reports/A07_HarmonyVault_Report.docx) |
| A08 | [KanoShield](backup-recovery/A08-buk-kano-kanoshield/README.md) | Bayero University, Kano, Kano State | Database-enforced retention locks, dual control of restores and RFC 6238 authenticator codes | 18/18 | 5108 | [report](reports/A08_KanoShield_Report.docx) |
| A09 | [RiversRecover](backup-recovery/A09-uniport-riversrecover/README.md) | University of Port Harcourt, Choba, Rivers State | Trigger-based change journal, hash-chained encrypted shipping, Senate locks and a database freeze switch | 15/15 | 5109 | [report](reports/A09_RiversRecover_Report.docx) |
| A10 | [AkureKeyVault](backup-recovery/A10-futa-akure-keyvault/README.md) | Federal University of Technology, Akure, Ondo State | X25519 envelope encryption, Shamir 2-of-3 key shares, key rotation and crypto-shredding | 18/18 | 5110 | [report](reports/A10_AkureKeyVault_Report.docx) |

## Aim 2: farmer-herder conflict early warning (10 states)

| # | System | For | Design in one line | Tests passed | Port | Report |
|---|---|---|---|---|---|---|
| B01 | [BenuePeaceGrid](conflict-early-warning/B01-benue-peacegrid/README.md) | Benue State (Makurdi, Guma, Agatu, Logo, Kwande and 7 other LGAs) | Multi-criteria risk on 9 km cells, signed GPS collars and protected community reporting | 15/15 | 5201 | [report](reports/B01_BenuePeaceGrid_Report.docx) |
| B02 | [PlateauWatch](conflict-early-warning/B02-plateau-plateauwatch/README.md) | Plateau State (Bokkos, Barkin Ladi, Mangu, Riyom, Bassa, Wase and 6 other LGAs) | Server-drawn SVG maps, Silverman bandwidth and emerging-hotspot analysis with no internet dependency | 12/12 | 5202 | [report](reports/B02_PlateauWatch_Report.docx) |
| B03 | [LafiaAlert](conflict-early-warning/B03-nasarawa-lafiaalert/README.md) | Nasarawa State (Lafia, Keana, Doma, Awe, Obi, Toto and 5 other LGAs) | Signed SMS gateway webhook, English-Hausa-Pidgin classifier, village gazetteer, corroboration and Poisson spike test | 16/16 | 5203 | [report](reports/B03_LafiaAlert_Report.docx) |
| B04 | [MambillaWatch](conflict-early-warning/B04-taraba-mambillawatch/README.md) | Taraba State (Wukari, Takum, Bali, Gassol, Sardauna/Mambilla and 7 other LGAs) | Point-in-polygon breach detection, approach ETA, counter-based replay protection and spoofing checks | 15/15 | 5204 | [report](reports/B04_MambillaWatch_Report.docx) |
| B05 | [KadunaCorridor](conflict-early-warning/B05-kaduna-corridor/README.md) | Kaduna State (Jema'a, Kachia, Kauru, Kajuru, Zangon Kataf, Kaura, Sanga and 5 other LGAs) | Maximum-likelihood fitting, escalation status, 7-day forecasts and retaliation chains | 11/11 | 5205 | [report](reports/B05_KadunaCorridor_Report.docx) |
| B06 | [YolaShield](conflict-early-warning/B06-adamawa-yolashield/README.md) | Adamawa State (Numan, Demsa, Lamurde, Girei, Guyuk, Song and 6 other LGAs) | Three-language USSD menus, Merkle-rooted Ed25519 blocks, an outside witness and lawful erasure | 20/20 | 5206 | [report](reports/B06_YolaShield_Report.docx) |
| B07 | [NigerBasinWatch](conflict-early-warning/B07-niger-basinwatch/README.md) | Niger State (Mokwa, Mariga, Rafi, Shiroro, Borgu, Agwara, Mashegu and 5 other LGAs) | An 8-week risk calendar with validated, fingerprinted environmental datasets | 13/13 | 5207 | [report](reports/B07_NigerBasinWatch_Report.docx) |
| B08 | [KwaraHarmony](conflict-early-warning/B08-kwara-harmony/README.md) | Kwara State (Baruten, Kaiama, Moro, Edu, Patigi, Asa, Ifelodun and 5 other LGAs) | A strict case workflow, SLA monitoring, relapse detection, encrypted field notes and a k-anonymous public export | 23/23 | 5208 | [report](reports/B08_KwaraHarmony_Report.docx) |
| B09 | [ZamfaraGuard](conflict-early-warning/B09-zamfara-guard/README.md) | Zamfara State (Gusau, Maru, Anka, Tsafe, Zurmi, Shinkafi and 6 other LGAs) | Beta reputation, DBSCAN space-time clustering, noisy-OR credibility, Sybil caps and copy-paste flood detection | 15/15 | 5209 | [report](reports/B09_ZamfaraGuard_Report.docx) |
| B10 | [ConfluenceEWS](conflict-early-warning/B10-kogi-confluence/README.md) | Kogi State (Omala, Bassa, Dekina, Ibaji, Kotonkarfe, Ankpa and 6 other LGAs) | Signed, replay-proof, idempotent sync with conflict resolution and a from-scratch logistic regression | 17/17 | 5210 | [report](reports/B10_ConfluenceEWS_Report.docx) |

## How to use one project on one computer

1. Copy one project folder (for example `backup-recovery/A05-uniben-beninvault`) to the computer.
2. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
3. Double-click `1_SETUP.bat`, then `2_START.bat`. Use `3_DEMO_MENU.bat` for the defence and `4_SELFTEST.bat` to rerun the tests.
4. Each project's README has the login, a defence demonstration script and all commands.

Every project uses its own port (5101 to 5110 and 5201 to 5210), so several can run on one computer at the same time.

## Reports

`reports/` holds 20 Word reports (A01 to B10). Each has a title page, declaration, abstract, five chapters
(introduction, literature review, methodology and design, implementation and testing, conclusion), references and
appendices. Before submitting:

1. Fill in the title page placeholders (university, name, matric number, lecturer).
2. Right-click the table of contents and choose **Update Field**.
3. Read Chapter Four: the test results are real output from `selftest.py`, so rerun `4_SELFTEST.bat` and rebuild if you change the code.

To rebuild the reports: `pip install python-docx matplotlib`, then `python reports/build/build_reports.py`.

**Literature.** Every source in the reports (2021-2026) was checked against a publisher or index page in October 2026.
Sources from the earlier project that could not be confirmed were left out.

**Data.** All records, incidents, NDVI and reports are synthetic and LGA coordinates are approximate. The results show that each
design works as specified. They do not show real-world accuracy; that needs real data.
