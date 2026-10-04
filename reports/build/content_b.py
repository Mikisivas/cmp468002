"""Report content for the ten farmer-herder conflict early warning systems (family B)."""

COMMON_CMP = [
    ["Overview of security in computing", "Confidentiality of informants, integrity of reports and data, availability of alerts"],
    ["Characteristics of computer intrusion", "Forged reports, fake devices, replayed messages, tampered records"],
    ["Types of security breaches", "Disclosure of informant identity, falsified incident data, unauthorised access to case files"],
    ["Classes of attacks", "Impersonation, replay, injection, brute force, cross-site request forgery, disinformation"],
    ["Methods of defence and controls", "Table 3.2 maps each threat to its control"],
    ["Data security: encryption and decryption", "See Section 3.5"],
    ["Database security", "Parameterised SQL, role checks before every query, encrypted personal fields"],
    ["Security policies and standards", "NDPA 2023 (personal data of reporters), ISO/IEC 27001:2022 access control"],
]

B = [
 {"id": "B01", "folder": "B01-benue-peacegrid", "name": "BenuePeaceGrid", "port": 5201,
  "title": "BenuePeaceGrid: An AHP-Weighted Hexagon Risk Grid for Farmer-Herder Conflict Early Warning in Benue State",
  "subtitle": "Multi-criteria risk on 9 km cells, signed GPS collars and protected community reporting",
  "place": "Benue State (12 LGAs including Makurdi, Guma, Agatu, Logo and Kwande)",
  "context": "Benue State, the 'Food Basket of the Nation', sits on the main southward routes of transhumant herds. Guma, Agatu and Logo "
             "have suffered repeated deadly clashes. Risk reported at LGA level is too coarse to send a patrol: an LGA can be larger "
             "than 2,000 km2, and the trouble is usually in a few farming settlements near a route or a river crossing.",
  "problems": ["Risk is reported per LGA, which is too coarse for patrols.", "How risk factors are weighted is hidden, so stakeholders distrust it.",
               "Herd positions are unknown or can be faked.", "Community reporters fear exposure."],
  "objectives": ["divide the state into hexagonal cells and score each from five factors;", "derive factor weights with AHP and reject inconsistent judgements;",
                 "accept only signed, fresh GPS collar positions;", "receive community reports with rate limits and encrypted phone numbers;",
                 "alert police, peace committees and LGA chairmen; back-test the grid against later incidents."],
  "scope": "LGA positions are approximate and incident history is synthetic, generated to follow documented seasonal patterns.",
  "closest": ["schwarz", "goodman", "rod"],
  "closest_text": "Schwarz et al. (2022) map environmental suitability for transhumance; BenuePeaceGrid uses route and water "
                  "proximity in the same spirit but adds live herds and incidents. Goodman et al. (2024) predict fatalities in Nigeria "
                  "from imagery with a black-box model; BenuePeaceGrid uses an explicit weighted model that local actors can inspect, "
                  "answering the transparency concern of Rød et al. (2024).",
  "gap": "Reviewed systems either forecast at coarse units or use models stakeholders cannot inspect. A fine grid with negotiated, "
         "checkable weights is missing.",
  "fr": ["Build hexagon grid", "Compute five factors per cell", "AHP weights and consistency ratio", "Score, rank and alert with cooldown",
         "Signed collar ping API", "Community report form", "Back-test"],
  "nfr": ["Leaflet map with OpenStreetMap tiles", "Roles: admin, analyst, responder", "Runs on a laptop"],
  "layers": [["GPS collars", "Community reports", "Incident history"], ["Factor engine", "AHP weights"], ["Hexagon scores"], ["Alerts to DPO, peace committee, chairman", "Risk map"]],
  "components": [["grid.py", "Hexagons, AHP, factors, scoring, alerts, device signatures, back-test"], ["geo.py", "Geography helpers, synthetic history"],
                 ["app.py", "Flask app, map, report form, ping API"], ["main.py / selftest.py", "Commands, live feed, tests"]],
  "threats": [["Fake collar moves herds on the map", "HMAC per device, 5-minute freshness"], ["Report flooding", "Arithmetic check, 5 per hour per address"],
              ["Reporter identity exposed", "Fernet-encrypted phone, HMAC pseudonym"], ["Responder alters data", "Role checks"],
              ["Coordinates outside the state", "Bounding-box validation"], ["Clickjacking or script injection", "CSP, X-Frame-Options, escaped output"]],
  "algorithms": [
    ("Hexagon grid", "Pointy-top hexagons 9 km across are laid row by row over the state's bounding box with alternate rows offset "
     "by half a cell; cells further than 32 km from any LGA headquarters are dropped. Result: 435 cells."),
    ("AHP weights", "A 5x5 Saaty pairwise matrix is reduced to its principal eigenvector by power iteration. lambda_max gives "
     "CI = (lambda_max - n)/(n - 1) and CR = CI / RI(5 = 1.12). CR must be below 0.10."),
    ("Cell score", "Factors: severity x 0.5^(age/21 days) x exp(-distance/6 km) summed over incidents; herd heads within 10 km; "
     "exp(-route distance/10); farmland count within 8 km; exp(-water distance/15). Incidents, herds and farms are scaled 0-1 by "
     "the state maximum. Score = 100 x sum(weight x factor) x (0.6 + 0.4 x season factor), capped at 100."),
  ],
  "metrics": lambda r: [
      ["Hexagon cells", str(r["setup"]["hex_cells"])], ["Synthetic incidents in history", str(r["setup"]["history_incidents"])],
      ["AHP weights", ", ".join(f"{f.replace('_', ' ')} {w}" for f, w in zip(r["ahp"]["factors"], r["ahp"]["weights"]))],
      ["Consistency ratio", f"{r['ahp']['cr']} (limit 0.10)"],
      ["Back-test: incidents in top 20% cells", f"{r['backtest']['captured']} of {r['backtest']['future_incidents']} (hit rate {r['backtest']['hit_rate']}, lift {r['backtest']['lift']})"],
      ["Time to score all cells", f"{r['scoring_seconds']} s"],
      ["Kwande top cell before / after attack burst", f"{r['kwande_escalation']['before']} / {r['kwande_escalation']['after']}"]],
  "discussion": "The back-test lift of 4.0 is encouraging but rests on 15 future incidents in synthetic data, so it shows that the "
                "pipeline behaves sensibly, not that it predicts real violence. Weights are only as good as the stakeholder session "
                "that produced the pairwise matrix; the consistency ratio catches contradictions, not bias. Signed pings stop a fake "
                "device, but not a real collar moved by vehicle; MambillaWatch's speed check would add that.",
  "recommendations": ["Hold an AHP workshop with farmers' and herders' representatives and police to agree the matrix.", "Load official LGA and settlement boundaries.",
                      "Pilot in Guma and Agatu with collars on willing herds."],
  "further": ["Learn weights from verified incidents and compare with AHP.", "Add satellite NDVI as a sixth factor."],
 },
 {"id": "B02", "folder": "B02-plateau-plateauwatch", "name": "PlateauWatch", "port": 5202,
  "title": "PlateauWatch: Offline Kernel-Density Hotspot Early Warning for Farmer-Herder Conflict in Plateau State",
  "subtitle": "Server-drawn SVG maps, Silverman bandwidth and emerging-hotspot analysis with no internet dependency",
  "place": "Plateau State (12 LGAs including Bokkos, Barkin Ladi, Mangu, Riyom and Bassa)",
  "context": "Plateau State has seen repeated waves of rural attacks, especially in Bokkos, Barkin Ladi, Mangu and Riyom. Babatunde and "
             "Ibnouf (2024) show how resource management and peacebuilding choices there shaped the conflict. Field offices often "
             "have no reliable internet, so a map that needs online tiles is blank exactly when it is needed.",
  "problems": ["Online map tools fail without internet.", "Points on a map do not show where violence is concentrating.",
               "Analysts cannot tell new hotspots from old ones.", "Data from police and NGOs arrive as messy spreadsheets."],
  "objectives": ["estimate a severity-weighted density surface with kernel density estimation;", "choose the bandwidth from the data;",
                 "classify hotspots as emerging, persistent or fading;", "draw maps on the server so they work offline;",
                 "validate imported data; evaluate with the Predictive Accuracy Index."],
  "scope": "Synthetic incidents; 3 km raster; one web server for a state office.",
  "closest": ["parlato", "browning", "babatunde"],
  "closest_text": "Parlato et al. (2024) used kernel density estimation to find where cattle spend time; PlateauWatch uses it to find "
                  "where violence concentrates. Browning et al. (2026) treat conflict as contagious in space and time; the "
                  "window-on-window comparison here is a light-weight way to spot that spread.",
  "gap": "Hotspot analysis tools assume online GIS software; none of the reviewed early warning tools works fully offline.",
  "fr": ["KDE surface on a raster", "Silverman bandwidth with cap", "Hotspot peaks and status", "Emerging-hotspot alerts", "SVG map for 7/30/90 days",
         "Validated CSV import", "PAI back-test"],
  "nfr": ["No JavaScript, no external resources", "Standard library server", "Coordinator and observer roles"],
  "layers": [["Police / NGO CSV", "Field reports"], ["Validation"], ["KDE raster", "Bandwidth (Silverman)"], ["Hotspot status", "SVG map", "Alerts"]],
  "components": [["kde.py", "Density, bandwidth, peaks, emerging analysis, PAI, CSV import"], ["server.py", "Standard-library server and SVG renderer"],
                 ["geo.py", "Geography and synthetic history"], ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Malicious CSV (injection)", "Parameterised SQL, strict field validation"], ["False locations", "State bounding-box check"],
              ["Session theft", "HttpOnly, SameSite=Strict cookies, 30-minute expiry"], ["CSRF on import", "Per-session token"],
              ["Brute force", "Lock after 5 failures"], ["Map loads attacker content", "CSP default-src 'none'"]],
  "algorithms": [
    ("Kernel density estimation", "density(cell) = sum over incidents of severity x (1 / 2 pi h^2) x exp(-d^2 / 2 h^2), where d is the "
     "great-circle distance in km from the incident to the cell centre, evaluated within 3h."),
    ("Bandwidth", "Silverman's rule h = 1.06 x sigma x n^(-1/5), with sigma the average spread of incident positions in km, capped at "
     "10 km because the rule assumes a single cluster."),
    ("Emerging hotspots", "Peaks are cells above the 90th percentile and at least as dense as their 5x5 neighbourhood. A peak is "
     "emerging if the previous 30-day window was below half the previous threshold there, or if density at least tripled."),
  ],
  "metrics": lambda r: [
      ["Synthetic incidents", str(r["setup"]["incidents"])], ["Bandwidth used", f"{r['pai']['bandwidth_km']} km"],
      ["Predictive Accuracy Index", f"{r['pai']['pai']} (hit rate {r['pai']['hit_rate']} in {r['pai']['area_share'] * 100:.1f}% of the area)"],
      ["Analysis time", f"{r['analysis_seconds']} s"],
      ["Hotspots after Kanam flare", "; ".join(f"{a}: {b}" for a, b in r["flare"]["hotspots"])]],
  "discussion": "Silverman's rule gave about 19-24 km on this data, which blurred separate LGAs into one blob; the 10 km cap is a "
                "documented judgement, not a derived value. The first emerging rule missed Kanam because there had been some earlier "
                "activity there; adding 'at least three times denser' fixed it. PAI rests on 11 test incidents, so it is a sanity "
                "check, not proof of skill.",
  "recommendations": ["Feed police and Operation Safe Haven situation reports through the CSV import.", "Review the 10 km cap with field staff.",
                      "Print the map weekly for LGA security meetings."],
  "further": ["Space-time KDE with a time kernel.", "Export SVG maps to PDF bulletins."],
 },
 {"id": "B03", "folder": "B03-nasarawa-lafiaalert", "name": "LafiaAlert", "port": 5203,
  "title": "LafiaAlert: SMS-Based Multilingual Early Warning with Naive Bayes Classification for Nasarawa State",
  "subtitle": "Signed SMS gateway webhook, English-Hausa-Pidgin classifier, village gazetteer, corroboration and Poisson spike test",
  "place": "Nasarawa State (11 LGAs including Lafia, Keana, Doma, Awe and Obi)",
  "context": "Nasarawa borders Benue, and Nwankwo (2025) documents how perceived injustice escalates violence in the Benue-Nasarawa "
             "borderland. Most rural people there have basic phones and write in Hausa, English or Pidgin. A situation room that "
             "receives hundreds of texts cannot read and map them all by hand.",
  "problems": ["Texts arrive in three languages and mixed spelling.", "Duplicate texts about one event look like many events.",
               "Fake SMS-gateway calls could inject false reports.", "Nobody knows whether today's count in an LGA is unusual."],
  "objectives": ["classify texts into incident types plus noise with a Naive Bayes model built from scratch;", "detect urgency in three languages;",
                 "locate reports from village names;", "merge reports per village and count independent senders;",
                 "accept only signed, fresh gateway calls; flag LGAs whose daily count is statistically unusual."],
  "scope": "Training messages are synthetic templates; real use needs labelled hotline messages.",
  "closest": ["rochana", "cicek", "ronoh"],
  "closest_text": "Rochana et al. (2024) propose WhatsApp-based village warning; LafiaAlert uses plain SMS, which works on any phone. "
                  "Cicek and Kantarci (2023) found most crowdsensing studies untested; LafiaAlert reports a full pipeline test. Ronoh "
                  "et al. (2022) send SMS alerts out; LafiaAlert also reads them in.",
  "gap": "Reviewed community warning systems do not classify multilingual free text automatically or quantify how unusual a day is.",
  "fr": ["Verify gateway signature", "Classify, score urgency, geocode", "Merge by village; count senders", "UNCONFIRMED then CORROBORATED alerts",
         "Poisson spike test", "Encrypt phone numbers"],
  "nfr": ["Classifier needs no external libraries", "Roles: supervisor, operator, viewer", "Auto-refreshing dashboard"],
  "layers": [["SMS gateway (signed)"], ["Naive Bayes classifier", "Urgency", "Gazetteer"], ["Event merge and corroboration"], ["Poisson spike test", "Alerts"]],
  "components": [["nlp.py", "Naive Bayes, training corpus, urgency, gazetteer"], ["pipeline.py", "Webhook check, ingest, merge, Poisson test, alerts"],
                 ["app.py", "Dashboard and webhook"], ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Forged gateway call", "HMAC-SHA256 signature"], ["Replayed gateway call", "5-minute timestamp window"],
              ["Informant exposure", "Fernet phone encryption; HMAC pseudonym"], ["One person faking corroboration", "Same sender counts once"],
              ["Viewer injects test SMS", "Role check"]],
  "algorithms": [
    ("Multinomial Naive Bayes", "Tokens are words and word pairs. For class c: log P(c) + sum log((count(t, c) + 1) / (total(c) + V)). "
     "Probabilities are normalised with the log-sum-exp trick. Below 0.6 confidence a message goes to review."),
    ("Event merge", "Same village, same type, within 6 hours = one event. A different sender increments the sender count; the "
     "first urgent report alerts as UNCONFIRMED, the second sender upgrades it to CORROBORATED."),
    ("Poisson spike test", "lambda = events in the LGA over the last 60 days / 60. p = P(X >= today's count). If p < 0.01 the LGA is "
     "flagged."),
  ],
  "metrics": lambda r: [
      ["Classifier accuracy on held-out template messages", str(r["model"]["accuracy"])], ["Test messages", str(r["model"]["test_size"])],
      ["Hand-written probes (Hausa, Pidgin, English)", f"{len(r['language_probes'])} probes, all correct: "
       f"{any(t['passed'] for t in r['tests'] if t['test'].startswith('Correct class'))}"],
      ["Processing time per SMS", f"{r['pipeline_ms_per_message']} ms"], ["Alerts in demo feed", str(len(r["alerts"]))]],
  "discussion": "Accuracy of 1.0 on template messages is not a real-world figure: templates are easy. The five hand-written probes, "
                "which are not templates, were all correct, which is more meaningful but still small. An early version merged every "
                "report in an LGA into one event, which hid separate attacks and stopped the spike test from firing; merging by "
                "village fixed that.",
  "recommendations": ["Collect and label 1,000 real hotline messages and retrain.", "Grow the gazetteer with ward and village lists from the LGAs.",
                      "Contract a gateway that signs webhooks."],
  "further": ["Add Tiv, Eggon and Alago vocabulary.", "Voice-call reports transcribed to text."],
 },
 {"id": "B04", "folder": "B04-taraba-mambillawatch", "name": "MambillaWatch", "port": 5204,
  "title": "MambillaWatch: Signed-Collar Geofencing and Crop-Calendar Early Warning for Herds in Taraba State",
  "subtitle": "Point-in-polygon breach detection, approach ETA, counter-based replay protection and spoofing checks",
  "place": "Taraba State (12 LGAs including Wukari, Takum, Bali, Gassol and Sardauna on the Mambilla Plateau)",
  "context": "On the Mambilla Plateau and along the Benue valley, the trigger for many clashes is simple: cattle in a farm while the "
             "crop is still standing. Eke et al. (2025) describe farmers reducing what they plant because of such incursions. "
             "Both farmers and herders lose when the first they hear of a problem is the damage itself.",
  "problems": ["Herd positions are unknown until damage is done.", "Warnings reach one community, not both.", "GPS data could be forged or replayed.",
               "Off-season grazing on harvested fields raises needless alarms."],
  "objectives": ["accept signed collar pings with counters;", "detect breaches of in-season farms and approaching herds with an ETA;",
                 "detect corridor deviations and protected-area entry;", "flag collars that jump at impossible speeds;",
                 "alert farmers' and herders' leaders together; evaluate lead time."],
  "scope": "Farm polygons, corridors and the park boundary are illustrative.",
  "closest": ["kanagamalliga", "parlato", "ronoh"],
  "closest_text": "Kanagamalliga et al. (2024) apply geofencing to animal management, and Parlato et al. (2024) track cattle with "
                  "low-power GPS. MambillaWatch turns those tools toward conflict prevention by adding the crop calendar and joint "
                  "alerts. Ronoh et al. (2022) alert response teams before animals reach people; MambillaWatch does the same with an "
                  "estimated arrival time.",
  "gap": "Livestock geofencing is studied for productivity, not for preventing farmer-herder violence; the security of the collar data is rarely addressed.",
  "fr": ["Collar registry with keys", "Signature, counter, bounds and speed checks", "BREACH, APPROACH (with ETA), DEVIATION, RESTRICTED alerts",
         "Battery alerts", "Joint notification", "Live map"],
  "nfr": ["Map refresh every 4 s", "Coordinator and ranger roles"],
  "layers": [["GPS collars (signed, counter)"], ["Validation: signature, counter, speed"], ["Geofence rules + crop calendar"], ["Farmers' leader", "Herders' leader", "Live map"]],
  "components": [["fence.py", "Collar keys, validation, geofencing, alerts"], ["app.py", "Flask app, live map, ping API"],
                 ["geo.py", "Geography helpers"], ["main.py / selftest.py", "Commands, scenario, tests"]],
  "threats": [["Forged ping", "Per-collar HMAC"], ["Replayed ping", "Counter must increase"], ["Spoofed GPS jump", "Speed above 12 km/h ignored and flagged"],
              ["Unknown collar", "Refused"], ["Malformed request", "400 response"], ["Ranger registers rogue collar", "Role check"]],
  "algorithms": [
    ("Ray casting", "A horizontal ray from the point crosses the polygon's edges; an odd number of crossings means inside."),
    ("Approach and ETA", "If a herd is within 2 km of an in-season farm edge and its distance to the farm centre fell at more than "
     "0.3 km/h since the last ping, ETA = distance / closing speed."),
    ("Spoofing check", "speed = great-circle distance between consecutive accepted pings / elapsed hours; above 12 km/h the ping is "
     "ignored and the collar marked suspect."),
  ],
  "metrics": lambda r: [
      ["Processing time per ping", f"{r['ms_per_ping']} ms"],
      ["Warning lead time before breach", f"{r['lead_time_minutes']} minutes"],
      ["Alerts by collar", "; ".join(f"{k}: {', '.join(v) or 'none'}" for k, v in r["alerts_by_collar"].items())]],
  "discussion": "The 30-minute lead time comes from a scripted path and 10-minute pings; real lead time depends on ping interval and "
                "herd speed. Counter-based replay protection needs no clock on the collar, but a collar that loses its counter "
                "after a battery failure must be re-registered.",
  "recommendations": ["Survey real farm boundaries with farmer groups each season.", "Agree the crop calendar with the State Ministry of Agriculture.",
                      "Pilot with herders' associations as willing partners, not targets."],
  "further": ["LoRaWAN collars for areas without GSM.", "Predict paths from past tracks."],
 },
 {"id": "B05", "folder": "B05-kaduna-corridor", "name": "KadunaCorridor", "port": 5205,
  "title": "KadunaCorridor: Hawkes Self-Exciting Process Forecasting of Retaliatory Farmer-Herder Violence in Southern Kaduna",
  "subtitle": "Maximum-likelihood fitting, escalation status, 7-day forecasts and retaliation chains",
  "place": "Kaduna State (12 LGAs including Jema'a, Kauru, Kajuru, Zangon Kataf, Kaura and Sanga)",
  "context": "Southern Kaduna has suffered cycles in which one attack is followed by reprisals. A system that only counts incidents "
             "treats each event as independent and misses the most predictable thing about them: violence breeds violence for a "
             "few days.",
  "problems": ["Counting models ignore retaliation.", "Commanders cannot tell an escalating LGA from a normally busy one.",
               "Mediators do not see which events belong to one cycle.", "Forecasts are not compared with simpler alternatives."],
  "objectives": ["fit a Hawkes process by maximum likelihood;", "verify the fitter on data with known parameters;", "compare with a Poisson model on held-out data;",
                 "compute escalation status and 7-day probabilities;", "link events into retaliation chains."],
  "scope": "Synthetic incidents generated with a retaliation mechanism; parameters shared across LGAs.",
  "closest": ["browning", "rod", "goodman"],
  "closest_text": "Browning et al. (2026) fit a Bayesian discrete-time Hawkes model to ACLED data; KadunaCorridor fits a simpler "
                  "continuous-time version by grid-search maximum likelihood that a state analyst can run on a laptop. Rød et al. "
                  "(2024) ask for transparent parameters; alpha and memory have plain meanings.",
  "gap": "Self-exciting models appear in research on national data but not in tools for LGA-level farmer-herder early warning.",
  "fr": ["Fit alpha, memory and background rates", "Simulate a Hawkes process for testing", "Held-out log-likelihood comparison",
         "Status, intensity ratio and 7-day probability", "Warnings with cooldown", "Retaliation chains", "SVG intensity charts"],
  "nfr": ["Pure Python", "Analyst and commander roles"],
  "layers": [["Incident history"], ["Likelihood + grid search"], ["Fitted alpha, memory, background"], ["Forecast and status", "Chains", "Warnings"]],
  "components": [["hawkes.py", "Likelihood, fitting, simulation, forecast, chains"], ["app.py", "Flask app with SVG charts"],
                 ["geo.py", "Geography and synthetic history"], ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Unauthorised refit with bad data", "Only analysts can refit; CSRF token"], ["Data exposure", "Login required for every page"],
              ["Brute force", "Lockout"], ["Clickjacking", "X-Frame-Options DENY"]],
  "algorithms": [
    ("Hawkes intensity", "lambda(t) = mu + alpha x beta x sum over past events of exp(-beta (t - t_i)). alpha is the branching ratio "
     "(expected follow-ups per event); 1/beta is memory in days."),
    ("Likelihood", "log L = sum log lambda(t_i) - integral of lambda over [0, T]. The excitation sum is computed recursively: "
     "A_i = exp(-beta (t_i - t_{i-1})) x (1 + A_{i-1}), so the cost is linear in the number of events."),
    ("Forecast", "Expected events in the next 7 days = mu x 7 + alpha x sum (exp(-beta (T - t_i)) - exp(-beta (T + 7 - t_i))). "
     "P(at least one) = 1 - exp(-expected). Status is ESCALATING when lambda / mu >= 3."),
  ],
  "metrics": lambda r: [
      ["Fitted branching ratio alpha", str(r["setup"]["fit"]["alpha"])], ["Fitted memory", f"{r['setup']['fit']['memory_days']} days"],
      ["Held-out log-likelihood, Hawkes vs Poisson", f"{r['setup']['fit']['test_loglik_hawkes']} vs {r['setup']['fit']['test_loglik_poisson']}"],
      ["Parameter recovery (true alpha 0.5, memory 3 d)", f"alpha {r['parameter_recovery']['fitted_alpha']}, memory {r['parameter_recovery']['fitted_memory_days']} d"],
      ["Sanga 7-day probability before / after flare", f"{r['sanga']['before']['p_any_7d']} / {r['sanga']['after']['p_any_7d']}"],
      ["Longest retaliation chain", str(r["longest_chain"])], ["Setup and fit time", f"{r['setup_seconds']} s"]],
  "discussion": "The parameter-recovery test matters more than the forecast numbers: it shows the fitter finds alpha 0.45 and memory "
                "3.0 days when the truth is 0.5 and 3. The held-out gain over Poisson is modest (3.3 log-likelihood units) on 23 "
                "events. Sharing alpha across LGAs keeps the model stable on little data but hides LGA differences.",
  "recommendations": ["Feed verified incidents from the state security council and NEMA.", "Review alpha and memory monthly.",
                      "Use chains to brief traditional rulers and youth leaders."],
  "further": ["Spatial kernel linking neighbouring LGAs.", "Separate alpha per LGA with Bayesian shrinkage."],
 },
 {"id": "B06", "folder": "B06-adamawa-yolashield", "name": "YolaShield", "port": 5206,
  "title": "YolaShield: USSD Incident Reporting with a Signed, Tamper-Evident Ledger for Adamawa State",
  "subtitle": "Three-language USSD menus, Merkle-rooted Ed25519 blocks, an outside witness and lawful erasure",
  "place": "Adamawa State (12 LGAs including Numan, Demsa, Lamurde, Guyuk and Song)",
  "context": "In the Numan-Demsa-Lamurde axis many people have only basic phones with no data. Reports that do reach the authorities "
             "can be lost, changed or quietly deleted, which destroys trust in any warning system.",
  "problems": ["Smartphone apps exclude most rural callers.", "Reports can be altered or deleted without trace.", "Personal data on a ledger cannot be erased.",
               "Callers rarely hear back about risk in their area."],
  "objectives": ["offer a USSD menu in English, Hausa and Pidgin;", "fit every screen on a basic phone;", "fingerprint reports into signed, chained blocks;",
                 "keep personal data off-chain and erasable;", "let callers hear their LGA alert level; protect the gateway endpoint."],
  "scope": "Simulated gateway; a real USSD code is leased through an aggregator.",
  "closest": ["shimizu", "rochana", "rod"],
  "closest_text": "Shimizu et al. (2025) show simple, offline-capable reporting working in Darfur; YolaShield uses USSD for the same "
                  "reach. Rochana et al. (2024) rely on WhatsApp, which needs data. Rød et al. (2024) call for transparency; a ledger "
                  "anyone can verify is a concrete step.",
  "gap": "Reviewed systems do not make collected reports tamper-evident to outsiders.",
  "fr": ["USSD menu (report, alert level, advice, mediator)", "Idempotent submission per session", "Seal blocks every 5 reports or 10 minutes",
         "Verify chain against witness", "Erase personal data lawfully", "Phone simulator for staff"],
  "nfr": ["Screens of 182 characters or fewer", "Standard library server", "Language packs as JSON"],
  "layers": [["Basic phone (USSD)"], ["Telco gateway (token + IP)"], ["Menu state machine"], ["Encrypted records", "Signed block ledger"], ["Peace Commission witness"]],
  "components": [["ussd.py", "Menu state machine"], ["ledger.py", "Records, blocks, Merkle, signatures, verification, erasure, risk"],
                 ["server.py", "Gateway endpoint, simulator, staff pages"], ["lang/", "Language packs"], ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Report edited in database", "Fingerprint mismatch"], ["Report deleted", "Sealed fingerprint has no record"],
              ["Block rewritten", "Signature and witness mismatch"], ["Fake gateway", "Token and IP allow-list"], ["Telco retries", "One report per session"],
              ["Personal data kept forever", "Off-chain, erasable records"]],
  "algorithms": [
    ("Stateless USSD", "The gateway sends all choices so far as '2*1*3*2*1*1'. Each request rebuilds the screen from that path, "
     "so the server keeps no session state and retries are harmless."),
    ("Block sealing", "block = {height, time, previous hash, Merkle root, fingerprints}; hash = SHA-256(block); signature = Ed25519(block). "
     "The hash is appended to the witness file held by the Peace Commission."),
    ("Verification", "Check heights, links, hashes against the witness, signatures and Merkle roots, then check every non-erased "
     "record's fingerprint and that every sealed fingerprint still has a record."),
  ],
  "metrics": lambda r: [
      ["Key presses for a Hausa report", str(len(r["hausa_report_flow"]) - 1)],
      ["Longest screen", f"{max(len(x) for x in r['hausa_report_flow'])} characters"],
      ["Ledger in test", f"{r['ledger']['blocks']} blocks, {r['ledger']['records']} records, verified: {r['ledger']['ok']}"],
      ["Lamurde level after urgent reports", f"{r['lamurde_risk']['level']} (score {r['lamurde_risk']['score']})"]],
  "discussion": "The ledger proves integrity only if the witness copy is truly held elsewhere; a single administrator controlling both "
                "the database and the witness file could rewrite both. The Hausa and Pidgin texts were written for this project and "
                "need review by native speakers before use.",
  "recommendations": ["Send each block hash to the Peace Commission by SMS or email automatically.", "Have native speakers review the language packs and add Fulfulde.",
                      "Lease a short USSD code through a licensed aggregator."],
  "further": ["Voice IVR for people who cannot read.", "Publish block hashes on a public web page."],
 },
 {"id": "B07", "folder": "B07-niger-basinwatch", "name": "NigerBasinWatch", "port": 5207,
  "title": "NigerBasinWatch: Seasonal Transhumance Pressure Forecasting from Vegetation and Rainfall Data for Niger State",
  "subtitle": "An 8-week risk calendar with validated, fingerprinted environmental datasets",
  "place": "Niger State (12 LGAs including Mokwa, Mariga, Rafi, Shiroro, Borgu and Agwara)",
  "context": "Niger State is Nigeria's largest by area and receives herds moving south from Sokoto, Kebbi and Zamfara and toward the "
             "Kainji and Jebba lakes. Estefania-Salazar and Iglesias (2025) show West African growing seasons shortening, which "
             "changes when herds move and when crops stand in their way.",
  "problems": ["Warnings come hours before violence, too late for planning.", "Satellite data are not used by state planners.",
               "Datasets can be altered without anyone noticing.", "No calendar tells planners when and where pressure will peak."],
  "objectives": ["build a Transhumance Pressure Index from northern dryness, local pull and crop exposure;", "forecast it 8 weeks ahead;",
                 "validate and fingerprint every dataset;", "show a risk calendar and NDVI charts;", "test the pipeline with a simulation study."],
  "scope": "Synthetic NDVI, rainfall and incidents; the validation is a simulation study.",
  "closest": ["schwarz", "navarro", "sola", "tarif"],
  "closest_text": "Schwarz et al. (2022) model environmental suitability for transhumance and link it to conflict; Navarro et al. "
                  "(2025) find vegetation predicts pastoral conflict a month ahead; Sola et al. (2025) find vegetation effects differ "
                  "by country. NigerBasinWatch combines northern push and local pull with the crop calendar and adds data provenance, "
                  "which none of these address. Tarif (2022) warns the evidence base is thin, so the index must stay open to revision.",
  "gap": "Environmental conflict models in the reviewed work are research outputs; none is packaged as a planning calendar with data integrity controls.",
  "fr": ["Import and validate NDVI/rainfall CSV", "Fingerprint and HMAC-seal each version", "Compute TPI history", "8-week forecast and warnings",
         "Spearman validation", "Integrity warning on the calendar"],
  "nfr": ["Analyst and planner roles", "Files up to 2 MB"],
  "layers": [["NDVI + rainfall CSV (satellite)"], ["Validation + SHA-256/HMAC seal"], ["Climatology and anomalies"], ["TPI + 8-week projection"], ["Risk calendar", "Seasonal warnings"]],
  "components": [["tpi.py", "Index, climatology, forecast, import and sealing, validation"], ["app.py", "Calendar heatmap, charts, dataset page"],
                 ["main.py / selftest.py", "Commands, simulation, tests"]],
  "threats": [["Edited dataset file", "SHA-256 mismatch shown on calendar"], ["Forged fingerprint record", "HMAC seal fails"],
              ["Bad data (out of range, wrong area)", "Row validation; file refused above 5% errors"], ["Planner uploads data", "Role check"]],
  "algorithms": [
    ("Transhumance Pressure Index", "push = clip(1 - NDVI_north / greenest-week NDVI_north); pull = 0.5 NDVI_local/max + 0.3 "
     "exp(-water km/40) + 0.2 exp(-route km/25); exposure = share of crops in field that month; TPI = clip(sqrt(push) x pull x "
     "exposure x 1.8, 0, 1)."),
    ("Projection", "Weekly climatology per area; current anomaly x 0.85^k added to climatology for week k = 1..8."),
    ("Spearman validation", "Rank monthly mean TPI and monthly incident counts per LGA and compute the rank correlation."),
  ],
  "metrics": lambda r: [
      ["Dataset rows imported", str(r["setup"]["dataset_rows"])], ["Calendar cells", str(r["setup"]["calendar_cells"])],
      ["Spearman rho (simulation study)", f"{r['validation']['spearman_rho']} over {r['validation']['lga_months']} LGA-months"],
      ["Mean TPI: February / June / September", f"{r['mean_tpi_by_month']['2']} / {r['mean_tpi_by_month']['6']} / {r['mean_tpi_by_month']['9']}"],
      ["LGAs with higher projected peak after drought week", f"{sum(1 for b, a in r['drought_update']['peak_tpi_change'].values() if a > b)} of {len(r['drought_update']['peak_tpi_change'])}"]],
  "discussion": "Because incidents were simulated with pressure built in, rho = 0.32 says the pipeline recovers a signal, not that "
                "the index works in the field. The fingerprint test caught a real bug: Windows-style line endings were silently "
                "changed when files were written and read in text mode, which broke the hash. Writing with newline='' fixed it. "
                "The index peaks at the start and end of the rains, when herds and standing crops overlap.",
  "recommendations": ["Use real MODIS or Sentinel NDVI and CHIRPS rainfall.", "Validate against verified incidents before trusting the calendar.",
                      "Share the calendar with the Niger State Ministry of Livestock each month."],
  "further": ["Learn index weights from data.", "Add herd-count estimates from veterinary records."],
 },
 {"id": "B08", "folder": "B08-kwara-harmony", "name": "KwaraHarmony", "port": 5208,
  "title": "KwaraHarmony: Early Response and Mediation Case Management with Attribute-Based Access Control for Kwara State",
  "subtitle": "A strict case workflow, SLA monitoring, relapse detection, encrypted field notes and a k-anonymous public export",
  "place": "Kwara State (12 LGAs including Baruten, Kaiama, Moro, Edu and Patigi)",
  "context": "Kwara's northern LGAs border Benin Republic and Niger State and see seasonal herd movement. Peace committees and "
             "traditional rulers resolve many disputes, but follow-up is informal: agreements are not tracked, and when trouble "
             "returns nobody links it to the earlier case.",
  "problems": ["Warnings are not followed through to agreement and monitoring.", "Response deadlines are not measured.",
               "Sensitive mediation notes are visible to too many people.", "Sharing data with NGOs risks exposing families."],
  "objectives": ["enforce a case workflow with role-specific moves;", "measure service-level deadlines;", "detect relapses and reopen mediation;",
                 "control access by role, LGA and assignment; encrypt notes per case;", "publish a privacy-preserving export."],
  "scope": "Synthetic cases and fictional mediators.",
  "closest": ["babatunde", "nwankwo", "rod"],
  "closest_text": "Babatunde and Ibnouf (2024) and Nwankwo (2025) show that how institutions handle disputes, and whether people "
                  "see it as fair, shapes escalation. KwaraHarmony makes that handling visible and accountable. Rød et al. (2024) "
                  "discuss warnings; this system covers the response that must follow.",
  "gap": "The reviewed early warning work stops at the warning; response tracking with privacy controls is missing.",
  "fr": ["Workflow with allowed moves table", "Business rules for agreement and closure", "ABAC on every action, refusals logged",
         "Encrypted field notes", "Relapse detection", "SLA breaches", "LGA risk", "k-anonymous GeoJSON"],
  "nfr": ["Six roles including auditor", "No sign-in for the internal system account"],
  "layers": [["Officers", "Mediators", "Supervisor", "Auditor"], ["ABAC policy"], ["Case workflow", "Encrypted notes"], ["SLA + relapse + risk", "Public export (k = 3)"]],
  "components": [["cases.py", "Workflow, ABAC, notes encryption, relapse, SLA, risk, export"], ["app.py", "Flask app"],
                 ["main.py / selftest.py", "Commands, synthetic history, tests"]],
  "threats": [["Officer reads another LGA's cases", "ABAC by LGA"], ["Mediator acts on another's case", "ABAC by assignment"],
              ["Note disclosure", "AES-256-GCM per case (HKDF key)"], ["Re-identification from export", "10 km grid, k = 3 suppression"],
              ["Skipping workflow steps", "Allowed-move table"], ["Probing for access", "Every denial logged"]],
  "algorithms": [
    ("ABAC decision", "can(user, action, case) uses role, the user's LGAs, the case LGA and the assigned mediator. Moves also need the "
     "(from, to) pair to list the user's role."),
    ("Relapse rule", "When a case opens in an LGA where another case is in monitoring, that case moves back to mediation and an alert "
     "asks the mediator to call both parties within 24 hours."),
    ("k-anonymous export", "Each case is snapped to a 10 km grid cell (one longitude step per grid row). Cells with fewer than 3 cases "
     "are suppressed; published cells show counts and types only."),
  ],
  "metrics": lambda r: [
      ["Synthetic cases", str(r["history"]["cases"])], ["Cases by state", ", ".join(f"{k} {v}" for k, v in r["history"]["by_state"].items())],
      ["Median days to close", str(r["history"]["median_days_to_close"])], ["SLA breaches in 3 days' time", str(r["sla_breaches_in_3_days"])],
      ["Export", f"{r['export']['grid_km']} km grid, k = {r['export']['k']}, {r['export']['suppressed_cases']} cases suppressed"],
      ["Refused actions logged", str(r["denied_attempts_logged"])]],
  "discussion": "The export first used a 5 km grid and, because of a keying bug, published nothing at all. Fixing the bug and moving "
                "to 10 km published 7 cells while still suppressing small ones. This is the usual privacy-utility trade-off: a "
                "finer grid helps NGOs, a coarser one protects families.",
  "recommendations": ["Agree SLA targets with the State Peace Committee.", "Train mediators to write notes in the system, not on paper.",
                      "Review the export grid with community leaders."],
  "further": ["SMS reminders before SLA deadlines.", "Differential privacy for counts."],
 },
 {"id": "B09", "folder": "B09-zamfara-guard", "name": "ZamfaraGuard", "port": 5209,
  "title": "ZamfaraGuard: Trust-Weighted Verification of Crowdsourced Conflict Reports Against Disinformation in Zamfara State",
  "subtitle": "Beta reputation, DBSCAN space-time clustering, noisy-OR credibility, Sybil caps and copy-paste flood detection",
  "place": "Zamfara State (12 LGAs including Gusau, Maru, Anka, Tsafe and Zurmi)",
  "context": "Zamfara has suffered cattle rustling and rural attacks. In such settings rumours spread fast, and a false message "
             "can provoke real reprisals. An open reporting line is both necessary and a target.",
  "problems": ["False reports trigger needless deployments or reprisals.", "Coordinated rumours use many fresh SIM cards.",
               "Repeated reports from one person look like confirmation.", "Reporters fear being identified."],
  "objectives": ["learn reporter reliability from verified outcomes;", "cluster reports of one event in space and time;",
                 "combine independent sources, capping new reporters;", "flag copy-paste floods;", "apply a two-source rule before dispatch;",
                 "keep reporters pseudonymous."],
  "scope": "Synthetic reports and verdicts; thresholds need tuning on real data.",
  "closest": ["cicek", "rochana", "rod"],
  "closest_text": "Cicek and Kantarci (2023) note that crowdsensing studies rarely test real incidents; ZamfaraGuard tests the "
                  "specific failure of false and coordinated reports. Rochana et al. (2024) encourage participation; ZamfaraGuard "
                  "adds the credibility layer such participation needs.",
  "gap": "Reviewed community reporting systems trust reports equally; none models reporter reliability or coordinated disinformation.",
  "fr": ["Pseudonymous reporters", "Beta reputation from verdicts", "DBSCAN clustering", "Noisy-OR with new-reporter cap", "Flood flag",
         "Two-source dispatch rule", "Verifier verdicts", "Map"],
  "nfr": ["Verifier and analyst roles", "4 reports per number per hour"],
  "layers": [["Community reports (pseudonymous)"], ["DBSCAN clusters"], ["Reputation + noisy-OR", "Flood detector"], ["Probable / verify / watch", "Verifier verdicts"]],
  "components": [["trust.py", "Reputation, clustering, credibility, flood detection, verdicts"], ["app.py", "Flask app and map"],
                 ["main.py / selftest.py", "Commands, scenario, tests"]],
  "threats": [["Coordinated rumour from new SIMs", "Sybil cap 0.60, copy-paste flag halves credibility"], ["One person repeating", "Counted once"],
              ["One trusted person alone", "Two-source rule"], ["Report flooding", "4 per hour per number"],
              ["Reporter identification", "HMAC pseudonym; phone never stored"], ["Analyst records verdicts", "Role check"]],
  "algorithms": [
    ("Beta reputation", "trust = (1 + confirmed) / (2 + confirmed + false), the mean of Beta(1 + confirmed, 1 + false)."),
    ("DBSCAN in space-time", "Neighbours are reports within 5 km and 6 hours; min points 2; clusters grow through dense neighbours; "
     "others are noise (single reports)."),
    ("Credibility", "Over distinct reporters: known reporters combine by noisy-OR, 1 - product(1 - trust); new reporters combine "
     "separately and are capped at 0.60. If at least half of report pairs have Jaccard similarity >= 0.8 and 60% come from new "
     "numbers, credibility is halved. Dispatch needs >= 0.80 and two reporters."),
  ],
  "metrics": lambda r: [
      ["Mean trust: reliable / unreliable informants", f"{r['reputation']['reliable_mean']} / {r['reputation']['unreliable_mean']}"],
      ["Maru (3 trusted informants)", f"credibility {r['scenario']['maru']['credibility']}, {r['scenario']['maru']['status']}"],
      ["Gusau (6 new numbers, copy-paste)", f"credibility {r['scenario']['gusau']['credibility']}, {r['scenario']['gusau']['status']}"],
      ["Anka (one unknown reporter)", f"credibility {r['scenario']['anka']['credibility']}, {r['scenario']['anka']['status']}"],
      ["Scenario processing time", f"{r['scenario_ms']} ms"]],
  "discussion": "The design trades speed for caution: a single highly trusted informant gets a verifier, not a dispatch. In an "
                "attack in progress that may cost minutes; it also prevents one compromised informant from directing forces. "
                "Reputation can be gamed slowly by building a record with true minor reports; the cap on new reporters limits but "
                "does not remove that risk.",
  "recommendations": ["Record verifier verdicts consistently; reputation depends on them.", "Tune thresholds with real data.",
                      "Combine with LafiaAlert-style SMS intake."],
  "further": ["Text similarity that handles Hausa spelling variants.", "Time-decay of reputation."],
 },
 {"id": "B10", "folder": "B10-kogi-confluence", "name": "ConfluenceEWS", "port": 5210,
  "title": "ConfluenceEWS: Offline-First Field Reporting with Secure Synchronisation and a Logistic Risk Model for Kogi State",
  "subtitle": "Signed, replay-proof, idempotent sync with conflict resolution and a from-scratch logistic regression",
  "place": "Kogi State (12 LGAs including Omala, Bassa, Dekina, Ibaji and Kotonkarfe)",
  "context": "Kogi sits at the confluence of the Niger and Benue rivers. Omala, Bassa and Ibaji have riverine and remote communities "
             "with weak network coverage, so field officers often record events hours before they can send them.",
  "problems": ["Field reporting fails without network.", "Retries after a dropped connection create duplicates.", "Captured uploads can be replayed.",
               "Officers in the field have no current risk picture."],
  "objectives": ["queue reports on tablets offline;", "sync with signed, counter-protected requests;", "make retries idempotent and resolve offline edits;",
                 "return the latest LGA risk table to tablets;", "predict 14-day risk with logistic regression and evaluate it against baselines."],
  "scope": "Standard library only; tablets simulated on one machine; synthetic incidents.",
  "closest": ["shimizu", "goodman", "sola"],
  "closest_text": "Shimizu et al. (2025) show offline reporting succeeding in Darfur; ConfluenceEWS adds the security of the sync "
                  "itself. Goodman et al. (2024) and Sola et al. (2025) report strong AUCs with richer data; ConfluenceEWS uses a "
                  "simple, explainable model and reports a modest AUC honestly against a naive baseline.",
  "gap": "Offline reporting tools in the review do not describe replay protection, idempotency or conflict resolution.",
  "fr": ["Offline queue on tablets", "HMAC-signed sync with counter", "UUID idempotency", "Version-based conflict resolution", "Risk table in reply",
         "Logistic regression with AUC and Brier", "Staff pages"],
  "nfr": ["No third-party packages", "Payload limit 1 MB, 500 reports per sync"],
  "layers": [["Tablet queues (offline)"], ["Signed sync (HMAC + counter)"], ["Hub: dedupe, versions"], ["Logistic model"], ["Risk table back to tablets", "Staff pages"]],
  "components": [["field.py", "Tablet queue, edits, sync, lost-reply simulation"], ["hub.py", "Sync protocol, conflict rules, scoring"],
                 ["model.py", "Features, logistic regression, AUC"], ["server.py", "Standard-library hub server"], ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Captured upload replayed", "Counter must increase"], ["Upload signed with another tablet's key", "Signature fails"],
              ["Retry after lost reply", "UUID makes it a no-op"], ["Stale edit overwrites new data", "Highest version wins"],
              ["Malformed body", "400 response"], ["Staff pages without login", "Session required"]],
  "algorithms": [
    ("Sync protocol", "body = {device, counter, reports}; X-Sig = HMAC-SHA256(device key, body). Accept only counter > last counter. "
     "For each report: insert if UUID new; replace if (version, edited) is greater; else count as duplicate. Reply with acked UUIDs "
     "and the risk table."),
    ("Logistic regression", "Seven standardised features per LGA-week. Batch gradient descent on log-loss with L2 = 0.01, learning "
     "rate 0.5, 600 epochs. Temporal split: train on older weeks, test on the last 90 days."),
    ("AUC", "Mann-Whitney: the probability that a random positive LGA-week is ranked above a random negative, with ties averaged."),
  ],
  "metrics": lambda r: [
      ["Training / test rows", f"{r['model']['train_rows']} / {r['model']['test_rows']}"],
      ["AUC: model / naive last-30-days rule", f"{r['model']['auc_model']} / {r['model']['auc_naive_last30']}"],
      ["Brier: model / always-average", f"{r['model']['brier_model']} / {r['model']['brier_climatology']}"],
      ["Retry after lost reply", f"{r['retry_after_lost_reply']['new']} new, {r['retry_after_lost_reply']['duplicates']} duplicates recognised"],
      ["Bassa 14-day probability before / after reports", f"{r['bassa_risk']['before']} / {r['bassa_risk']['after']}"]],
  "discussion": "An AUC of 0.63 is modest; it beats the naive rule (0.51) and the Brier score beats an always-average forecast, but "
                "only slightly. That is an honest result for seven simple features. The sync tests found that the tablet received "
                "the old risk table because the hub replied before rescoring; the hub now rescoring first means officers take home "
                "levels that include their own reports.",
  "recommendations": ["Put the hub behind HTTPS.", "Issue tablets with full-disk encryption.", "Retrain monthly on verified incidents."],
  "further": ["Peer-to-peer sync between tablets.", "More features: market days, rainfall, NDVI."],
 },
]
