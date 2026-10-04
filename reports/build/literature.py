"""Verified literature (2021-2026) used by the 20 reports.

Every entry below was checked against a publisher, index or repository page in October 2026.
Each `note` only states what that check confirmed about the work. Do not add a source here
without checking it first.
"""

A_REFS = {
    "baek": ("Baek, S., Jung, Y., Mohaisen, D., Lee, S., & Nyang, D. (2021). SSD-assisted ransomware detection and data recovery "
             "techniques. *IEEE Transactions on Computers, 70*(10), 1762-1776. https://doi.org/10.1109/TC.2020.3011214",
             "Baek et al. (2021) built ransomware detection and recovery into SSD firmware (SSD-Insider++): the drive watches I/O "
             "patterns and uses delayed deletion to restore original data, reporting 0% false rates in most cases and recovery "
             "with no data loss. The approach needs special drive firmware."),
    "simili": ("Simili, E., Stewart, G., Roy, G., Skipsey, S., & Britton, D. (2021). A hybrid system for monitoring and automated "
               "recovery at the Glasgow Tier-2 cluster. *EPJ Web of Conferences, 251*, 02047.",
               "Simili et al. (2021) combined Prometheus, Loki and Grafana at a university computing cluster and added an alerting "
               "application that performs simple recovery actions for known problems, so that staff intervene less often."),
    "amoruso": ("Amoruso, E., Amoruso, P., & Zou, C. (2026). Integrity-gated file monitoring for ransomware resilience and real-time "
                "recovery. In *2026 International Conference on Smart Applications, Communications and Networking (SmartNets)*. IEEE.",
                "Amoruso et al. (2026) proposed integrity-gated file monitoring, in which changed files must pass integrity checks "
                "before they are trusted, as a route to ransomware resilience and real-time recovery."),
    "muthoni": ("Muthoni, S., Okeyo, G., & Chemwa, G. (2021). Infrastructure as code for business continuity in institutions of higher "
                "learning. In *2021 International Conference on Electrical, Computer and Energy Technologies (ICECET)*. IEEE.",
                "Muthoni et al. (2021) found that African universities, Kenyan ones in particular, are slow to adopt cloud business "
                "continuity, and showed with Ansible and Terraform that infrastructure as code reduced cost, effort and human error "
                "when recovering a local data centre to the cloud."),
    "ilau": ("Ilau, M.-C., Baldwin, A., Caulfield, T., & Pym, D. (2025). Modelling and simulating organizational ransomware recovery: "
             "Structure, methodology, and decisions. *Journal of Cybersecurity, 11*(1), tyaf035. https://doi.org/10.1093/cybsec/tyaf035",
             "Ilau et al. (2025) modelled ransomware recovery in a medium-sized organisation and compared recovery strategies over "
             "9,000 parameter configurations (450,000 simulation runs)."),
    "plaka": ("Plaka, R. (2022). Backup & data recovery in cloud computing: A systematic mapping study. *Ingenious*.",
              "Plaka (2022) mapped 45 studies (2010-2020) on backup and disaster recovery and catalogued their causes, techniques, "
              "and privacy and security issues."),
    "lysetskyi": ("Lysetskyi, Y. M. (2025). Choosing an effective data backup and recovery strategy. *Mathematical Machines and Systems*.",
                  "Lysetskyi (2025) recommends the 3-2-1-1-0 rule with an air-gapped copy, because backups that cannot be reached "
                  "from the network survive ransomware."),
    "olugbile": ("Olugbile, O. H., Ojeniyi, J. A., & Anyachebelu, T. K. (2025). Towards a standard framework for cybersecurity "
                 "readiness for Nigerian universities. *International Journal of Applied Mathematics, Sciences, and Technology for "
                 "National Defense*.",
                 "Olugbile et al. (2025) used Design Science Research to build cybersecurity readiness tiers for Nigerian universities "
                 "covering pre-event, event-management and post-event factors, and named inadequate funding, weak infrastructure, "
                 "poor training and a shortage of professionals as the main obstacles."),
    "kodali": ("Kodali, A., & Sangani. (2026). Automatic ransomware-resilient encrypted backup system using SHA-256 change detection "
               "and AES-256-GCM encryption. In *2026 3rd International Conference on Research Methodologies in Knowledge Management, "
               "Artificial Intelligence and Telecommunication Engineering (RMKMATE)*. IEEE.",
               "Kodali and Sangani (2026) combined SHA-256 change detection with AES-256-GCM encryption in an automatic, "
               "ransomware-resilient backup tool."),
    "varshney": ("Varshney, P. K., & Kumar, R. (2026). A governance-oriented cyber recovery framework for ransomware preparedness and "
                 "resilience. *EDPACS*. https://doi.org/10.1080/07366981.2026.2682427",
                 "Varshney and Kumar (2026) treat fast, trustworthy restoration as a first-class security goal: behavioural detection "
                 "(97.4% accuracy at a 3.1% false-positive rate), an isolated immutable vault and an automated orchestrator that finds "
                 "a verified clean recovery point."),
    "farouk": ("Farouk, S., et al. (2024). Enhancing cybersecurity in Nigeria: A proposed risk management framework for universities. "
               "In *2024 International Conference on Science, Engineering and Business for Driving Sustainable Development Goals "
               "(SEB4SDG)*. IEEE.",
               "Farouk et al. (2024) note that Nigerian universities lack scientifically derived frameworks for managing cyber risk "
               "and propose situational crime prevention as one."),
    "pragathi": ("Pragathi, B. C., et al. (2024). Implementing an effective infrastructure monitoring solution with Prometheus and "
                 "Grafana. *International Journal of Computer Applications, 186*(38), 7-15.",
                 "Pragathi et al. (2024) deployed Prometheus, Grafana and Node Exporter on Kubernetes and reported shorter deployment "
                 "time and lower operating cost."),
    "rafiq": ("Rafiq, A., Shakir, M. Z., Gray, D., Inglis, J., & Ferguson, F. (2025). AI and IoT-driven monitoring and visualisation "
              "for optimising MSP operations in multi-tenant networks: A modular approach using sensor data integration. *Sensors, "
              "25*(19), 6248. https://doi.org/10.3390/s25196248",
              "Rafiq et al. (2025) ran five Prometheus instances on Raspberry Pi edge nodes to watch about 500 network elements in five "
              "client organisations, adding machine-learning anomaly prediction and alert routing."),
    "kumar": ("Kumar, B., Gupta, S. K., & Dwivedi, R. (2026). Artificial intelligence driven approach for securing backup data and "
              "enhancing cyber resilience in sustainable smart infrastructure. *Scientific Reports*. "
              "https://doi.org/10.1038/s41598-026-37802-6",
              "Kumar et al. (2026) argue that backup integrity must be verified before restoration, and report 98.65% accuracy for "
              "their AI-assisted integrity-verification and ransomware-detection pipeline."),
    "vinisha": ("Vinisha, J., Sanjay, R., & Sundar, D. (2025). Automated disaster recovery architecture for educational institutions "
                "web infrastructure using hybrid cloud. In *2025 2nd International Conference on Artificial Intelligence and Knowledge "
                "Discovery in Concurrent Engineering (ICECONF)*. IEEE.",
                "Vinisha et al. (2025) gave smaller colleges with one on-premises web server an on-demand cloud standby that health "
                "checks start automatically when the main server fails."),
    "tatineni": ("Tatineni, S. (2023). Cloud-based business continuity and disaster recovery strategies. *International Research "
                 "Journal of Modernization in Engineering Technology and Science*.",
                 "Tatineni (2023) lists risk assessment, backup, duplication and failover as the core of a disaster recovery plan."),
    "dotasara": ("Dotasara, M., & Sharma, A. (2022). MDAS_DBRCC: Data backup and recovery technique in cloud computing for education "
                 "industry. *International Journal on Recent and Innovation Trends in Computing and Communication*.",
                 "Dotasara and Sharma (2022) compress and encrypt education data before storing it in the cloud."),
}

B_REFS = {
    "rod": ("Rød, E. G., Gåsste, T., & Hegre, H. (2024). A review and comparison of conflict early warning systems. *International "
            "Journal of Forecasting, 40*(1), 96-112.",
            "Rød et al. (2024) compared conflict early warning systems on transparency, key parameters and forecasts, found weak "
            "access to data and code and large differences between systems, and called for shared standards."),
    "nnaji": ("Nnaji, A., Ma, W., Ratna, N., & Renwick, A. (2022). Farmer-herder conflicts and food insecurity: Evidence from rural "
              "Nigeria. *Agricultural and Resource Economics Review*.",
              "Nnaji et al. (2022) surveyed 401 rural Nigerian households and found that both the incidence and the severity of "
              "farmer-herder conflict raise food insecurity, severity more so."),
    "browning": ("Browning, R., Patten, H., Rousseau, J., & Mengersen, K. (2026). Bayesian spatiotemporal modelling of political "
                 "violence and conflict events using discrete-time Hawkes processes. *Journal of the Royal Statistical Society Series "
                 "A*. https://doi.org/10.1093/jrsssa/qnag039",
                 "Browning et al. (2026) fitted a Bayesian spatiotemporal Hawkes process to ACLED events in South Asia, treating "
                 "political violence as self-exciting (contagious) in space and time."),
    "goodman": ("Goodman, S., BenYishay, A., & Runfola, D. (2024). Spatiotemporal prediction of conflict fatality risk using "
                "convolutional neural networks and satellite imagery. *Remote Sensing, 16*(18), 3411. https://doi.org/10.3390/rs16183411",
                "Goodman et al. (2024) predicted sub-national conflict-fatality risk in Nigeria from Landsat 8 imagery and ACLED data, "
                "with an average AUC above 0.75, but performance fell when the geography of conflict shifted."),
    "sola": ("Sola, L., Chen, Y., Murphy, S. K., & Subrahmanian, V. S. (2025). Quantifying the risk of pastoral conflict in 4 central "
             "African countries. *EPJ Data Science, 14*. https://doi.org/10.1140/epjds/s13688-025-00591-5",
             "Sola et al. (2025) predicted pastoral conflict in Cameroon, Chad, the Central African Republic and the DRC from weather "
             "and terrain data (AUC 0.99 for Cameroon) and found that vegetation affects risk differently in each country."),
    "ronoh": ("Ronoh, E. K., Mirau, S., & Dida, M. A. (2022). Human-wildlife conflict early warning system using the Internet of "
              "Things and short message service. *Engineering, Technology & Applied Science Research*.",
              "Ronoh et al. (2022) built a low-cost early warning unit (motion sensor, GPS, camera, YOLO detection) that sends SMS "
              "alerts to response teams when animals approach a park border."),
    "shimizu": ("Shimizu, K., et al. (2025). Piloting a mobile early warning alert and response system for East and Central Darfur, "
                "Sudan. *International Health, 18*(2), ihaf122.",
                "Shimizu et al. (2025) describe the EWARS Mobile pilot in Darfur, whose offline reporting worked where network "
                "coverage was poor: 158 health facilities sent 752 weekly reports and the system was expanded to all Darfur states."),
    "rochana": ("Rochana, E., et al. (2024). The urgency of an early warning system for social conflict by using WhatsApp. "
                "*International Journal of Innovative Research and Scientific Studies, 7*(1), 107-114.",
                "Rochana et al. (2024) surveyed 267 villagers, found low public participation in conflict prevention, and proposed "
                "village-level early warning through WhatsApp groups."),
    "cicek": ("Cicek, D., & Kantarci, B. (2023). Use of mobile crowdsensing in disaster management: A systematic review, challenges, "
              "and open issues. *Sensors, 23*(3), 1699. https://doi.org/10.3390/s23031699",
              "Cicek and Kantarci (2023) reviewed mobile crowdsensing for disasters and found most studies conceptual, with little "
              "testing in real incidents."),
    "parlato": ("Parlato, M. C. M., Valenti, F., & Porto, S. M. C. (2024). GIS-based methodology for tracking the grazing cattle site "
                "use. *Heliyon, 10*(13), e33166. https://doi.org/10.1016/j.heliyon.2024.e33166",
                "Parlato et al. (2024) tracked grazing cattle with low-power GPS collars and used heatmaps and kernel density "
                "estimation to find the areas animals use most."),
    "schwarz": ("Schwarz, M., Landmann, T., Jusselme, D., Zambrano, E., Danzeglocke, J., Siegert, F., & Franke, J. (2022). Assessing "
                "the environmental suitability for transhumance in support of conflict prevention in the Sahel. *Remote Sensing, "
                "14*(5), 1109. https://doi.org/10.3390/rs14051109",
                "Schwarz et al. (2022) modelled environmental suitability for transhumance in Chad and the Central African Republic "
                "from Earth observation data, found most conflicts where suitability was high, and suggested combining herd tracking "
                "with satellite data for early warning along corridors."),
    "nwankwo": ("Nwankwo, C. F. (2025). Perceptions of injustices in the struggle for scarce critical lands: Farmer-herder conflict "
                "and violence escalation in the Benue-Nasarawa borderland. *World Development, 186*, 106824.",
                "Nwankwo (2025) showed from interviews in the Benue-Nasarawa borderland that perceived injustice drives escalation of "
                "farmer-herder violence."),
    "eke": ("Eke, O. G., et al. (2025). Climate-driven conflicts in Nigeria: Farmers' strategies for coping with herders' incursion on "
            "crop lands. *Sustainability, 17*(24), 11316. https://doi.org/10.3390/su172411316",
            "Eke et al. (2025) found Enugu farmers coping with herd incursions by farming in groups, reducing what they plant and "
            "preparing for crop loss, with falling income and productivity."),
    "kanagamalliga": ("Kanagamalliga, S., et al. (2024). Integration of IoT for precision livestock monitoring through geofencing. In "
                      "*2024 5th International Conference on Electronics and Sustainable Communication Systems (ICESC)*. IEEE.",
                      "Kanagamalliga et al. (2024) used IoT collars with geofencing and temperature sensing for remote monitoring "
                      "of livestock movement and health."),
    "estefania": ("Estefania-Salazar, E., & Iglesias, E. (2025). Assessing vegetation phenology dynamics in West African rangelands: "
                  "Implications for livestock sustainability and transhumance. *Ecological Informatics, 88*.",
                  "Estefania-Salazar and Iglesias (2025) analysed 250 m NDVI for 2003-2023 across 13 West African countries and "
                  "found growing seasons shortening through a later start, with consequences for transhumance routes."),
    "tarif": ("Tarif, K. (2022). *Climate change and violent conflict in West Africa: Assessing the evidence* (SIPRI Insights on Peace "
              "and Security). Stockholm International Peace Research Institute.",
              "Tarif (2022) reviewed the West African evidence and grouped climate-conflict links into four pathways, including "
              "changing pastoral mobility, while warning that the research base is thin."),
    "navarro": ("Navarro, R., Saleh, L., & Owino, E. (2025). Pastoral conflict on the greener grass? Exploring the climate-conflict "
                "nexus in the Karamoja Cluster. *International Journal of Disaster Risk Reduction*.",
                "Navarro et al. (2025) found in the Karamoja Cluster that vegetation data predicted pastoral conflict one month ahead "
                "better than rainfall, and that conflict clustered 'on the greener grass'."),
    "babatunde": ("Babatunde, A. O., & Ibnouf, F. O. (2024). The dynamics of herder-farmer conflicts in Plateau State, Nigeria, and "
                  "Central Darfur State, Sudan. *African Studies Review, 67*(2), 321-350. https://doi.org/10.1017/asr.2024.45",
                  "Babatunde and Ibnouf (2024) showed that officials, traditional rulers and security agents in Plateau State "
                  "deepened conflict through unequal resource allocation and peacebuilding that favoured some groups."),
}

STANDARDS = [
    "Federal Republic of Nigeria. (2023). *Nigeria Data Protection Act, 2023*. Nigeria Data Protection Commission.",
    "International Organization for Standardization. (2022). *ISO/IEC 27001:2022 Information security, cybersecurity and privacy "
    "protection: Information security management systems: Requirements*. ISO.",
    "National Institute of Standards and Technology. (2024). *The NIST Cybersecurity Framework (CSF) 2.0* (NIST CSWP 29). NIST.",
]

# Shared review paragraphs. Each report adds its own "closest related work" section on top of these.
A_REVIEW = [
    ("Cybersecurity in Nigerian universities",
     ["olugbile", "farouk"],
     "Nigerian work on university cybersecurity agrees that the weak points are after an attack starts, not only before it. "
     "{olugbile} {farouk} Neither study builds or measures a working recovery system, which leaves room for the practical "
     "contribution of this project."),
    ("Monitoring and automated response",
     ["simili", "pragathi", "rafiq"],
     "Open-source monitoring stacks dominate recent practice. {simili} {pragathi} {rafiq} The common lesson is that monitoring "
     "pays off when it triggers action automatically, and that small teams benefit most."),
    ("Backup strategy and disaster recovery",
     ["lysetskyi", "plaka", "tatineni", "muthoni", "vinisha", "dotasara"],
     "{lysetskyi} {plaka} {tatineni} Education-specific studies add cost and skills constraints. {muthoni} {vinisha} {dotasara}"),
    ("Ransomware-resilient recovery",
     ["baek", "kodali", "amoruso", "varshney", "kumar", "ilau"],
     "Recent work moves from detection alone to guaranteed recovery. {baek} {kodali} {amoruso} {varshney} {kumar} {ilau}"),
]

B_REVIEW = [
    ("Farmer-herder conflict in Nigeria and the region",
     ["nnaji", "nwankwo", "babatunde", "eke", "tarif"],
     "{nnaji} {nwankwo} {babatunde} {eke} {tarif} Together these studies explain why prevention must be local, fast and trusted "
     "by both farming and herding communities."),
    ("Conflict early warning systems and forecasting",
     ["rod", "goodman", "sola", "browning"],
     "{rod} {goodman} {sola} {browning} Forecast accuracy matters, but so do transparency and whether the people at risk can act "
     "on the warning."),
    ("Environment, mobility and herd tracking",
     ["schwarz", "estefania", "navarro", "parlato", "kanagamalliga"],
     "{schwarz} {estefania} {navarro} {parlato} {kanagamalliga}"),
    ("Community reporting and mobile alerting",
     ["rochana", "cicek", "shimizu", "ronoh"],
     "{rochana} {cicek} {shimizu} {ronoh} Low-cost phones, SMS and offline-capable tools reach people that web dashboards miss."),
]
