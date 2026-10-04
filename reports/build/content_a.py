"""Report content for the ten backup, monitoring and recovery systems (family A)."""


def kib(n):
    return f"{n / 1024:.1f} KiB"


COMMON_CMP = [
    ["Overview of security in computing", "CIA triad: encryption (confidentiality), hashing and signatures (integrity), copies and restore (availability)"],
    ["Characteristics of computer intrusion", "Ransomware behaviour model: mass modification, new extensions, ransom notes, high-entropy output"],
    ["Types of security breaches", "Data destruction, data tampering, insider deletion of backups, unauthorised access to the console"],
    ["Classes of attacks", "Ransomware, brute-force login, cross-site request forgery, backup tampering"],
    ["Methods of defence and controls", "Preventive, detective and corrective controls listed in Table 3.2"],
    ["Data security: encryption and decryption", "See Section 3.5 and 3.6"],
    ["Network security", "Service reachability checks, security headers, SameSite cookies"],
    ["Security policies and standards", "Backup and retention policy in config.json; NIST CSF 2.0 Recover; ISO/IEC 27001:2022; NDPA 2023"],
]

A = [
 {"id": "A01", "folder": "A01-abu-zaria-zariasafe", "name": "ZariaSafe", "port": 5101,
  "title": "ZariaSafe: A Versioned-Mirror Backup, Monitoring and Recovery System for Ahmadu Bello University, Zaria",
  "subtitle": "Point-in-time encrypted versions with a mass-change ransomware detector, built on Python's standard web server",
  "place": "Ahmadu Bello University (ABU), Zaria, Kaduna State",
  "context": "ABU Zaria is one of the largest universities in West Africa, with the main Samaru campus, the Kongo campus and many "
             "affiliated institutions. Its registry, bursary, results, learning materials and payroll records sit on a small number "
             "of servers looked after by a busy ICT directorate. When one of those servers fails, or when a staff laptop connected "
             "to a shared drive is infected with ransomware, the records of tens of thousands of students are at risk.",
  "problems": ["Backups are copied by hand to external drives, irregularly, and are never tested by restoring them.",
               "A backup job that runs after ransomware has struck copies encrypted files over the last good copies.",
               "There is no way to rebuild the records as they were on a chosen date, for example before a disputed result change.",
               "Outages of the student portal are noticed by students before the ICT staff."],
  "objectives": ["take scheduled, encrypted, point-in-time versions of university records that store only changed files;",
                 "detect ransomware-like mass change before a backup runs and hold the backup so the clean history is protected;",
                 "restore any version, in place or to a side folder, and measure the recovery time;",
                 "monitor host resources and the student portal, and restart the portal automatically;",
                 "protect the console with strong authentication, CSRF tokens and a signed audit trail;",
                 "evaluate the system with an automated attack-and-recovery test."],
  "scope": "ZariaSafe protects file-level records on one server and monitors HTTP and TCP services. The test data set has 15 files "
           "(about 130 KB) of synthetic student, fee, result, lecture and payroll records, so timings show relative behaviour, "
           "not production throughput.",
  "closest": ["kodali", "amoruso", "varshney"],
  "closest_text": "ZariaSafe shares the SHA-256 change detection and AES-256-GCM choice of Kodali and Sangani (2026) and the "
                  "integrity-before-trust idea of Amoruso et al. (2026). It differs in where the check happens: instead of judging "
                  "each file, it judges the whole backup run, holding it when 30% or more of protected files change at once. Unlike "
                  "the vault of Varshney and Kumar (2026), it needs no separate appliance and no web framework.",
  "gap": "None of the reviewed systems was designed for a Nigerian university ICT unit that must run on one ordinary server with "
         "no web framework, yet still offers point-in-time versions, a whole-run ransomware hold and measured recovery.",
  "fr": ["Back up changed files on a schedule and on demand", "Hold a backup when the run looks like ransomware", "Restore any version in place or to another folder",
         "Verify every encrypted object and repair it from a replica", "Monitor CPU, memory, disk, HTTP and TCP services", "Restart the portal when it is down",
         "Record every action in a signed audit trail"],
  "nfr": ["Runs with only two third-party packages (cryptography, psutil)", "Works on Windows, Linux and macOS", "A non-specialist can set it up with 1_SETUP.bat",
          "Role separation: admin and read-only auditor"],
  "layers": [["Student portal", "Server host"], ["Monitor", "Scheduler"], ["Ransomware detector", "Version store (AES-GCM)"], ["Replica: second disk", "Replica: Samaru campus"]],
  "components": [["core.py", "Backup versions, signed manifests, detector, verify and repair, restore, monitoring, signed audit trail"],
                 ["web.py", "Console on http.server with sessions, CSRF tokens, lockout, roles and scheduler thread"],
                 ["demo.py", "Synthetic ABU records, demo portal and safe ransomware simulations"],
                 ["main.py / selftest.py", "Command line and automated tests"]],
  "threats": [["Ransomware encrypts records in place", "Mass-change detector holds the backup; restore from last good version"],
              ["Ransomware renames files and leaves a note", "Extension and ransom-note checks hold the backup"],
              ["Someone edits a stored backup file", "AES-GCM authentication fails; repair from replica"],
              ["Someone edits a version manifest", "HMAC-SHA256 manifest signature fails; restore refused"],
              ["Insider changes the audit trail", "HMAC chain breaks at the edited row"],
              ["Password guessing on the console", "PBKDF2 (310,000 iterations), 5-failure lockout"],
              ["Cross-site request forgery", "Per-session CSRF token, SameSite=Strict cookie"]],
  "algorithms": [
    ("Versioned-mirror backup", "For each run: hash every source file with SHA-256; compare with the previous version's manifest; "
     "encrypt only new or changed files with AES-256-GCM (random 96-bit nonce, file path as associated data); write a manifest "
     "listing every file and the version that holds its object; sign the manifest with HMAC-SHA256; copy the version folder to the replicas."),
    ("Mass-change ransomware detector", "Before writing a version, compute the share of protected files that changed or vanished since "
     "the last good version. If it is 30% or more (with at least 5 files), or ransomware extensions or ransom notes appear, mark the run "
     "HELD, raise a critical alert and write nothing."),
    ("Restore", "Read and verify the manifest signature, delete files that are not in the version (removes ransom notes and .locked "
     "files), decrypt each object from the version that holds it, and write it back."),
  ],
  "keys_used": "A random 256-bit master key; sub-keys for data, manifests and the audit trail are derived with HMAC-SHA256.",
  "metrics": lambda r: [
      ["Protected data set", f"{r['dataset_files']} files, {kib(r['dataset_bytes'])}"],
      ["First (full) backup", f"{r['full_backup']['changed']} files, {r['full_backup']['seconds']} s, stored {kib(r['full_backup']['bytes_stored'])}"],
      ["Incremental backup after one edit", f"{r['incremental_backup']['changed']} file copied, {r['incremental_backup']['seconds']} s"],
      ["Unchanged backup", f"{r['unchanged_backup']['changed']} files copied, {r['unchanged_backup']['seconds']} s"],
      ["Files hit by simulated ransomware", str(r["recovery"]["files_encrypted"])],
      ["Recovery time (RTO) measured", f"{r['recovery']['rto_seconds']} s, byte-identical: {r['recovery']['byte_identical']}"],
      ["Objects checked by verification", str(r["verify_checked_objects"])]],
  "discussion": "The full backup stored slightly more than the original data because ZariaSafe encrypts without compressing, so each "
                "file gains a 12-byte nonce and a 16-byte authentication tag. Compression before encryption would cut storage but "
                "would also open the door to compression side-channels on shared data; for a single-owner backup it is a reasonable "
                "later addition. The whole-run detector caught both the quiet attack (40% of files changed) and the loud one. Its "
                "weakness is a slow attacker who encrypts a few files per interval; the per-file entropy checks used in other "
                "designs (for example LionKeep) would close that gap.",
  "recommendations": ["Point the second replica at a different building on Samaru or Kongo campus, or at an external drive that is unplugged after each copy.",
                      "Keep the master key file off the server and in the ICT Director's safe; ZariaSafe needs it only for restore and verify.",
                      "Run selftest.py each semester as a recovery drill and keep the results as evidence for the NDPA compliance file.",
                      "Add per-file entropy checks to catch slow encryption."],
  "further": ["Compress before encrypting to save storage.", "Put the console behind HTTPS with a university certificate.",
              "Stream version folders to an object store with object lock."],
 },
 {"id": "A02", "folder": "A02-unn-nsukka-lionkeep", "name": "LionKeep", "port": 5102,
  "title": "LionKeep: Full and Differential Encrypted Backup with Grandfather-Father-Son Retention for the University of Nigeria, Nsukka",
  "subtitle": "Signature and entropy validation keeps suspicious files out of the archives",
  "place": "University of Nigeria (UNN), Nsukka, Enugu State",
  "context": "UNN runs campuses in Nsukka and Enugu and a teaching hospital at Ituku-Ozalla. Its ICT staff are used to tape-style "
             "thinking: a weekly full backup and smaller backups in between. That model is easy to explain to auditors, but it "
             "breaks when ransomware turns the files themselves into rubbish before the next differential runs.",
  "problems": ["Differential and incremental jobs copy whatever is on disk, including files that ransomware has just encrypted.",
               "There is no written retention rule, so old backups are either kept forever or deleted at random.",
               "Restores need a chain of many archives, which takes long and fails if one archive is missing.",
               "Backups are not encrypted, so a stolen external drive exposes student data."],
  "objectives": ["implement full and differential archives so that any restore needs at most two archives;",
                 "encrypt archives with a key derived from an operator passphrase;",
                 "validate every file's signature and entropy before it enters an archive, and quarantine suspicious files;",
                 "apply Grandfather-Father-Son retention automatically;",
                 "monitor services and keep a hash-linked activity log;",
                 "evaluate with an automated attack-and-recovery test."],
  "scope": "LionKeep protects one folder tree per server and three storage copies. Tests used 15 synthetic UNN files (about 128 KB).",
  "closest": ["amoruso", "kumar", "dotasara"],
  "closest_text": "LionKeep applies the integrity-before-trust idea of Amoruso et al. (2026) at file level and checks integrity "
                  "before data is trusted, as Kumar et al. (2026) argue. Like Dotasara and Sharma (2022) it compresses and encrypts "
                  "education data before storage. Unlike them, it combines this with a classic full + differential schedule and a "
                  "formal retention scheme that an auditor can check.",
  "gap": "Classic differential schedules and modern ransomware gating are usually studied apart. LionKeep shows they can live "
         "together on one server at a Nigerian university.",
  "fr": ["Take full and differential archives", "Quarantine files that fail signature or entropy checks", "Abort a backup when three or more files are suspicious",
         "Restore from the full archive plus at most one differential", "Rotate archives by Grandfather-Father-Son", "Verify archive hashes and repair from copies",
         "Monitor services, restart the portal"],
  "nfr": ["Flask dashboard with admin, operator and viewer roles", "Per-account lockout", "Runs on Windows and Linux"],
  "layers": [["Protected folders"], ["Signature + entropy validator", "Quarantine log"], ["ZIP + Fernet archive (full / diff)"], ["Primary store", "ICT Centre NAS", "Enugu campus copy"]],
  "components": [["core.py", "Archives, validation, quarantine, GFS rotation, verify, restore, monitoring, hash-linked log"],
                 ["app.py", "Flask dashboard, roles, lockout, scheduler"], ["demo.py", "Synthetic UNN records and simulations"],
                 ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Ransomware encrypts CSV files in place", "UTF-8 and entropy checks quarantine them; three or more abort the backup"],
              ["A PDF or DOCX is replaced with ciphertext", "Magic-byte signature check fails"],
              ["Archive file damaged on disk", "SHA-256 catalogue check fails; replaced from NAS copy"],
              ["Stolen backup drive", "Fernet encryption, PBKDF2 key (600,000 iterations)"],
              ["Brute-force on an account", "Lock for 15 minutes after 5 failures"],
              ["Viewer tries to restore", "Role check returns 403"]],
  "algorithms": [
    ("File validation", "For each file read the first 64 KiB. If the extension is a known binary type, the leading bytes must match "
     "its signature (PDF starts with %PDF, DOCX/XLSX with PK). Text types must decode as UTF-8. Other files must have Shannon "
     "entropy at or below 7.2 bits per byte. Failing files are quarantined, their last clean copy stays listed in the manifest."),
    ("Full + differential", "A full archive holds every file. A differential holds files whose SHA-256 differs from the last full. "
     "Restore = unzip the full, overlay the chosen differential, delete files not in the manifest, check every SHA-256."),
    ("Grandfather-Father-Son", "Month-end archives are grandfathers (keep 12), Fridays are fathers (keep 5), other days are sons "
     "(keep 7). A full archive is never deleted while a kept differential depends on it."),
  ],
  "keys_used": "Fernet (AES-128-CBC with HMAC-SHA256) under a key derived from the operator passphrase with PBKDF2-HMAC-SHA256, 600,000 iterations and a random salt.",
  "metrics": lambda r: [
      ["Protected data set", f"{r['dataset_files']} files, {kib(r['dataset_bytes'])}"],
      ["Full archive", f"{kib(r['full_backup']['raw_bytes'])} compressed and encrypted to {kib(r['full_backup']['stored_bytes'])} in {r['full_backup']['seconds']} s"],
      ["Differential after 1 change", f"{r['differential_1']['files']} file, {kib(r['differential_1']['stored_bytes'])}"],
      ["Differential after 2 changes", f"{r['differential_2']['files']} files (cumulative), {kib(r['differential_2']['stored_bytes'])}"],
      ["Archives used by restore", str(r["recovery"]["archives_used"])],
      ["Recovery time (RTO) measured", f"{r['recovery']['rto_seconds']} s, byte-identical: {r['recovery']['byte_identical']}"]],
  "discussion": "Compression shrank the archive to about 28% of the original because CSV and text records compress well. Most of "
                "the 0.2-0.4 s per run is the PBKDF2 key derivation, which is deliberately slow to protect the passphrase. Partial "
                "quarantine is the main strength: when one results file was encrypted, the backup still ran for everything else and "
                "the clean copy of that file stayed restorable. Differentials grow until the next full archive, which is the price "
                "of needing only two archives to restore.",
  "recommendations": ["Set LIONKEEP_PASSPHRASE in the environment and delete the demo passphrase file before real use.",
                      "Take the full archive weekly, on Friday night, so it becomes a 'father'.",
                      "Keep the Enugu campus copy on a separate network segment."],
  "further": ["Add signatures for more university file types (images of certificates, scanned transcripts).",
              "Send the quarantine list by email to the ICT Director each morning."],
 },
 {"id": "A03", "folder": "A03-ui-ibadan-premierguard", "name": "PremierGuard", "port": 5103,
  "title": "PremierGuard: De-duplicated, Merkle-Verified Snapshot Backup for the University of Ibadan",
  "subtitle": "Content-defined chunking, ChaCha20-Poly1305 and a compressibility-based ransomware detector",
  "place": "University of Ibadan (UI), Ibadan, Oyo State",
  "context": "UI keeps large, slowly changing collections: decades of results, theses in the Kenneth Dike Library, and lecture "
             "material that is edited a little every session. Copying everything every night wastes disk and time, and fixed-block "
             "de-duplication fails when one line is inserted near the top of a file.",
  "problems": ["Nightly full copies waste storage on files that hardly change.", "Simple block de-duplication breaks when text is inserted.",
               "There is no way to prove later that a snapshot has not been altered.", "Ransomware output is backed up without question."],
  "objectives": ["split files into content-defined chunks and store each unique chunk once;", "encrypt chunks with ChaCha20-Poly1305 and keyed chunk IDs;",
                 "seal each snapshot with a Merkle root kept at a separate anchor location;", "block snapshots when text files stop compressing like text;",
                 "provide a JSON API and single-page dashboard; monitor CPU with an adaptive baseline;", "evaluate de-duplication, detection and recovery."],
  "scope": "Tests used 15 synthetic UI files plus a 250 KB handbook for the chunking experiment.",
  "closest": ["kodali", "kumar", "plaka"],
  "closest_text": "Where Kodali and Sangani (2026) detect change with whole-file SHA-256, PremierGuard detects it at chunk level, so a "
                  "small edit to a large file costs one chunk. Kumar et al. (2026) verify integrity before restoration; PremierGuard "
                  "does the same with a Merkle root compared against an anchor kept elsewhere. Plaka (2022) lists data integrity as an "
                  "open problem; the anchor gives a cheap, checkable answer.",
  "gap": "Content-defined de-duplication, Merkle anchoring and a ransomware gate are rarely combined in a tool small enough for a "
         "single university server.",
  "fr": ["Snapshot with content-defined chunking", "Store each unique chunk once", "Block snapshots with three or more encrypted-looking files",
         "Verify Merkle roots and chunks, repair from mirrors", "Restore any snapshot", "Garbage-collect unreferenced chunks", "Monitor CPU with EWMA, probe services"],
  "nfr": ["JSON API with header-based CSRF token", "Roles: admin and observer", "Standard Python plus Flask and cryptography"],
  "layers": [["Protected folders"], ["Gear-hash chunker", "Compressibility detector"], ["Chunk store (ChaCha20-Poly1305)", "Merkle tree"], ["Mirrors", "Anchor log (Registrar)"]],
  "components": [["engine.py", "Chunking, encryption, Merkle trees, detector, snapshots, verify, restore, GC, monitoring"],
                 ["server.py", "JSON API, single-page dashboard, scheduler"], ["demo.py", "Synthetic UI records and simulations"],
                 ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Ransomware encrypts CSVs quietly", "Incompressible text detected; snapshot blocked"], ["Corrupted chunk", "Poly1305 tag and keyed ID fail; repaired from mirror"],
              ["Snapshot tree swapped or edited", "Merkle root differs from the anchor; restore refused"],
              ["Attacker tests whether a known file is stored", "Chunk IDs are HMAC-keyed, not plain hashes"],
              ["Forged API call from another site", "X-CSRF-Token header required"]],
  "algorithms": [
    ("Gear content-defined chunking", "Roll h = (h << 1) + GEAR[byte] over the file. Cut a chunk when the top 13 bits of h are zero "
     "(average about 8 KiB), never below 2 KiB or above 64 KiB. Because cuts depend on content, an insertion changes only nearby chunks."),
    ("Compressibility detector", "For CSV, TXT, SQL, JSON and similar files over 1 KiB, compress with zlib level 1. Text normally "
     "shrinks below 40%; a ratio above 0.95 means ciphertext. Three such files block the snapshot."),
    ("Merkle anchoring", "Leaves are 'path:chunk-ids' strings. Pairs are hashed upward with SHA-256 to one root. The root is appended "
     "to an anchor log held by the Registrar's office. Verify and restore recompute the root and compare."),
  ],
  "keys_used": "One 256-bit root key; HKDF-SHA256 derives separate keys for chunk IDs, chunk encryption and snapshot trees.",
  "metrics": lambda r: [
      ["Protected data set", f"{r['dataset_files']} files, {kib(r['dataset_bytes'])}"],
      ["First snapshot", f"{r['first_snapshot']['chunks']} chunks, stored {kib(r['first_snapshot']['bytes_new'])} in {r['first_snapshot']['seconds']} s"],
      ["Unchanged snapshot", f"{r['unchanged_snapshot']['new_chunks']} new chunks"],
      ["Insert one line at the top of a 250 KB file", f"{r['cdc_insert_test']['new_chunks_after_insert']} new chunk of {r['cdc_insert_test']['chunks_in_file']}"],
      ["Storage saved by de-duplication and compression", f"{r['dedup_saving_percent']}%"],
      ["Recovery time (RTO) measured", f"{r['recovery']['rto_seconds']} s, byte-identical: {r['recovery']['byte_identical']}"]],
  "discussion": "An early version cut chunks on the low bits of the Gear hash and failed the insertion test: repetitive text never "
                "produced a cut, so every chunk was forced at 64 KiB and shifted. Testing on the top 13 bits fixed it (1 new chunk of "
                "31). This shows why the self-test exists. Chunking in pure Python is slow for gigabytes; production use would need a "
                "compiled chunker. The compressibility detector is simple and strong for text, but it cannot judge files that are "
                "already compressed (ZIP, JPEG), which therefore skip the check.",
  "recommendations": ["Print the anchor log weekly and file it at the Registrar's office.", "Move one mirror to a different campus building.",
                      "Exclude huge media files or move chunking to a compiled library."],
  "further": ["Publish Merkle roots to an external timestamping service.", "Add per-user restore of single files from the dashboard."],
 },
 {"id": "A04", "folder": "A04-oau-ife-ifesentinel", "name": "IfeSentinel", "port": 5104,
  "title": "IfeSentinel: Agent-Based Monitoring and Zero-Knowledge Backup Across Obafemi Awolowo University Computers",
  "subtitle": "Signed heartbeats, replay protection, canary files and backups the central server cannot read",
  "place": "Obafemi Awolowo University (OAU), Ile-Ife, Osun State",
  "context": "OAU's records are not on one server. The Registry, the Bursary, faculty offices and computer laboratories each run their own "
             "machines. A central backup server that can read everything becomes the most valuable target on campus, and a "
             "machine that stops reporting is often a power cut nobody logged.",
  "problems": ["Many computers, no single view of their health.", "A central backup server holds readable copies of every record.",
               "An attacker on the network could replay or forge status reports.", "Ransomware on one PC can poison that PC's backups."],
  "objectives": ["run a small agent on each computer that reports to a central console;", "authenticate agents with one-time enrolment and per-agent keys;",
                 "sign every request and refuse stale or replayed ones;", "encrypt backups on the agent so the server stores only ciphertext;",
                 "isolate a computer whose canary files change and freeze its backup history;", "detect offline computers; evaluate everything automatically."],
  "scope": "The demonstration runs three agents (Registry server, Bursary PC, CSE laboratory) and the console on one laptop; the README "
           "explains real multi-computer deployment.",
  "closest": ["rafiq", "varshney", "simili"],
  "closest_text": "Rafiq et al. (2025) monitored about 500 devices across five organisations with edge nodes reporting to a centre; "
                  "IfeSentinel uses the same centre-and-edge shape but adds signed, replay-proof agent traffic. Varshney and Kumar "
                  "(2026) isolate a clean vault; IfeSentinel isolates the infected computer and marks its later uploads untrusted. "
                  "Unlike the Glasgow system (Simili et al., 2021), the central server never holds the data keys.",
  "gap": "Reviewed monitoring systems trust the central server completely. IfeSentinel shows a design where the centre can monitor "
         "and store but cannot read university records.",
  "fr": ["Enrol computers with one-time tokens", "Signed heartbeats with CPU, memory, disk", "Mark computers offline after 3 missed heartbeats",
         "Canary trip and text-to-binary detection isolate the computer", "Agent-side encrypted incremental backups",
         "Restore from trusted uploads only", "Admin releases a computer after clean-up"],
  "nfr": ["Agent needs Python, cryptography and psutil", "Console shows every computer as a card", "Real deployment over LAN with firewall rule"],
  "layers": [["Agent: Registry", "Agent: Bursary", "Agent: CSE lab"], ["Signed API (HMAC + nonce + time)"], ["Central console", "Ciphertext blob store"]],
  "components": [["agent.py", "Heartbeat, canaries, garble check, encrypted backup and restore, enrolment"],
                 ["server.py", "Signed agent API, replay cache, blob store, offline sweep, staff console"],
                 ["main.py / selftest.py", "Setup of demo fleet, simulations, tests"]],
  "threats": [["Fake agent joins", "One-time enrolment token, stored only as a hash"], ["Forged heartbeat", "HMAC-SHA256 over method, path, time, nonce, body hash"],
              ["Captured request replayed", "120 s freshness window plus nonce cache"], ["Central server stolen", "Data key never leaves the agent"],
              ["Ransomware on one PC", "Canary files and text-to-binary check isolate it; later uploads untrusted"],
              ["Stored blob altered", "SHA-256 check before download"]],
  "algorithms": [
    ("Request signing", "sig = HMAC-SHA256(agent secret, method | path | timestamp | nonce | SHA-256(body)). The server recomputes it, "
     "refuses timestamps more than 120 s away, and refuses any nonce seen in the last 5 minutes."),
    ("Canary isolation", "At enrolment the agent writes decoy files named to sort first (!000_Staff_Salaries_2026.xlsx) in each folder "
     "and stores their hashes. Any change or deletion triggers a single 'canary tripped' report; the server isolates the agent."),
    ("Trusted restore", "Fetch the catalogue, keep only trusted blobs, start from the newest trusted full, replay later trusted "
     "incrementals, check every file's SHA-256 against the last manifest."),
  ],
  "keys_used": "Per-agent 256-bit HMAC secret issued at enrolment; per-agent AES-256-GCM data key generated and kept on the agent.",
  "metrics": lambda r: [
      ["Files per agent", str(r["dataset_files_per_agent"])],
      ["Initial full backups", f"{len(r['initial_full_backups'])} agents"],
      ["Incremental after one edit", f"{r['incremental_backup']['files']} file, {kib(r['incremental_backup']['bytes'])}"],
      ["Blobs used in restore", str(r["recovery"]["blobs_used"])],
      ["Recovery time (RTO) measured", f"{r['recovery']['rto_seconds']} s, byte-identical: {r['recovery']['byte_identical']}"]],
  "discussion": "The test suite exposed one design mistake early: replay tests that changed the system clock also moved the server's "
                "clock, because both ran in one process. The final tests craft signed requests by hand instead. Zero-knowledge "
                "storage has a cost: if a computer's agent.json is lost, its backups are lost too, so the key file itself must be "
                "kept safe offline. The console does not yet use HTTPS; the HMAC signatures protect integrity and replay, and "
                "backups are encrypted, but heartbeat values travel in clear text on the LAN.",
  "recommendations": ["Put the console behind HTTPS before campus-wide use.", "Store each agent.json on an encrypted USB in the ICT safe.",
                      "Start agents with Task Scheduler at boot so power cuts show as offline and then back online."],
  "further": ["Push configuration (thresholds, schedules) from the console to agents.", "Add per-agent quotas on the blob store."],
 },
 {"id": "A05", "folder": "A05-uniben-beninvault", "name": "BeninVault", "port": 5105,
  "title": "BeninVault: Erasure-Coded Encrypted Backup and Service-Level Monitoring for the University of Benin",
  "subtitle": "Two data shards and one XOR parity shard over three sites, with scrubbing and SLA tracking",
  "place": "University of Benin (UNIBEN), Benin City, Edo State",
  "context": "UNIBEN has two main campuses, Ugbowo and Ekehuan. Keeping three full copies of every backup triples storage cost, while "
             "keeping one copy means a single fire or theft can destroy it. Management also asks a question the ICT team cannot "
             "answer: how many hours was the portal actually up this month?",
  "problems": ["Three full copies are too expensive; one copy is too risky.", "Damaged backup copies are discovered only during a crisis.",
               "Ransomware that renames files is not noticed until students complain.", "There is no uptime figure to compare with a service target."],
  "objectives": ["split each encrypted backup into two data shards and one parity shard on three sites;", "rebuild a missing or damaged shard automatically (scrubbing);",
                 "refuse backups that show rename bursts, ransom notes or unreadable text;", "track service uptime against SLA targets;",
                 "provide a Flask console with roles and a hash-linked trail;", "evaluate loss of each site and attack recovery."],
  "scope": "Three directories stand in for the three sites in the demonstration; in production they are mounts of different buildings or a cloud bucket.",
  "closest": ["lysetskyi", "tatineni", "plaka"],
  "closest_text": "Lysetskyi (2025) and Tatineni (2023) rely on multiple full copies. BeninVault reaches the same survive-one-site "
                  "goal with 1.5 times the storage instead of 3 times. Plaka (2022) names integrity of stored backups as an open "
                  "issue; per-shard SHA-256 and scheduled scrubbing address it directly.",
  "gap": "Erasure coding is common in large storage systems but absent from the reviewed university backup work.",
  "fr": ["Encrypt and split each backup into A, B and P shards", "Restore from any two healthy shards", "Scrub: rebuild missing or damaged shards",
         "Refuse backups showing ransomware signs", "Uptime per service against SLA", "Roles: admin and auditor"],
  "nfr": ["Storage overhead 50% over the archive", "Jinja templates for easy changes", "Runs on one server"],
  "layers": [["Protected folders"], ["Detector (rename burst, text, note)"], ["ZIP + AES-256-GCM archive"], ["Shard A: Ugbowo", "Shard B: Ekehuan", "Shard P: cloud"]],
  "components": [["vault.py", "Encryption, erasure coding, scrubbing, detection, restore, SLA"], ["app.py", "Flask console and scheduler"],
                 ["templates/", "Jinja page templates"], ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["One site destroyed", "Restore from the other two shards"], ["Shard silently damaged", "SHA-256 per shard; scrub rebuilds"],
              ["Two sites lost", "Reported as unrecoverable instead of restoring wrong data"], ["Rename-style ransomware", "Rename burst detector"],
              ["Stolen shard", "Shards are halves or parity of ciphertext; key derived with scrypt"], ["Auditor tries to restore", "403"]],
  "algorithms": [
    ("2 + 1 XOR erasure coding", "archive = nonce || AES-GCM(zip). A = first half, B = second half padded, P = A XOR B. Any one "
     "missing shard is rebuilt: A = B XOR P or B = A XOR P. Each shard's SHA-256 is stored in the catalogue."),
    ("Scrubbing", "For every backup: read the three shards, keep those whose hash matches; if two remain, rebuild the archive and "
     "rewrite the missing shard; if fewer than two remain, raise a critical alert."),
    ("Rename-burst detection", "An old file name that now exists only as a stem of a new name (students.csv to students.csv.locked) "
     "counts as renamed; three or more in one interval refuse the backup."),
  ],
  "keys_used": "scrypt (n = 2^15, r = 8, p = 1) derives the AES-256-GCM key from a passphrase and random salt; the backup ID is associated data.",
  "metrics": lambda r: [
      ["Protected data set", f"{r['dataset_files']} files, {kib(r['dataset_bytes'])}"],
      ["Encrypted archive", f"{kib(r['backup']['cipher_bytes'])} in {r['backup']['seconds']} s"],
      ["Each shard", kib(r["backup"]["shard_bytes"])],
      ["Storage overhead over one archive", f"{r['storage_overhead_percent']}% (three full copies would be 200%)"],
      ["Recovery time (RTO) measured", f"{r['recovery']['rto_seconds']} s, byte-identical: {r['recovery']['byte_identical']}"],
      ["SLA example (3 of 4 checks up)", f"{r['sla_example'][0]['uptime']}% against {r['sla_example'][0]['target']}% target"]],
  "discussion": "Restores succeeded with any one site removed, and losing two sites was reported clearly instead of producing a "
                "wrong file. XOR parity tolerates exactly one loss; Reed-Solomon coding would tolerate more at higher complexity. "
                "Because shards are made from ciphertext, one stolen shard reveals nothing useful. The SLA figure is only as good as "
                "the check interval: a 15-second check cannot see a 5-second outage.",
  "recommendations": ["Mount shard P on a cloud bucket with Object Lock, shards A and B in different campus buildings.",
                      "Report monthly uptime to the Vice-Chancellor's office from the SLA chart.", "Run scrub at least daily."],
  "further": ["Reed-Solomon (k of n) coding for more sites.", "Incremental archives to reduce shard size."],
 },
 {"id": "A06", "folder": "A06-unimaid-sahelstore", "name": "SahelStore", "port": 5106,
  "title": "SahelStore: Low-Bandwidth, Power-Aware Backup and Recovery for the University of Maiduguri",
  "subtitle": "rsync-style delta transfer to an offsite mirror, a daily data budget and an inverter-aware scheduler",
  "place": "University of Maiduguri (UNIMAID), Maiduguri, Borno State",
  "context": "UNIMAID works under conditions few backup products expect: long power outages served by inverters and generators, "
             "expensive and slow internet, and a security situation in Borno State that makes an offsite copy essential. Sending "
             "whole files offsite every night is not affordable, and a backup that runs while the inverter is dying can corrupt data.",
  "problems": ["Full offsite copies exceed the bandwidth budget.", "Heavy backup jobs drain the inverter during power cuts.",
               "There is no plan if the server room itself is lost.", "A web page that can trigger restores is a target."],
  "objectives": ["keep compressed, encrypted local snapshots;", "send only changed byte ranges offsite within a daily budget and an off-peak window;",
                 "defer heavy jobs on low battery and take one emergency snapshot at a critical level;", "recover everything from the offsite copy if the local store is lost;",
                 "provide a read-only status page; detect bursts of file modification;", "evaluate bandwidth, power behaviour and recovery."],
  "scope": "The offsite mirror is a folder in the demonstration; battery state comes from the laptop or a simulated UPS file.",
  "closest": ["vinisha", "muthoni", "lysetskyi"],
  "closest_text": "Vinisha et al. (2025) and Muthoni et al. (2021) assume steady cloud connectivity. SahelStore assumes the opposite "
                  "and saves bandwidth with block-level deltas. It keeps the offsite copy of Lysetskyi (2025) affordable on a "
                  "200 MB daily budget.",
  "gap": "None of the reviewed systems treats power and bandwidth scarcity as design inputs, although both shape daily ICT work in north-east Nigeria.",
  "fr": ["Local snapshots with LZMA + AES-GCM", "Delta sync offsite within window and budget", "Defer jobs below 40% battery; emergency snapshot at 15%",
         "Restore locally or from offsite", "Burst detector", "Read-only status page"],
  "nfr": ["Standard library web server", "Actions only from the server's command line", "Two packages: cryptography, psutil"],
  "layers": [["Protected folders", "UPS / battery"], ["Power-aware scheduler", "Burst detector"], ["Local store (LZMA + AES-GCM)"], ["Delta sync (budget, window)", "Offsite mirror (Abuja)"]],
  "components": [["sahel.py", "Snapshots, delta algorithm, offsite sync and restore, power logic, detection, hash-chained log"],
                 ["status_page.py", "Read-only page with HTTP Basic over PBKDF2, scheduler"], ["main.py / selftest.py", "Commands, simulations, tests"]],
  "threats": [["Local server room destroyed", "Offsite base + delta restore"], ["Offsite object altered", "AES-GCM tag fails"],
              ["Burst encryption", "Modified-file burst refuses the snapshot"], ["Web session hijacked", "Page is read-only; no destructive action exists on the web"],
              ["Password guessing on status page", "PBKDF2 and a 1-second delay on failure"]],
  "algorithms": [
    ("rsync-style delta", "Split the offsite copy into 2 KiB blocks, index each by a weak rolling checksum (a, b mod 2^16) and a "
     "truncated SHA-256. Slide over the new file one byte at a time, updating the weak checksum in O(1); on a weak match confirm with "
     "SHA-256 and emit 'copy block i', else collect literal bytes. Send the encrypted op list."),
    ("Power-aware scheduling", "On mains: normal. On battery at or below 40%: defer snapshots and syncs. At or below 15%: take one "
     "emergency snapshot, then stay idle until mains power returns."),
    ("Burst detection", "Count files that already existed in the last snapshot and were modified in the last 60 s; if five or more "
     "and at least 30% of files, refuse the snapshot."),
  ],
  "keys_used": "One 256-bit AES-GCM key; objects are labelled by their SHA-256 and the label is bound as associated data.",
  "metrics": lambda r: [
      ["Protected data set", f"{r['dataset_files']} files, {kib(r['dataset_bytes'])}"],
      ["First snapshot", f"stored {kib(r['first_snapshot']['bytes_stored'])} in {r['first_snapshot']['secs']} s"],
      ["Delta sync of edited register", f"{r['delta_sync']['sent_bytes']} bytes sent for {kib(r['delta_sync']['file_bytes'])} file"],
      ["Local recovery time", f"{r['recovery']['rto_seconds']} s"],
      ["Offsite recovery time (local store deleted)", f"{r['recovery']['offsite_rto_seconds']} s, byte-identical: {r['recovery']['byte_identical']}"]],
  "discussion": "Sending 756 bytes instead of 38 KB is a 98% saving for a typical edit. The test also found a real logic error: after "
                "the emergency snapshot, the scheduler fell through to normal jobs while still on a critical battery. The fixed "
                "version stays idle until mains returns. Delta chains are capped at 8 so a corrupt delta cannot spoil an unlimited "
                "history. The read-only page is a deliberate trade-off: less convenient, much smaller attack surface.",
  "recommendations": ["Use an offsite location outside Borno State (for example a partner university in Abuja).",
                      "Connect the server's UPS by USB so psutil reports the real battery.", "Set the daily budget from the actual data plan."],
  "further": ["Resume interrupted transfers mid-file.", "Encrypt the transport with TLS when the offsite end is a server."],
 },
 {"id": "A07", "folder": "A07-unilorin-harmonyvault", "name": "HarmonyVault", "port": 5107,
  "title": "HarmonyVault: A Signed, Git-Style Backup History with Honey Directories for the University of Ilorin",
  "subtitle": "Ed25519-signed commits, content-addressed encrypted objects and change-rate anomaly detection",
  "place": "University of Ilorin (UNILORIN), Ilorin, Kwara State",
  "context": "UNILORIN is widely known for keeping a stable academic calendar, which depends on records nobody can dispute. Disputes about "
             "results usually ask two questions: what did the record say on a given day, and has anyone altered the backup itself? "
             "Ordinary backups answer neither with proof.",
  "problems": ["Backups can be quietly replaced or deleted by someone with storage access.", "There is no readable history of what changed between two backups.",
               "Intruders browsing the share are not noticed.", "Fixed thresholds miss unusual change rates."],
  "objectives": ["store backups as signed commits in an encrypted object store;", "verify the full history from HEAD to the first commit;",
                 "show what changed between any two commits and each file's history;", "plant honey directories and refuse commits when they change;",
                 "detect unusual change rates with a z-score;", "evaluate tamper detection and recovery."],
  "scope": "One repository per server; signing key on the server; public key fingerprint displayed for checking.",
  "closest": ["ilau", "kodali", "farouk"],
  "closest_text": "Ilau et al. (2025) stress that recovery decisions depend on knowing which state is trustworthy; HarmonyVault proves "
                  "it with signatures. Kodali and Sangani (2026) detect change by hash; HarmonyVault adds a signed chain so the change "
                  "record itself cannot be rewritten. The honey directories apply the deterrence idea behind situational crime "
                  "prevention discussed by Farouk et al. (2024).",
  "gap": "Version-control style signed histories are standard for source code but missing from the reviewed backup systems.",
  "fr": ["Commit blobs, trees and signed commits", "Verify signatures and every object", "Diff any two commits; per-file history", "Honey files refuse commits",
         "z-score change anomaly", "Checkout any commit"],
  "nfr": ["Roles: custodian and reviewer", "Timeline user interface", "Two packages: flask, cryptography"],
  "layers": [["Protected folders", "Honey directories"], ["Anomaly + honey checks"], ["Blob / tree / commit objects (AES-GCM)"], ["Ed25519 signature chain"]],
  "components": [["history.py", "Object store, signing, honey files, anomaly, verify, diff, checkout"], ["web.py", "Timeline console and scheduler"],
                 ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Insider rewrites a commit with the storage key", "Ed25519 signature fails"], ["Commit object edited", "Keyed object ID mismatch"],
              ["Intruder edits exam questions folder", "Honey file check refuses the commit"], ["Quiet encryption of 6 files", "z = 5 against history"],
              ["Reviewer tries to restore", "403"]],
  "algorithms": [
    ("Object model", "blob = file bytes; tree = {path: blob id}; commit = {tree, parent, time, author, message, stats}. IDs are "
     "HMAC-SHA256(key, type || content). Each object is stored AES-256-GCM encrypted with the type and ID as associated data."),
    ("Signing and verification", "The commit body is serialised with sorted keys and signed with Ed25519. Verification walks parent "
     "links from HEAD, checking each signature, then decrypts and re-hashes every tree and blob."),
    ("Change-rate anomaly", "z = (changed files now - mean of last 30 incremental commits) / standard deviation (minimum 1). z above 3 "
     "refuses the commit; with fewer than 3 past commits a 30%-of-files rule applies."),
  ],
  "keys_used": "256-bit object key; Ed25519 signing key pair with the public key fingerprint shown on screen.",
  "metrics": lambda r: [
      ["Protected data set", f"{r['dataset_files']} files (including honey files), {kib(r['dataset_bytes'])}"],
      ["First commit", f"{r['first_commit']['new_blobs']} blobs in {r['first_commit']['seconds']} s"],
      ["Daily commit after one edit", f"{r['incremental_commits']['new_blobs']} new blob"],
      ["History verification", f"{r['verify']['commits']} commits, {r['verify']['blob_checks']} blob checks"],
      ["Recovery time (RTO) measured", f"{r['recovery']['rto_seconds']} s, byte-identical: {r['recovery']['byte_identical']}"]],
  "discussion": "Two tamper tests show the layering. An edited commit re-encrypted with the storage key was caught because its keyed "
                "ID no longer matched. A forged commit with a correct ID, made by someone holding the storage key, was still caught "
                "by the Ed25519 signature. Protection therefore depends on the signing key staying separate from the storage key. "
                "The z-score works well once a few commits exist; on day one the share rule takes over.",
  "recommendations": ["Keep the signing key on a separate encrypted volume or hardware token.", "Publish the public-key fingerprint in the ICT policy document.",
                      "Make honey folder names match real departmental naming."],
  "further": ["Branches for staging approved result changes.", "Garbage collection of unreachable objects."],
 },
 {"id": "A08", "folder": "A08-buk-kano-kanoshield", "name": "KanoShield", "port": 5108,
  "title": "KanoShield: A WORM Backup Vault with Four-Eyes Approval and Two-Factor Sign-In for Bayero University Kano",
  "subtitle": "Database-enforced retention locks, dual control of restores and RFC 6238 authenticator codes",
  "place": "Bayero University Kano (BUK), Kano, Kano State",
  "context": "BUK, with its old and new campuses, holds records that matter for decades. The biggest risk to backups is often not an "
             "outsider but a single privileged insider, or a stolen administrator password, that can delete the history or restore "
             "old data over current records.",
  "problems": ["One administrator can delete all backups.", "Restores over live data need no second opinion.", "Passwords alone protect administrator accounts.",
               "Retention periods are not enforced by the system itself."],
  "objectives": ["store backups in a vault that refuses early deletion and any edit;", "require two different administrators for restores and early releases;",
                 "add TOTP two-factor sign-in for administrators;", "lock accounts under brute force;", "replicate the vault to a second campus and offline media;",
                 "evaluate governance controls and recovery."],
  "scope": "The vault is an SQLite file; triggers enforce WORM behaviour inside the database engine.",
  "closest": ["varshney", "lysetskyi", "farouk"],
  "closest_text": "Varshney and Kumar (2026) and Lysetskyi (2025) rely on immutable copies; KanoShield enforces immutability with "
                  "database triggers that even the application cannot bypass. It adds governance that the reviewed work leaves to "
                  "policy documents: dual control and two-factor authentication. Farouk et al. (2024) call for structured risk "
                  "controls in Nigerian universities; four-eyes approval is one.",
  "gap": "Reviewed backup systems treat governance as paperwork. KanoShield makes it a technical control.",
  "fr": ["Seal backups into a WORM vault", "Refuse edits and early deletion", "Request and approve restore/release by two admins", "TOTP sign-in for admins",
         "Brute-force lock with alert", "Replicate vault with SQLite backup API", "Verify every blob"],
  "nfr": ["Admins and auditor roles", "Works with any authenticator app", "Demo code command for defence without a phone"],
  "layers": [["Protected folders"], ["Entropy screening"], ["WORM vault (SQLite triggers + AES-GCM)"], ["Four-eyes approvals", "TOTP sign-in"], ["New campus copy", "Offline USB copy"]],
  "components": [["shield.py", "Vault and triggers, TOTP, users, approvals, verify, replicate, monitoring"], ["app.py", "Flask console and scheduler"],
                 ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Insider deletes backups", "Trigger: retention lock still active"], ["Insider edits a backup", "Trigger: write-once"],
              ["Rogue admin restores old data", "Needs a second, different admin"], ["Stolen admin password", "TOTP code required"],
              ["Password guessing", "Lock after 5 failures, critical alert"], ["Ransomware data", "Entropy screening blocks the backup"]],
  "algorithms": [
    ("WORM triggers", "BEFORE UPDATE of sealed columns: abort. BEFORE DELETE when retain_until is in the future and the backup is not "
     "released: abort. Blobs: no update ever; no delete while the parent backup is locked."),
    ("TOTP (RFC 6238)", "counter = floor(time / 30); mac = HMAC-SHA1(secret, counter); dynamic truncation gives a 6-digit code. One "
     "step of clock drift is accepted either way. Checked against the RFC test vector (T = 59 s gives 287082)."),
    ("Four-eyes workflow", "An admin files a request (restore or early release) with a reason. Any different admin can approve or "
     "reject. Self-approval is refused and raises a critical alert. Approval executes the action and logs both names."),
  ],
  "keys_used": "256-bit AES-GCM vault key; per-admin 160-bit TOTP secrets; scrypt password hashes.",
  "metrics": lambda r: [
      ["Protected data set", f"{r['dataset_files']} files, {kib(r['dataset_bytes'])}"],
      ["Sealing a backup", f"{r['backup']['seconds']} s, locked until {r['backup']['retain_until']}"],
      ["Approvals needed for restore", str(r["recovery"]["approvals"])],
      ["Recovery time after approval", f"{r['recovery']['rto_seconds']} s, byte-identical: {r['recovery']['byte_identical']}"],
      ["Vault verification", f"{r['verify']['blobs_checked']} blobs, {len(r['verify']['problems'])} problems"]],
  "discussion": "Governance controls slow recovery in human terms (a second person must approve) but not in machine terms. That "
                "delay is the point. The WORM triggers protect against the application and its users; someone with direct access "
                "to the database file could still delete the file, which is why replicas include an offline USB copy.",
  "recommendations": ["Give the two admin roles to people in different reporting lines (for example ICT Director and Deputy Registrar).",
                      "Keep one vault copy on a USB drive stored outside the server room.", "Remove the demo 'code' command in production."],
  "further": ["Store vault copies on object storage with legal hold.", "Add a third approver for early release."],
 },
 {"id": "A09", "folder": "A09-uniport-riversrecover", "name": "RiversRecover", "port": 5109,
  "title": "RiversRecover: Continuous Data Protection and Point-in-Time Recovery for the University of Port Harcourt Results Database",
  "subtitle": "Trigger-based change journal, hash-chained encrypted shipping, Senate locks and a database freeze switch",
  "place": "University of Port Harcourt (UNIPORT), Choba, Rivers State",
  "context": "The most sensitive asset at UNIPORT is not a file share but the examination results database. Two threats dominate: "
             "insiders changing grades, and malware that destroys the database file. A nightly backup loses a day of work and says "
             "nothing about who changed what.",
  "problems": ["Nightly backups lose up to a day of results entry.", "Approved results can be edited by anyone with database access.",
               "Grade tampering is found long after it happens.", "There is no way to rebuild the database as it was at a precise moment."],
  "objectives": ["journal every row change with database triggers;", "ship the journal every few seconds as encrypted, hash-chained segments;",
                 "lock Senate-approved results unless an amendment window is opened;", "freeze the database automatically on mass changes;",
                 "rebuild the database at any chosen second (point-in-time recovery);", "evaluate tamper, freeze and recovery."],
  "scope": "SQLite stands in for the production DBMS; the same trigger and journal approach applies to MySQL or PostgreSQL.",
  "closest": ["ilau", "varshney", "kumar"],
  "closest_text": "Varshney and Kumar (2026) locate a verified clean recovery point; RiversRecover can choose any second as that point. "
                  "Kumar et al. (2026) verify backups before restoration; RiversRecover verifies the journal hash chain. Ilau et al. "
                  "(2025) show that recovery strategy changes outcomes; continuous journalling moves the recovery point objective "
                  "from hours to seconds.",
  "gap": "The reviewed work protects files. Database-level protection of examination records, including tamper prevention, is not covered.",
  "fr": ["Triggers journal every insert, update and delete", "Ship encrypted, chained segments every 5 s", "Senate lock on approved results",
         "Freeze on 40 changes per minute or 10 grade-A updates", "Point-in-time recovery to any second", "Verify store; DBA and auditor roles"],
  "nfr": ["No downtime for base snapshots (online backup API)", "Recovery starts a new timeline safely"],
  "layers": [["Results database"], ["Triggers: journal, Senate lock, freeze"], ["Journal shipper (AES-GCM, hash chain)", "Base snapshots"], ["Recovery store + copies"]],
  "components": [["cdp.py", "Schema, triggers, shipping, detection, freeze, base snapshots, verification, PITR"], ["app.py", "Flask console and shipper"],
                 ["main.py / selftest.py", "Commands, simulations, tests"]],
  "threats": [["Insider edits approved grade", "Trigger refuses without amendment window"], ["Burst of grade changes", "Freeze triggers on every table"],
              ["Mass delete", "Refused while frozen"], ["Database file encrypted", "PITR from base + journal"],
              ["Journal segment altered", "Hash chain and GCM fail"], ["Auditor runs recovery", "403"]],
  "algorithms": [
    ("Journal and shipping", "AFTER triggers append (time, table, op, key, row JSON) to a journal. Every 5 s new rows are serialised, "
     "encrypted with AES-256-GCM using the previous segment's SHA-256 as associated data, and recorded with their own hash."),
    ("Point-in-time recovery", "Choose the newest base taken before time T; restore it; drop triggers; replay journal rows after the "
     "base up to T; recreate triggers; mark later shipped rows as an abandoned timeline so they are never replayed."),
    ("Freeze", "Counting result updates and deletes in the last 60 s; 40 or more, or 10 updates to grade A, set control.frozen = 1; "
     "BEFORE triggers on every table then abort writes."),
  ],
  "keys_used": "One 256-bit AES-GCM recovery key for segments and base snapshots.",
  "metrics": lambda r: [
      ["Live database", f"{r['dataset']['students']} students, {r['dataset']['results']} results, {kib(r['dataset']['db_bytes'])}"],
      ["Base snapshot", f"up to journal row {r['base_snapshot']['upto_seq']}, {kib(r['base_snapshot']['bytes'])}"],
      ["Journal rows replayed in recovery", str(r["recovery"]["replayed_rows"])],
      ["Recovery time after ransomware", f"{r['recovery']['rto_seconds']} s, exact match: {r['recovery']['exact_match']}"],
      ["Recovery point objective", r["recovery"]["rpo"]]],
  "discussion": "The first version failed one test, and the failure was instructive: after rolling back, new journal rows reused "
                "sequence numbers from the abandoned timeline, so a later recovery could have replayed tampered rows. Real database "
                "systems solve this with timelines; RiversRecover now does the same. The freeze is blunt: it stops all writes, "
                "including legitimate ones, until a DBA investigates. That suits examination periods better than silent damage.",
  "recommendations": ["Keep the recovery store on a different server from the database.", "Open amendment windows only after Senate minutes are signed.",
                      "Port the triggers to the production DBMS used by the results portal."],
  "further": ["Per-user attribution of changes through database accounts.", "Streaming the journal over TLS to a remote site."],
 },
 {"id": "A10", "folder": "A10-futa-akure-keyvault", "name": "AkureKeyVault", "port": 5110,
  "title": "AkureKeyVault: Split-Key Envelope-Encrypted Backup with Custodian Shares for the Federal University of Technology, Akure",
  "subtitle": "X25519 envelope encryption, Shamir 2-of-3 key shares, key rotation and crypto-shredding",
  "place": "Federal University of Technology Akure (FUTA), Akure, Ondo State",
  "context": "FUTA runs an undergraduate Cyber Security programme, which makes it a fitting place for a design that "
             "asks who should be able to read backups at all. In most systems the backup server holds the key, so whoever steals "
             "or controls the server can read every record.",
  "problems": ["The backup server can decrypt everything it stores.", "One person holds the only key, so their absence blocks recovery.",
               "Old keys are never rotated.", "Erasure requests under the NDPA cannot be met for data already on tape."],
  "objectives": ["encrypt backups with a public key so the server cannot decrypt them;", "split the private key 2-of-3 among the Registrar, Bursar and ICT Director;",
                 "restore only after an unlock ceremony with two shares;", "rotate keys without re-encrypting archives;", "crypto-shred individual backups;",
                 "evaluate key handling and recovery."],
  "scope": "Shares are printed to files for the demonstration; in practice they are handed over on paper.",
  "closest": ["varshney", "dotasara", "kodali"],
  "closest_text": "Dotasara and Sharma (2022) and Kodali and Sangani (2026) encrypt backups but keep the key with the system. "
                  "AkureKeyVault removes the private key from the system entirely. Varshney and Kumar (2026) protect the vault "
                  "operationally; AkureKeyVault protects it cryptographically, with human custody spread over three offices.",
  "gap": "Key custody is the missing piece in the reviewed backup systems.",
  "fr": ["Seal backups with an envelope to the public key", "Split private key 2-of-3 with checksummed shares", "Unlock ceremony with two shares",
         "Key rotation re-wraps data keys", "Crypto-shred a backup", "Three copies with fallback"],
  "nfr": ["Unattended backups", "Ceremonies always logged", "Operator and auditor roles"],
  "layers": [["Protected folders"], ["Screening", "Random data key per backup"], ["Envelope: X25519 + HKDF + AES-GCM"], ["Store", "Obakekere copy", "Offline tape"], ["Shamir shares: Registrar, Bursar, ICT"]],
  "components": [["keyvault.py", "Shamir, envelope, backups, restore, rotation, shredding, monitoring"], ["app.py", "Flask console with unlock ceremony"],
                 ["main.py / selftest.py", "Commands and tests"]],
  "threats": [["Backup server stolen", "Only the public key is there"], ["One custodian coerced", "One share reveals nothing"],
              ["Mistyped share", "Checksum rejects it"], ["Custodian leaves", "Rotation voids old shares"],
              ["Archive copy damaged", "Hash check, fall back to another copy"], ["Erasure request", "Crypto-shred the data key"]],
  "algorithms": [
    ("Shamir 2-of-3", "Treat the 32-byte private key as an integer s below the prime p = 2^521 - 1. Pick a random a and define "
     "f(x) = s + a x mod p. Shares are (1, f(1)), (2, f(2)), (3, f(3)). Any two recover s by Lagrange interpolation at x = 0."),
    ("Envelope encryption", "Per backup: random 256-bit data key; archive sealed with AES-256-GCM. Wrap: ephemeral X25519 key, ECDH "
     "with the recovery public key, HKDF-SHA256 to a wrapping key, AES-GCM over the data key. Store only the wrapped key."),
    ("Rotation and shredding", "Rotation: unlock old key, create new key pair and shares, unwrap and re-wrap every data key. "
     "Shredding: delete one wrapped data key; the archive becomes permanently unreadable on every copy."),
  ],
  "keys_used": "X25519 recovery key pair; per-backup AES-256-GCM data keys; operator passwords hashed with PBKDF2.",
  "metrics": lambda r: [
      ["Protected data set", f"{r['dataset_files']} files, {kib(r['dataset_bytes'])}"],
      ["Sealed backup", f"{kib(r['backup']['stored_bytes'])} in {r['backup']['seconds']} s, key version {r['backup']['key_version']}"],
      ["Custodians needed", str(r["recovery"]["custodians_needed"])],
      ["Recovery time (two shares)", f"{r['recovery']['rto_seconds']} s, byte-identical: {r['recovery']['byte_identical']}"],
      ["Key rotation", f"to version {r['rotation']['new_version']}, {r['rotation']['rewrapped']} data keys re-wrapped"],
      ["Unlock ceremonies recorded", str(r["ceremonies"])]],
  "discussion": "The tests found one bug: pairing a real share with a forged one produced a number too large to be a key, which "
                "crashed instead of failing politely. The system now treats it as a failed ceremony and logs it. Shredding is final "
                "by design, so it must sit behind a policy approval. Because unlocking reconstructs the private key in memory, the "
                "machine used for ceremonies should be trusted and offline when possible.",
  "recommendations": ["Hand shares over in sealed envelopes and delete data/shares_to_print.", "Rotate keys whenever a custodian changes office.",
                      "Record each ceremony in the Registry's minutes."],
  "further": ["3-of-5 shares for larger committees.", "Hardware security keys for share storage."],
 },
]
