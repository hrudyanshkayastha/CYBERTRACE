# Academic Limitations & Future Work
### Critical Evaluation for Third-Year BSc Cybersecurity Defense

In an academic viva voce, examiners award high marks to students who demonstrate mature awareness of their system's technical boundaries. This document outlines the architectural and detection limitations of CYBERTRACE and proposes realistic future enhancements.

---

## 1. Rule-Based Detection vs. Machine Learning

### Current State
CYBERTRACE relies on deterministic, rule-based detection using fixed mathematical thresholds (e.g. $\ge 5$ failed attempts within 300 seconds).

### Limitations
1. **Low-and-Slow Attack Evasions:** An adversary who spaces out password attempts to 1 attempt every 15 minutes will evade the sliding 5-minute brute-force threshold.
2. **Threshold Rigidity:** A threshold tuned for a small 50-user network may cause false positives or false negatives if applied to a corporate 10,000-user network.
3. **Novel Attack Patterns:** Rule-based engines only identify known signatures and patterns that have been pre-programmed. They cannot generalize to zero-day attack tactics.

### Academic Rationale
Despite these limitations, deterministic rules were deliberately chosen for this project because:
- They guarantee **100% explainability** without black-box opacity.
- They have **zero false positives** on strictly defined violation logic.
- They teach the foundational building blocks of security monitoring before introducing complex AI.

---

## 2. Ingestion & Log Telemetry Boundaries

### Current State
CYBERTRACE processes ingested flat files (`.log`, `.csv`, `.json`, `.txt`).

### Limitations
1. **Post-Mortem / Batch Processing:** The system does not currently listen on a live network socket (e.g. Syslog UDP port 514) for continuous streaming ingestion.
2. **Log Tampering / Evasion:** If an attacker gains root privileges and alters or wipes local log files (`/var/log/auth.log`) prior to ingestion, the forensic evidence is lost.
3. **Encrypted Payload Blindness:** The network connection detection inspects IP addresses and port metadata; it cannot inspect encrypted TLS/HTTPS payload content without SSL decryption proxies.

---

## 3. Database & Scalability Boundaries

### Current State
CYBERTRACE uses a local SQLite database (`data/cybertrace.db`).

### Limitations
1. **Concurrent Write Lockouts:** SQLite supports unlimited concurrent readers, but serializes write transactions with a table-level database lock. High-velocity enterprise log streams (thousands of events per second) would encounter database lock contention.
2. **Single-Node Architecture:** SQLite is bounded by local disk space and does not support distributed sharding across cluster nodes.

---

## 4. Proposed Future Work
For postgraduate study or production transition:
1. **Statistical Anomaly Detection:** Implement moving-average baseline calculations (e.g. Z-score anomaly detection) to dynamically flag deviation from normal user behavior without hardcoded thresholds.
2. **Live Syslog Streaming:** Equip the FastAPI server with an asynchronous UDP/TCP listener to ingest syslog events in real time.
3. **SIGMA Rule Compatibility:** Adopt the open-source SIGMA rule standard to allow importing industry-standard detection rules.
4. **MITRE ATT&CK Mapping:** Formally map each detection finding to specific MITRE ATT&CK techniques (e.g. T1110 for Brute Force, T1548 for Abuse Elevation Control Mechanism).
