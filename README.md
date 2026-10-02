# CYBERTRACE
### Security Incident Detection & Investigation System
**Third-Year BSc Cybersecurity Project**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688.svg)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite3-003B57.svg)](https://www.sqlite.org/)
[![Tests](https://img.shields.io/badge/Tests-36%20Passed-success.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. Project Title and Subtitle

**CYBERTRACE: Security Incident Detection & Investigation System**  
*A Rule-Based Defensive Security Event Analysis & Investigation Platform for Undergraduate Cybersecurity Studies.*

---

## 2. Project Overview

**CYBERTRACE** is an educational, locally hosted defensive Security Incident Detection & Investigation System developed as a third-year BSc Cybersecurity project. It is specifically tailored for students and examiners who need a clear, professional, and accessible demonstration of core Security Operations Center (SOC) workflows.

In enterprise cybersecurity, analysts ingest thousands of logs every hour from firewalls, operating systems, authentication servers, and applications. Junior analysts face three core obstacles:
1. **Log Format Fragmentation:** Disparate log formats (Syslog, CSV, JSON, plaintext) obscure security visibility.
2. **Alert Fatigue:** Disjointed single-event alerts hide the larger coordinated attack sequence.
3. **Black-Box Complexity:** Complex proprietary systems make it difficult for beginners to explain *why* an alert occurred during an academic viva defense.

CYBERTRACE solves these challenges by providing a transparent, 100% deterministic, rule-based pipeline. It processes multi-format logs, normalizes them into standard event structures, applies transparent detection logic, correlates related events into unified multi-stage incidents, computes an explainable additive risk score, extracts forensic Indicators of Compromise (IOCs), and presents the findings in a dark-mode SOC Analyst Web Dashboard with executive report exports.

---

## 3. Academic & Security Disclaimer

> [!IMPORTANT]
> **SOC Operational Notice & Academic Disclaimer:**  
> This system performs rule-based security event analysis. Detection results indicate potentially suspicious activity and do not prove malicious intent.

- **Defensive Scope:** CYBERTRACE is strictly a defensive analysis platform. It contains no offensive exploitation capabilities, network attack tooling, or malware binaries.
- **Synthetic Datasets:** All log files supplied in the `samples/` directory are synthetic test records created exclusively for academic demonstration and laboratory testing.
- **Educational Objective:** Designed to illustrate defensive security concepts clearly and defensibly during university viva examinations.

---

## 4. Core Architecture Pipeline

CYBERTRACE processes security data through a sequential, deterministic six-stage defensive pipeline:

```text
+-----------------------------------------------------------------------+
|                          1. RAW LOG INGESTION                         |
|     Heterogeneous logs (.log, .txt, .csv, .json) up to 10 MB limit    |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                       2. PARSER & NORMALIZATION                       |
|   Standardizes timestamps to ISO-8601, validates IPs, maps event types|
|          Resilient to corrupt lines with zero-crash fallbacks         |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                     3. RULE-BASED DETECTION ENGINE                    |
|   5 Deterministic Security Rules (Brute-Force, PrivEsc, Lockout, etc.)|
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                       4. EVENT CORRELATION ENGINE                     |
|  Groups findings by Source IP / User within sliding time windows (30m)|
|           Synthesizes chronological multi-stage attack chains         |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                     5. EXPLAINABLE RISK SCORING                       |
|      Additive points (+20, +25, +15...) capped at 100 with itemized   |
|         breakdown factors: LOW, MEDIUM, HIGH, and CRITICAL            |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                     6. SOC DASHBOARD & REPORTING                      |
|   Dark SOC Dashboard, Modal Investigation, JSON Export, HTML Reports  |
+-----------------------------------------------------------------------+
```

---

## 5. Key Features

- **Multi-Format Ingestion:** Ingests plaintext Syslog, standard bracketed logs, CSV spreadsheets, and structured JSON arrays up to a 10 MB safety threshold.
- **Corrupted-Input Resilience:** Gracefully processes malformed rows, non-standard timestamps, and corrupted lines without crashing the server.
- **Standardized Schema (`NormalizedEvent`):** Uniformly formats timestamps into ISO-8601, canonicalizes event types, and validates source/destination IPs.
- **5 Deterministic Detection Rules:** Transparent, threshold-based rules that can be explained in plain English to examiners.
- **Multi-Stage Attack Correlation:** Groups related security findings by entity (IP/username) into cohesive incidents, mapping the progression from initial access to execution.
- **Visual Attack Chains:** Generates human-readable progression diagrams (e.g., `Brute Force → Successful Authentication → Privilege Escalation → Suspicious Network Connection → File Artifact Creation`).
- **Additive & Explainable Risk Scoring:** Computes risk scores from 0 to 100 with an exact mathematical breakdown of every contributing factor.
- **Automated IOC Extraction:** Identifies IPv4 addresses, domains, URLs, usernames, and file paths, classifying RFC 1918 private vs. public routable IPs.
- **Single-Page Dark SOC Web Dashboard:** Nine dedicated interface views designed with modern security operations aesthetics.
- **Incident Investigation Modal:** Interactive modal displaying chronological event timelines, risk factors, and recommended SOC containment actions.
- **Dual-Format Reporting:** Generates downloadable machine-readable JSON reports and self-contained, printable HTML executive reports with print-friendly CSS.
- **Zero-Setup Embedded Database:** Built on Python's built-in `sqlite3` relational database (`data/cybertrace.db`) with zero external database dependencies.

---

## 6. Security Log Analysis

The ingestion subsystem (`app/parser/log_parser.py` and `app/parser/normalizer.py`) converts raw, heterogeneous records into structured, queryable data:

### Supported Formats
1. **Bracketed / Syslog Format (`.log`, `.txt`):**
   `2026-10-01 10:31:02 [WARN] [192.168.1.20] [admin] LOGIN_FAILED: Failed SSH login`
2. **Comma-Separated Values (`.csv`):**
   Comma-delimited logs with automatic header mapping (`timestamp`, `source_ip`, `username`, `event_type`, `message`).
3. **Structured JSON Arrays (`.json`):**
   JSON object lists containing structured event attributes and optional `extra_data` dictionaries.
4. **Unstructured Fallback Logs:**
   Regex-based token extraction parses arbitrary log formats while ensuring no server crashes.

### Canonical Normalization Schema
Each raw entry is transformed into a `NormalizedEvent` schema:
- **Timestamp:** ISO-8601 UTC representation (`YYYY-MM-DDTHH:MM:SS`).
- **Source IP:** Validated IPv4 address string (or `null` if unrecorded).
- **Username:** Identified user account string (or `null`).
- **Canonical Event Types:**
  - `LOGIN_FAILED`
  - `LOGIN_SUCCESS`
  - `ACCOUNT_LOCKED`
  - `PRIVILEGE_ESCALATION`
  - `NETWORK_CONNECTION`
  - `PROCESS_EXECUTED`
  - `FILE_CREATED`
  - `LOGOUT`
  - `SECURITY_ALERT`
  - `OTHER`
- **Severity Classification:** `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- **Message & Raw Text:** Normalized message text and original unparsed log string preserved for forensic audit.

---

## 7. Rule-Based Detection

CYBERTRACE deliberately avoids black-box machine learning models in favor of five deterministic, explainable security detection rules (`app/detection/rules.py`):

| Rule Identifier | Rule Name | Detection Criteria | Default Threshold | Severity |
|---|---|---|---|---|
| `RULE_001_BRUTE_FORCE` | Brute-Force Authentication Attempt | Flags rapid repeated authentication failures from the same source. | $\ge 5$ failures within 300s (5 min) | `HIGH` |
| `RULE_002_LOGIN_AFTER_FAILURES` | Successful Login Following Failures | Detects successful authentication immediately preceded by multiple failures. | $\ge 3$ failures before a success in 600s | `HIGH` |
| `RULE_003_ACCOUNT_LOCKOUT` | Account Lockout Event | Identifies authentication failures culminating in an account lockout event. | $\ge 3$ failures before lockout in 600s | `MEDIUM` |
| `RULE_004_PRIVILEGE_ESCALATION` | Privilege Escalation Activity | Identifies unauthorized elevation to root/administrator rights (`sudo`, `su root`, root shell spawning). | Immediate on event match | `HIGH` |
| `RULE_005_EXTERNAL_CONNECTION` | Suspicious External Connection | Detects outbound communication directed toward external, public IP addresses (non-RFC 1918). | Immediate on external IP match | `MEDIUM` |

*All thresholds and time windows are centralized in `app/config.py` and can be customized or explained during viva presentations.*

---

## 8. Event Correlation

Isolated alerts often fail to reveal coordinated attacks. The Event Correlation Engine (`app/correlation/engine.py`) synthesizes related events into unified security incidents:

1. **Entity Grouping:** Groups rule matches and related events by primary entity key (Source IP address and/or Username).
2. **Temporal Windowing:** Correlates chronological events within a configurable 30-minute sliding window (`CORRELATION_WINDOW_SECONDS = 1800`).
3. **Attack Chain Synthesis:** Arranges event types in chronological sequence to construct a multi-stage attack pattern:
   `Brute Force → Successful Authentication → Privilege Escalation → Suspicious Network Connection → File Artifact Creation`
4. **Contextual Classification:** Automatically assigns an incident title and incident type:
   - `ACCOUNT_COMPROMISE` (Brute force + Privilege escalation)
   - `CREDENTIAL_COMPROMISE` (Brute force + Successful authentication)
   - `BRUTE_FORCE` (Isolated brute force)
   - `PRIVILEGE_ESCALATION` (Isolated privilege escalation)
   - `ACCOUNT_LOCKOUT` (Excessive failures resulting in lockout)
   - `NETWORK_ANOMALY` (Suspicious outbound external communication)
   - `SUSPICIOUS_ACTIVITY` (General correlated anomalous actions)

---

## 9. Risk Scoring

The Risk Scoring Engine (`app/risk/scorer.py`) uses a transparent, additive scoring methodology that produces a final score between 0 and 100:

### Additive Risk Weights (`app/config.py`)
- **`+20` points:** Multiple failed login attempts / brute-force burst (`RULE_001_BRUTE_FORCE`).
- **`+20` points:** Successful login following multiple failures (`RULE_002_LOGIN_AFTER_FAILURES`).
- **`+10` points:** Account lockout event triggered (`RULE_003_ACCOUNT_LOCKOUT`).
- **`+25` points:** Privilege escalation activity detected (`RULE_004_PRIVILEGE_ESCALATION`).
- **`+20` points:** Outbound connection to an external IP address (`RULE_005_EXTERNAL_CONNECTION`).
- **`+15` points:** Multiple correlated attack indicators originating from the same entity source ($\ge 2$ rules or $\ge 3$ distinct event types).

### Score Normalization & Categorization
The raw points are summed and capped at a maximum of `100`. The resulting score maps directly to one of four severity bands:

| Risk Score Range | Severity Level | Badge Color | Interpretation |
|---|---|---|---|
| **80 – 100** | `CRITICAL` | Red (`#ef4444`) | Severe multi-stage compromise requiring immediate incident containment. |
| **60 – 79** | `HIGH` | Orange (`#f97316`) | Significant suspicious activity indicating potential unauthorized access. |
| **30 – 59** | `MEDIUM` | Yellow (`#eab308`) | Anomalous activity or policy violations warranting analyst investigation. |
| **0 – 29** | `LOW` | Green (`#10b981`) | Routine baseline activity or isolated low-severity anomalies. |

Every scored incident includes an itemized breakdown of contributing factors and defensive recommendations.

---

## 10. IOC Extraction

The Indicator of Compromise extraction module (`app/ioc/extractor.py`) automatically discovers, de-duplicates, and evaluates forensic artifacts from normalized events:

- **IPv4 Addresses:** Differentiates internal RFC 1918 private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`) from public routable IP addresses. Outbound external IPs are classified as potentially suspicious.
- **Domain Names:** Identifies network domain names (e.g., `suspicious-example.local`) and flags domains containing suspicious keywords (`c2`, `payload`, `malware`).
- **Web URLs:** Identifies HTTP and HTTPS web endpoints.
- **Usernames:** Extracts user identities, flagging privileged accounts (`root`, `admin`, `administrator`) involved in anomalous operations.
- **File System Paths:** Extracts referenced Linux and Windows file paths, highlighting sensitive directories and staged payloads (e.g., `/tmp/stage_payload.sh`, `/etc/shadow`, `powershell.exe`).
- **Assessment Flagging:** Each IOC is cataloged with an assessment status (`Observed` vs. `Suspicious`), operational context, and first-seen timestamp.

---

## 11. Incident Investigation

CYBERTRACE provides a structured investigation workflow designed for tier-1 and tier-2 SOC analysts:

1. **Detection & Triage:** Analysts review incoming incidents sorted by risk score.
2. **Deep-Dive Investigation Modal:** Clicking **Investigate Incident Details** opens an investigation window displaying:
   - **Incident Identity:** Incident Code (`INC-001`), Title, and Severity Badge.
   - **Entity Context:** Attacking Source IP, targeted user account, and active duration.
   - **Attack Progression:** Visual progression sequence.
   - **Triggered Rules:** Exact rule IDs triggered.
   - **Mathematical Risk Breakdown:** Itemized point contributions explaining how the score was calculated.
   - **Containment Recommendations:** Prescriptive, step-by-step SOC response actions (e.g., *“Review sudoers logs and active root sessions”*, *“Inspect perimeter firewall for outbound C2 channels”*).
   - **Chronological Incident Timeline:** Filtered table listing only the normalized events tied to that specific incident.

---

## 12. Dashboard

The frontend interface (`app/ui/templates/index.html`) is a dark-mode Single-Page Application (SPA) offering nine modular sections:

1. **Dashboard:** High-level metrics (Total Events, Suspicious Events, Total Incidents, Critical Incidents, Unique IPs, Max Risk Score), Active Run Target indicator, quick ingest trigger, and a summary card of recent incidents.
2. **Upload Logs:** File dropzone supporting drag-and-drop or file selection (with a 10 MB limit) plus one-click sample demonstration scenario buttons.
3. **Normalized Events:** Comprehensive table of all standardized records with search filtering, event-type filtering, and severity badges.
4. **Incidents:** Complete card-based incident directory displaying risk scores, attack patterns, entity information, and investigation triggers.
5. **IOC Findings:** Structured artifact catalog displaying extracted IPs, domains, URLs, users, and file paths with suspicion tags.
6. **Timeline:** Global chronological sequence of all parsed log events across the entire dataset.
7. **Risk Assessment:** Dedicated view explaining system-wide risk posture, risk score formulas, and the defensive risk rubric.
8. **Reports:** Export panel providing one-click JSON report downloads and a direct link to view the printable Executive HTML Report.
9. **About & Viva Guide:** Built-in viva reference guide outlining architecture, viva talking points, and pipeline explanations for examiners.

---

## 13. Incident Timeline

Reconstructing the order of events is critical during post-incident investigations. CYBERTRACE provides chronological timeline views:
- **Global Ingestion Timeline:** Displays every normalized event in sequential order based on normalized ISO-8601 timestamps.
- **Incident-Specific Timeline:** Filters and displays only the events contributing to a specific incident within the Investigation Modal and Executive Report.
- **Forensic Continuity:** Preserves exact original timestamps and event order to clearly demonstrate attacker progression from reconnaissance to compromise.

---

## 14. Report Generation

The reporting module (`app/reporting/generator.py`) generates two distinct report formats for technical audit and executive briefings:

### 1. Structured JSON Report (`/api/runs/{id}/report/json`)
- Fully structured machine-readable export containing:
  - Run metadata and target filename.
  - Event and incident summary statistics.
  - Full incident records with risk scores, factors, and recommendations.
  - Complete list of observed and suspicious IOCs.
  - A 50-event sample audit trail.
  - Academic methodology and limitations statement.

### 2. Standalone Executive HTML Report (`/api/runs/{id}/report/html`)
- Self-contained, styled HTML investigation report designed for stakeholders and examiners.
- Features executive KPI summary cards, incident attack chains, mathematical risk breakdowns, and IOC tables.
- **Print & PDF Optimized:** Includes a dedicated `@media print` CSS stylesheet that converts the dark-mode layout into a clean, black-and-white printable document when using browser print (`Ctrl+P` / **Print / Save PDF**).
- **Guaranteed Consistency:** Uses the identical canonical incident data, risk score, severity, and factors shown in the dashboard.

---

## 15. Technology Stack

CYBERTRACE is built entirely with lightweight, beginner-friendly technologies with zero external database servers or cloud dependencies:

| Component | Technology | Purpose |
|---|---|---|
| **Language** | Python 3.11+ (tested on Python 3.12.9) | Core programming language for all backend components. |
| **Web Framework** | FastAPI (v0.100+) & Starlette | High-performance asynchronous REST API framework. |
| **ASGI Server** | Uvicorn (v0.22+) | Lightweight ASGI web server for hosting the application. |
| **Data Validation** | Pydantic v2 | Robust schema definitions and input validation. |
| **Templating** | Jinja2 (v3.1+) | HTML template rendering for the dashboard and reports. |
| **Database** | SQLite3 (`sqlite3`) | Built-in Python relational database for persistent storage. |
| **Frontend** | Vanilla HTML5, CSS3, Vanilla JS | Zero-dependency responsive dark-mode SOC user interface. |
| **Test Suite** | pytest (v7.4+) | Automated unit and integration testing (36 tests). |

---

## 16. Project Structure

```text
cybertrace/
│
├── app/                              # Application source code
│   ├── __init__.py
│   ├── config.py                     # Configurable thresholds, weights, and paths
│   ├── main.py                       # FastAPI application setup and lifespan
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py                 # REST API endpoints (upload, runs, incidents, reports)
│   ├── correlation/
│   │   ├── __init__.py
│   │   └── engine.py                 # Multi-stage incident correlation and attack chain builder
│   ├── database/
│   │   ├── __init__.py
│   │   └── db.py                     # SQLite schema, tables, and CRUD operations
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── engine.py                 # Detection engine coordinator
│   │   └── rules.py                  # 5 Deterministic security detection rules
│   ├── ioc/
│   │   ├── __init__.py
│   │   └── extractor.py              # IOC extraction and RFC 1918 private IP evaluation
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py                # Pydantic v2 models and API envelopes
│   ├── parser/
│   │   ├── __init__.py
│   │   ├── log_parser.py             # Multi-format log parser (.log, .txt, .csv, .json)
│   │   └── normalizer.py             # ISO-8601 timestamp normalizer and event classifier
│   ├── reporting/
│   │   ├── __init__.py
│   │   └── generator.py              # JSON and printable Executive HTML report generator
│   ├── risk/
│   │   ├── __init__.py
│   │   └── scorer.py                 # Additive explainable risk scoring engine
│   └── ui/                           # Frontend assets
│       ├── static/
│       │   ├── css/styles.css        # Dark-mode SOC styling and print CSS
│       │   └── js/app.js             # Vanilla JS state management and API communication
│       └── templates/
│           └── index.html            # Single-page dashboard HTML template
│
├── data/                             # SQLite persistent database storage
│   └── cybertrace.db                 # SQLite database file (created on launch)
│
├── reports/                          # Generated reports and documentation artifacts
│   └── screenshots/                  # Verification walkthrough screenshots (14 screens)
│
├── samples/                          # 7 Synthetic demonstration log datasets
│   ├── sample_suspicious_incident.log# Complete multi-stage attack log
│   ├── sample_clean.log              # Baseline administrative activity (zero incidents)
│   ├── sample_malformed.log          # Corrupted and irregular log lines
│   ├── sample_bruteforce.log         # High-frequency failed authentication attempts
│   ├── sample_privilege_escalation.log# Sudo privilege elevation activity
│   ├── sample_web_attacks.csv        # CSV-formatted web brute-force and lockout
│   └── sample_cloud_events.json      # JSON array-formatted audit events
│
├── tests/                            # Automated test suite (36 tests)
│   ├── __init__.py
│   ├── test_api.py                   # API routes and upload handling
│   ├── test_correlation.py           # Attack chain correlation tests
│   ├── test_database.py              # SQLite persistence tests
│   ├── test_detection.py             # Rule matching verification
│   ├── test_ioc.py                   # IOC regex and RFC 1918 tests
│   ├── test_normalizer.py            # Normalization and timestamp tests
│   ├── test_parser.py                # Multi-format parser resilience tests
│   ├── test_reporting.py             # JSON and HTML report tests
│   └── test_risk_scorer.py           # Risk calculation and capping tests
│
├── ARCHITECTURE.md                   # Detailed architecture reference
├── API_DOCUMENTATION.md              # REST API endpoint reference
├── DOCUMENTATION.md                  # Comprehensive technical system documentation
├── LIMITATIONS.md                    # Engineering boundaries and constraints
├── VIVA_QUESTIONS.md                 # 20 Academic viva questions with beginner answers
├── requirements.txt                  # Python package dependencies
├── run.py                            # Standalone server launcher script with ASCII banner
└── README.md                         # Project documentation and guide
```

---

## 17. Installation Requirements

Before running CYBERTRACE, ensure you have:
- **Python 3.11 or newer** installed (tested and verified on Python 3.12).
- **Git** installed on your system.
- **Operating System:** Compatible with Windows 10/11, macOS, and Linux.
- **Modern Web Browser:** Google Chrome, Mozilla Firefox, Microsoft Edge, or Safari.

---

## 18. Clone Instructions

Clone the project repository to your local computer:

```bash
git clone https://github.com/hrudyanshkayastha/CYBERTRACE.git
cd CYBERTRACE
```

---

## 19. Virtual Environment Setup

Creating an isolated Python virtual environment is recommended:

### On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### On Windows (Command Prompt):
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

### On macOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 20. Dependency Installation

Install all required packages using `pip`:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

*Requirements include: `fastapi`, `uvicorn`, `pydantic`, `jinja2`, and `pytest`.*

---

## 21. Running the Application

### Option A: Using the Launcher Script (Recommended)
```bash
python run.py
```
This prints the project ASCII banner, initializes the SQLite database, and starts the server.

### Option B: Using Uvicorn Directly
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Once started, open your web browser and navigate to:
```text
http://127.0.0.1:8000
```

---

## 22. Demonstration Using `sample_suspicious_incident.log`

To demonstrate the full incident detection and investigation workflow:

1. Open `http://127.0.0.1:8000` in your web browser.
2. In the left sidebar, click **Upload Logs**.
3. Under **Built-in Synthetic Demonstration Scenarios**, find `sample_suspicious_incident.log` and click **Analyze Sample**.
4. The system processes eight log entries depicting a multi-stage attack:
   - 4 failed SSH login attempts from `192.168.1.20` for user `admin`.
   - 1 successful login for `admin` from the same IP.
   - 1 unauthorized sudo privilege escalation command.
   - 1 outbound connection to external IP `203.0.113.50` (`suspicious-example.local`).
   - 1 staged file artifact created at `/tmp/stage_payload.sh`.
5. Observe the results across dashboard views:
   - **Dashboard:** Displays Total Events (8), Suspicious Events (7), Total Incidents (1), Critical Incidents (1), and Max Risk Score (80 / 100).
   - **Incidents:** Displays `INC-001: Potential Account Takeover & Privilege Escalation` flagged as **CRITICAL (80/100)**.
   - **Modal Investigation:** Clicking **Investigate Incident Details** displays the attack chain, the 5 contributing risk factors, and recommended containment actions.
   - **IOC Findings:** Lists public IP `203.0.113.50`, domain `suspicious-example.local`, and file path `/tmp/stage_payload.sh`.
   - **Reports:** Click **Reports** &rarr; **View / Print Executive HTML Report** to view the publication-ready investigation report.

---

## 23. Clean Sample Demonstration (`sample_clean.log`)

To evaluate baseline administrative activity:

1. Navigate to **Upload Logs**.
2. Click **Analyze Sample** on `sample_clean.log`.
3. The sample contains six legitimate administrative activities by users `sarah` and `david`.
4. **Result:** Clean baseline produced zero detected incidents.
   - Total Events: 6
   - Suspicious Events: 0
   - Correlated Incidents: 0
   - Max Risk Score: 0 / 100 (`LOW`)
5. This synthetic baseline test demonstrates that the configured detection rules did not trigger on the supplied clean sample.

---

## 24. Malformed Sample Demonstration (`sample_malformed.log`)

To demonstrate parser robustness against corrupted inputs:

1. Navigate to **Upload Logs**.
2. Click **Analyze Sample** on `sample_malformed.log`.
3. The file contains missing timestamps, corrupted IP strings (`999.999.999.999`), broken JSON fragments, and unformatted text.
4. **Result:**
   - The application parses all lines without throwing an unhandled exception or crashing the server.
   - Valid events embedded within corrupt data are extracted safely, while unparseable lines receive default fallback categorizations (`OTHER`).

---

## 25. Example Incident Breakdown

Here is the exact structure of `INC-001` generated from `sample_suspicious_incident.log`:

```yaml
Incident Code: INC-001
Title: Potential Account Takeover & Privilege Escalation
Incident Type: ACCOUNT_COMPROMISE
Severity: CRITICAL
Risk Score: 80 / 100
Entity:
  Source IP: 192.168.1.20
  Username: admin
Time Window: 2026-10-01 10:31:02 UTC to 2026-10-01 10:31:25 UTC
Related Events: 8

Attack Progression Chain:
  Brute Force → Successful Authentication → Privilege Escalation → Suspicious Network Connection → File Artifact Creation

Triggered Security Rules:
  - RULE_001_BRUTE_FORCE (Brute-Force Authentication Attempt)
  - RULE_002_LOGIN_AFTER_FAILURES (Successful Login Following Repeated Failures)
  - RULE_004_PRIVILEGE_ESCALATION (Privilege Escalation Activity)
  - RULE_005_EXTERNAL_CONNECTION (Suspicious External Network Connection)

Risk Score Breakdown:
  +20 : Successful login following multiple authentication failures
  +25 : Privilege escalation activity detected (sudo / administrator rights)
  +20 : Suspicious outbound connection to external IP address
  +15 : Multiple correlated attack indicators originating from same source
  Total: 80 / 100 (CRITICAL)

Defensive Containment Recommendations:
  1. Immediately verify whether user authentication was authorized or credential stuffing.
  2. Review sudoers logs and active root sessions to confirm authorized administrative change.
  3. Inspect perimeter firewall and DNS logs for outbound C2 or data staging channels.
  4. Escalate to Tier-2 SOC analyst for comprehensive incident containment.
```

---

## 26. Testing

CYBERTRACE includes a comprehensive automated test suite implemented with `pytest`:

```bash
python -m pytest tests -v
```

### Test Coverage Summary (36 Tests):
- `tests/test_api.py`: Validates file upload validation, sample ingestion, health checks, error status codes, and static asset routes (8 tests).
- `tests/test_parser.py`: Tests bracketed logs, Syslog, CSV, JSON arrays, empty files, and malformed line resilience (6 tests).
- `tests/test_normalizer.py`: Tests timestamp formatting, canonical event classification, and IP validation (5 tests).
- `tests/test_detection.py`: Tests the 5 deterministic security rules and the detection aggregator (6 tests).
- `tests/test_correlation.py`: Verifies grouping by entity, sliding windows, and attack chain synthesis (2 tests).
- `tests/test_risk_scorer.py`: Tests additive scoring, factor explanations, score capping at 100, and boundary levels (4 tests).
- `tests/test_ioc.py`: Tests regex extraction and RFC 1918 private vs. public IP classification (2 tests).
- `tests/test_database.py`: Validates SQLite CRUD operations, relational links, and cascading deletes (1 test).
- `tests/test_reporting.py`: Validates structured JSON generation and Executive HTML rendering with disclaimer checks (2 tests).

*All 36 tests execute and pass in under 1 second.*

---

## 27. System Limitations

In accordance with academic rigor, the following design boundaries should be noted:
1. **Deterministic Rule Constraints:** Rule-based detection relies on strict threshold conditions (e.g., 5 failures in 300 seconds). Stealthy, "low-and-slow" attacks spaced across days will not cross these threshold windows.
2. **Offline Log Processing:** CYBERTRACE operates on uploaded log files rather than listening on live network tap interfaces or live raw socket packet sniffers.
3. **Synthetic Demonstration Data:** The sample datasets are synthetically crafted for academic scenarios; they do not represent live production corporate telemetry.
4. **Log Fidelity Dependency:** Detection accuracy depends entirely on the presence and accuracy of log fields (timestamps, IPs, and messages).
5. **No Deep Packet Inspection:** The system evaluates log metadata rather than reassembling and analyzing encrypted network payloads.
6. **Local Single-Instance Storage:** Uses an embedded SQLite database designed for single-node academic evaluation rather than clustered enterprise data lakes.

---

## 28. Future Scope

Potential enhancements for postgraduate research or extended project phases:
- **Streaming Log Ingestion:** Implementing a real-time Syslog UDP/TCP listener (port 514) to process live log streams.
- **Sigma Rule Standard:** Supporting the industry-standard Sigma rule format for generic, vendor-agnostic rule definitions.
- **MITRE ATT&CK Mapping:** Explicitly tagging correlated attack stages with corresponding MITRE ATT&CK enterprise technique IDs (e.g., T1110 for Brute Force, T1548 for Abuse Elevation Control Mechanism).
- **Automated Incident Response Webhooks:** Dispatching automated containment notifications via email, Slack, or webhook endpoints.
- **Multi-Tenant Role-Based Access Control (RBAC):** Providing separate Analyst, Lead, and Auditor login portals.

---

## 29. Viva / Demonstration Flow

A structured 5-minute walkthrough guide for your project viva or examiner evaluation:

1. **Introduction (1 min):**
   - Introduce CYBERTRACE as a rule-based defensive incident detection system designed to model end-to-end SOC analysis for undergraduate study.
   - Emphasize the educational design: transparent, deterministic, explainable, and zero-crash.
2. **Architecture Explanation (1 min):**
   - Walk through the six-stage pipeline: Log Ingestion &rarr; Normalization &rarr; Rule Detection &rarr; Event Correlation &rarr; Risk Scoring &rarr; Reporting.
   - Explain why rule-based detection was chosen over machine learning (explainability, deterministic auditing, no black-box decisions).
3. **Live Suspicious Incident Walkthrough (1.5 min):**
   - Open `http://127.0.0.1:8000`.
   - Go to **Upload Logs** and click **Analyze Sample** on `sample_suspicious_incident.log`.
   - Show the **Dashboard** metrics updating to 1 Incident with an **80/100 CRITICAL** risk score.
   - Open **Incidents** and click **Investigate Incident Details**.
   - Show the examiner the **Attack Pattern Chain** and explain how the **Risk Score Breakdown** mathematically reached 80 points.
   - Show the **Chronological Incident Timeline** and **Recommended Defensive Actions**.
4. **Forensic Artifacts & Reports (1 min):**
   - Open **IOC Findings** and show how the system automatically distinguished internal IPs (`192.168.1.20`) from public IPs (`203.0.113.50`).
   - Open **Reports** and click **View / Print Executive HTML Report**. Demonstrate the print-ready CSS formatting.
5. **Robustness & Baseline Verification (30 sec):**
   - Analyze `sample_clean.log` to demonstrate that the clean baseline produced zero detected incidents on the supplied clean sample.
   - Analyze `sample_malformed.log` to demonstrate parser resilience against corrupted rows.
   - Conclude by reciting the standard SOC disclaimer: *"Detection results indicate potentially suspicious activity and do not prove malicious intent."*

---

## 30. License

This project is released under the **MIT License**. It is freely available for educational, academic, and non-commercial research use.

```text
MIT License

Copyright (c) 2026 CYBERTRACE Project Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

*CYBERTRACE &bull; Third-Year BSc Cybersecurity Project &bull; Built for Transparent Defensive Security Education*
