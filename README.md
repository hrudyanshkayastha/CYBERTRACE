# CYBERTRACE
### Security Incident Detection & Investigation System
**Third-Year BSc Cybersecurity Project**

---

## 1. What is CYBERTRACE?
**CYBERTRACE** is an educational, locally hosted Security Operations Center (SOC) incident detection and investigation platform designed specifically for students and examiners in cybersecurity. 

It demonstrates the full end-to-end defensive workflow of a SOC analyst: ingesting raw security logs, normalizing heterogeneous log records into canonical events, applying deterministic detection rules, correlating multi-stage attack chains across time, scoring incident risk transparently, and producing executive-ready investigation reports.

---

## 2. Problem Statement
Modern enterprise environments generate thousands of security logs daily from firewalls, authentication servers, web applications, and endpoints. Junior security analysts face three major challenges:
1. **Format Fragmentation:** Logs arrive in diverse structures (Syslog, CSV, JSON, Apache/SSH text).
2. **Alert Fatigue:** Isolated alerts obscure the larger context of coordinated attacks.
3. **Black-Box Confusion:** Opaque machine learning models cannot easily explain *why* an alert was generated during security audits or academic defense.

CYBERTRACE solves this by providing a clean, deterministic, rule-based correlation pipeline where every detection, attack chain stage, and risk score is 100% explainable in beginner-friendly terms.

---

## 3. Project Objectives
- Ingest multiple log formats (`.log`, `.txt`, `.csv`, `.json`) with zero-crash resilience against corrupt data.
- Normalize heterogeneous log fields into a unified schema (`NormalizedEvent`).
- Extract forensic Indicators of Compromise (IPv4, Domains, URLs, Usernames, File Paths).
- Detect suspicious behaviors using transparent deterministic security rules.
- Correlate isolated events into contextual **Incidents** representing realistic attack progressions.
- Compute an additive, explainable **Risk Score** (0–100) with detailed contributing factors.
- Render a dark-mode SOC Analyst Web Dashboard.
- Export standalone JSON and styled executive HTML investigation reports with academic disclaimers.

---

## 4. Pipeline Architecture
```
+-----------------------------------------------------------------------+
|                             RAW LOG FILE                              |
|                    (.log, .txt, .csv, .json)                          |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                           1. LOG PARSER                               |
|        Safe multi-format reader with regex & schema extraction        |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                       2. EVENT NORMALIZATION                          |
|    Standardizes timestamp (ISO-8601), IPs, users, and event types     |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                     3. SECURITY RULE ENGINE                           |
|       Brute-Force, Auth Success Anomalies, Sudo PrivEsc, NetConn      |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                      4. EVENT CORRELATION                             |
|       Groups by Source IP / User within sliding time window           |
|            Synthesizes multi-stage attack pattern chains              |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                        5. RISK SCORING                                |
|        Additive points (+20, +25, +15...) capped at 100               |
|            Categorizes risk: LOW, MEDIUM, HIGH, CRITICAL              |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                    6. SOC DASHBOARD & REPORTING                       |
|         Interactive dark-mode web UI, JSON export, HTML reports       |
+-----------------------------------------------------------------------+
```

---

## 5. Technology Stack
- **Backend Language:** Python 3.11+ (tested on Python 3.12)
- **Web Framework:** FastAPI & Starlette
- **ASGI Server:** Uvicorn
- **Database:** SQLite (built-in Python `sqlite3`, transparent schema)
- **Frontend:** Vanilla HTML5, CSS3 (SOC Dark Theme), Vanilla JavaScript
- **Validation:** Pydantic v2
- **Testing:** pytest (35 automated tests, 100% pass rate)

---

## 6. Installation & Quickstart

### Prerequisites
- Python 3.11 or newer installed on your system.

### Step 1: Navigate to Project Directory
```powershell
cd C:\Users\ADMIN\.gemini\antigravity\scratch\cybertrace
```

### Step 2: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 3: Run Automated Test Suite
```powershell
python -m pytest tests -v
```
All 35 tests will run and pass in under 1 second.

### Step 4: Launch the CyberTrace Application
```powershell
python run.py
```
Or run directly with uvicorn:
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Step 5: Open the SOC Web Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 7. Step-by-Step Demonstration Procedure (Viva Walkthrough)

To demonstrate CYBERTRACE to an examiner or supervisor:

1. **Open the Dashboard:** Go to `http://127.0.0.1:8000`. Notice the clean dark SOC metrics layout.
2. **Navigate to Upload Logs:** Click **Upload Logs** on the sidebar.
3. **Execute 1-Click Analysis:** Under **Built-in Synthetic Demonstration Scenarios**, click **Analyze Sample** on `sample_suspicious_incident.log`.
4. **Inspect Normalized Events:** Click **Normalized Events** to observe how the 8 raw log entries were standardized with ISO timestamps, IPs, and canonical event types.
5. **View Correlated Incidents:** Click **Incidents**. Observe `INC-001: Potential Account Takeover & Privilege Escalation` flagged with **HIGH/CRITICAL Risk**.
6. **Investigate Attack Chain:** Click **Investigate Incident Details**. The modal displays:
   - Attack sequence: `Brute Force → Successful Authentication → Privilege Escalation → Suspicious Network Connection → File Artifact Creation`
   - Detailed Risk Scoring breakdown (`+20`, `+20`, `+25`, `+20`, `+15`).
   - Actionable SOC containment recommendations.
   - Chronological event timeline.
7. **Examine IOC Findings:** Click **IOC Findings** to review observed public IPs (`203.0.113.50`), domains (`suspicious-example.local`), usernames, and file staging paths (`/tmp/stage_payload.sh`).
8. **Export Reports:** Click **Reports** &rarr; **View / Print Executive HTML Report** to generate a publication-ready SOC investigation report with printable PDF styling.

---

## 8. Synthetic Sample Logs Included
- `sample_suspicious_incident.log`: Complete multi-stage attack sequence demonstrating full correlation.
- `sample_bruteforce.log`: High-frequency failed authentication attempts from a single source.
- `sample_privilege_escalation.log`: Routine user login followed by unauthorized sudo elevation.
- `sample_clean.log`: Routine authorized administrator actions with zero incidents.
- `sample_malformed.log`: Corrupted timestamps, non-standard text, and invalid IP addresses proving parser resilience.
- `sample_web_attacks.csv`: CSV structured log data depicting web brute-force and lockout.
- `sample_cloud_events.json`: JSON array format depicting cloud audit trails.

---

## 9. Academic Disclaimer
> **SOC Operational Notice:** This system performs rule-based security event analysis. Detection results indicate potentially suspicious activity and do not prove malicious intent.
