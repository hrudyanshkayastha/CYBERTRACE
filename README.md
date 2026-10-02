# CYBERTRACE
### Security Incident Detection & Investigation Platform
**Author:** Hrudyansh Kayastha

## Overview
CYBERTRACE is a local defensive security platform for analyzing security logs and detecting suspicious activity. It correlates related events, extracts IOCs, calculates explainable risk scores, and generates structured investigation reports.

## Features
- Multi-format log analysis
- Rule-based threat detection
- Incident correlation
- IOC extraction
- Explainable risk scoring
- JSON/HTML reports

## Architecture
```text
Logs → Parser → Detection → Correlation → IOC Extraction → Risk Engine → Dashboard & Reports
```

## Tech Stack
| Layer | Technology |
|---|---|
| Backend | Python, FastAPI |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite |
| Testing | pytest |

## Quick Start
```bash
git clone https://github.com/hrudyanshkayastha/CYBERTRACE.git
cd CYBERTRACE
python -m venv venv
pip install -r requirements.txt
python run.py
```
Dashboard: `http://127.0.0.1:8000`

## Example
`sample_suspicious_incident.log`: Brute Force → Login → Privilege Escalation → External Connection  
**Result:** 80/100 — CRITICAL

## Testing
`python -m pytest tests -v` — **36 tests passed**

## Scope
CyberTrace is a local defensive log-analysis platform. It does not execute uploaded files, perform exploitation, actively scan networks, or guarantee malicious-activity detection.

## License
MIT — **Author:** Hrudyansh Kayastha
