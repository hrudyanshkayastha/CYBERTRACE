# CYBERTRACE REST API Documentation

Base URL: `http://127.0.0.1:8000`

---

## 1. System Endpoints

### `GET /api/health`
Checks server readiness.
- **Status:** `200 OK`
- **Response:**
```json
{
  "status": "healthy",
  "service": "CYBERTRACE Incident Detection Platform",
  "version": "1.0.0"
}
```

---

## 2. Log Ingestion & Sample Scenarios

### `GET /api/samples`
Returns a list of built-in synthetic test scenarios.
- **Status:** `200 OK`
- **Response Example:**
```json
[
  {
    "name": "sample_suspicious_incident.log",
    "size_bytes": 834,
    "description": "Full multi-stage attack: Brute-force -> Auth -> PrivEsc -> Outbound Connection."
  }
]
```

### `POST /api/samples/analyze/{sample_name}`
Executes instant 1-click analysis on a built-in test log.
- **URL Parameter:** `sample_name` (e.g. `sample_suspicious_incident.log`)
- **Status:** `200 OK`
- **Response:**
```json
{
  "success": true,
  "message": "Successfully processed 8 events from sample_suspicious_incident.log.",
  "run_id": 1,
  "run_uuid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "filename": "sample_suspicious_incident.log",
  "total_events": 8,
  "suspicious_events": 5,
  "total_incidents": 1,
  "critical_incidents": 1,
  "max_risk_score": 100,
  "warnings": []
}
```

### `POST /api/logs/upload`
Uploads and parses a custom log file (`.log`, `.txt`, `.csv`, `.json`).
- **Form Data:** `file` (multipart/form-data)
- **Status:** `200 OK` on success, `400 Bad Request` if empty or disallowed extension.
- **Example cURL:**
```bash
curl -X POST "http://127.0.0.1:8000/api/logs/upload" \
  -H "accept: application/json" \
  -F "file=@sample_bruteforce.log"
```

---

## 3. Events & Incidents

### `GET /api/events`
Returns normalized security events for an analysis run.
- **Query Parameters:**
  - `run_id` (int, optional): Defaults to latest run.
  - `severity` (string, optional): `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
  - `event_type` (string, optional): `LOGIN_FAILED`, `PRIVILEGE_ESCALATION`, etc.
  - `search` (string, optional): Filter text for IP, user, or message.
  - `limit` (int, default 100, max 500)
  - `offset` (int, default 0)
- **Status:** `200 OK`

### `GET /api/incidents`
Lists all correlated security incidents for a run.
- **Query Parameter:** `run_id` (int, optional)
- **Status:** `200 OK`
- **Response Example:**
```json
[
  {
    "id": 1,
    "incident_code": "INC-001",
    "title": "Potential Account Takeover & Privilege Escalation",
    "incident_type": "ACCOUNT_COMPROMISE",
    "risk_score": 100,
    "risk_level": "CRITICAL",
    "source_ip": "192.168.1.20",
    "username": "admin",
    "attack_pattern": "Brute Force → Successful Authentication → Privilege Escalation → Suspicious Network Connection → File Artifact Creation",
    "event_count": 8
  }
]
```

### `GET /api/incidents/{incident_id}`
Returns complete incident details including chronological timeline and recommendations.
- **URL Parameter:** `incident_id` (int)
- **Status:** `200 OK`

---

## 4. Indicators of Compromise & Metrics

### `GET /api/iocs`
Returns forensic artifacts extracted from logs.
- **Query Parameters:** `run_id` (int), `ioc_type` (string), `suspicious_only` (bool)
- **Status:** `200 OK`

### `GET /api/statistics`
Returns high-level SOC dashboard metrics.
- **Query Parameter:** `run_id` (int, optional)
- **Response Example:**
```json
{
  "total_events": 8,
  "suspicious_events": 5,
  "total_incidents": 1,
  "critical_incidents": 1,
  "unique_ips": 2,
  "total_iocs": 5
}
```

---

## 5. Report Export

### `GET /api/reports/{run_id}/html`
Renders an executive, printable HTML incident report.
- **Response:** `text/html; charset=utf-8`

### `GET /api/reports/{run_id}/json`
Exports full structured report as a downloadable JSON file.
- **Response:** `application/json` (Content-Disposition attachment)
