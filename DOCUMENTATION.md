# CYBERTRACE Technical Documentation
### Deep-Dive System Architecture & Implementation Manual

---

## 1. System Overview & Philosophy
CYBERTRACE is built on the engineering philosophy of **"Simple implementation, professional presentation."**
In beginner cybersecurity education and undergraduate vivas, systems that rely on opaque distributed architectures or black-box machine learning models obscure the core fundamentals of incident triage. CYBERTRACE uses clean, deterministic algorithms where every decision is verifiable and defensible.

---

## 2. Ingestion & Multi-Format Parsing (`app/parser/log_parser.py`)

### Input Validation & Defensive Ingestion
To protect the host system from resource exhaustion and unsafe file operations:
- **Maximum File Size:** Enforced at 10 MB (`MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024`).
- **File Extensions:** Strictly whitelisted to `.log`, `.txt`, `.csv`, `.json`.
- **Filename Sanitization:** Evaluated via `Path(filename).name` to eradicate path traversal attempts (`../../`).

### Multi-Format Parsing Strategy
The `LogParser` class detects log formatting dynamically:
1. **JSON Logs:** Evaluates valid JSON arrays (`[ {...} ]`) or JSON-lines (one object per line).
2. **CSV Logs:** Uses Python's standard `csv.DictReader` and automatically normalizes header aliases:
   - Timestamp aliases: `timestamp`, `time`, `date`, `datetime`, `logged_at`
   - IP aliases: `source_ip`, `src_ip`, `ip`, `client_ip`, `remote_ip`
   - User aliases: `username`, `user`, `account`, `user_id`
   - Event aliases: `event_type`, `action`, `event`, `type`
   - Message aliases: `message`, `msg`, `details`, `description`
3. **Structured Bracketed Logs:** Evaluates structured formats matching:
   `YYYY-MM-DD HH:MM:SS [SEVERITY] [IP] [USER] EVENT_TYPE: Message`
4. **Syslog / Auth.log Logs:** Evaluates standard Linux syslog prefixes (`Oct 01 10:31:02 hostname daemon[pid]: content`) and extracts SSH, Sudo, and UFW firewall actions.
5. **Fallback Generic Parser:** If an unstructured log line is encountered, regex matches extract whatever timestamps and IPv4 addresses are present, preserving the full line text in `message`.

**Zero-Crash Guarantee:** If any line is syntactically malformed, it is normalized as an `OTHER` event. The parser never raises an unhandled exception.

---

## 3. Event Normalization (`app/parser/normalizer.py`)

Every log entry is mapped into a canonical `NormalizedEvent` data structure:
```json
{
  "timestamp": "2026-10-01T10:31:02",
  "source_ip": "192.168.1.20",
  "username": "admin",
  "event_type": "LOGIN_FAILED",
  "message": "Failed SSH login",
  "severity": "LOW",
  "raw_log": "...",
  "extra_data": {}
}
```

### Supported Canonical Event Types
- `LOGIN_FAILED`: Unsuccessful authentication attempt.
- `LOGIN_SUCCESS`: Verified authentication.
- `ACCOUNT_LOCKED`: Administrative or policy lockout.
- `PRIVILEGE_ESCALATION`: Escalation to root, administrator, or sudo execution.
- `PASSWORD_CHANGED`: Modification of account credentials.
- `PROCESS_EXECUTED`: Execution of system binary or shell script.
- `FILE_CREATED`: File system modification or staging.
- `NETWORK_CONNECTION`: Inbound or outbound network communication.
- `LOGOUT`: Termination of user session.
- `OTHER`: Unclassified diagnostic or non-security message.

### Null Handling Rule
If a field (such as `source_ip` or `username`) is absent from a log entry, CYBERTRACE assigns `None` (`null` in JSON) rather than inventing placeholder values.

---

## 4. Deterministic Security Rules (`app/detection/rules.py`)

All detection rules subclass `BaseRule` and implement `evaluate(events) -> List[RuleMatch]`:

### Rule 1: `RuleBruteForce`
- **Condition:** $\ge 5$ failed logins (`LOGIN_FAILED`) from the same source IP within 300 seconds (5 minutes).
- **Severity:** HIGH
- **Finding:** `"Possible brute-force attack"`

### Rule 2: `RuleLoginAfterFailures`
- **Condition:** $\ge 3$ failed logins followed chronologically by a successful login (`LOGIN_SUCCESS`) for the same IP or user within 600 seconds.
- **Severity:** HIGH
- **Finding:** `"Successful login following multiple authentication failures"`

### Rule 3: `RuleAccountLockout`
- **Condition:** $\ge 3$ failed logins culminating in an `ACCOUNT_LOCKED` event within 600 seconds.
- **Severity:** MEDIUM
- **Finding:** `"Account lockout following multiple authentication failures"`

### Rule 4: `RulePrivilegeEscalation`
- **Condition:** Explicit `PRIVILEGE_ESCALATION` event or `PROCESS_EXECUTED` involving `sudo`, `su root`, `runas`, or privileged command escalation.
- **Severity:** HIGH
- **Finding:** `"Potential unauthorized privilege escalation"`

### Rule 5: `RuleSuspiciousExternalConnection`
- **Condition:** Network connection (`NETWORK_CONNECTION`) targeted toward an external public IP address (outside RFC 1918 / Loopback).
- **Severity:** MEDIUM
- **Finding:** `"Outbound network connection to external IP"`

---

## 5. Event Correlation Engine (`app/correlation/engine.py`)

Rather than bombarding the analyst with disconnected alerts, the `CorrelationEngine`:
1. **Entity Grouping:** Groups events by primary entity identifier (Source IP or Username).
2. **Context Aggregation:** Correlates both triggered rule events and contextual intermediate events (e.g. file creations, process executions) occurring within the same activity window.
3. **Attack Chain Synthesis:** Inspects the chronological sequence of actions and synthesizes a human-readable attack progression:
   $$\text{Brute Force} \longrightarrow \text{Successful Auth} \longrightarrow \text{Privilege Escalation} \longrightarrow \text{External Connection}$$
4. **Defensive Labeling:** Uses objective defensive terminology: `"Potential attack pattern detected"`.

---

## 6. Explainable Risk Scoring (`app/risk/scorer.py`)

CYBERTRACE computes risk using a completely transparent additive formula capped at 100:

| Security Factor | Added Points | Viva Explanation |
| :--- | :---: | :--- |
| Failed login burst | +20 | Rapid password guessing attempts |
| Successful login after failures | +20 | Likely credential compromise |
| Account lockout | +10 | Policy ceiling breached |
| Privilege escalation | +25 | Attacker gaining superuser permissions |
| External network connection | +20 | Potential command & control (C2) / data staging |
| Multiple correlated indicators | +15 | Multi-stage attack convergence |

### Risk Level Tiers
- **0–29:** LOW (Minor operational noise or isolated failure)
- **30–59:** MEDIUM (Suspicious anomaly warranting observation)
- **60–79:** HIGH (Correlated attack chain requiring containment)
- **80–100:** CRITICAL (Multi-stage compromise confirmed across indicators)

---

## 7. SQLite Relational Schema (`app/database/db.py`)

The SQLite database (`data/cybertrace.db`) consists of 5 normalized tables:
- `analysis_runs`: Audit records of uploaded files, upload timestamps, and summary counts.
- `events`: Individual normalized event entries with foreign key to `analysis_runs`.
- `incidents`: Correlated incident records including attack pattern, score, factors, and recommendations.
- `incident_events`: Many-to-many junction table mapping which specific events belong to an incident.
- `iocs`: Extracted indicators of compromise with type and suspicion status.
