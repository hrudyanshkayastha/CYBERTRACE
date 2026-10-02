# CYBERTRACE Architectural Specification

---

## 1. High-Level Architectural Layers

CYBERTRACE follows a clean 4-tier monolithic architecture designed for local defensive cybersecurity analysis:

```
+-------------------------------------------------------------------------+
|                         PRESENTATION LAYER                              |
|   - Vanilla JS SPA Controller (app.js)                                  |
|   - SOC Dark-Mode Styling (styles.css)                                  |
|   - Executive HTML & JSON Incident Reports                              |
+-------------------------------------------------------------------------+
                                    |
                                    v [HTTP / REST]
+-------------------------------------------------------------------------+
|                            API ROUTING LAYER                            |
|   - FastAPI Application (app/main.py)                                   |
|   - REST Endpoints & Parameter Validation (app/api/routes.py)           |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                         CORE SECURITY PIPELINE                          |
|   - Log Parser & Resilient Normalizer (app/parser/)                     |
|   - IOC Extractor (app/ioc/)                                            |
|   - Deterministic Detection Rules (app/detection/)                      |
|   - Event Correlation Engine (app/correlation/)                         |
|   - Explainable Risk Scoring Engine (app/risk/)                         |
+-------------------------------------------------------------------------+
                                    |
                                    v [SQL]
+-------------------------------------------------------------------------+
|                            STORAGE LAYER                                |
|   - SQLite Database (data/cybertrace.db)                                |
|   - Raw & Structured Reports (reports/)                                 |
+-------------------------------------------------------------------------+
```

---

## 2. Event Processing Pipeline Flowchart

```
[Raw Log Ingestion]
        |
        v
[Log Parser] ──────────> Flag & sanitize malformed lines
        |
        v
[Event Normalizer] ────> Standardize ISO timestamp, IP, User, Canonical Type
        |
        +─────────────────────────+
        |                         |
        v                         v
[IOC Extractor]           [Detection Rule Engine]
- IPs (Public vs Private)  - Rule 001: Brute Force
- URLs & Domains          - Rule 002: Login After Failures
- Usernames & Paths       - Rule 003: Account Lockout
        |                 - Rule 004: Privilege Escalation
        |                 - Rule 005: External Connection
        |                         |
        +───────────+─────────────+
                    |
                    v
          [Event Correlation]
          - Group by Source IP / User
          - Synthesize Attack Chain
                    |
                    v
          [Explainable Risk Scorer]
          - Additive Scoring Model
          - Compute Risk Level & Factors
                    |
                    v
          [SQLite Persistence]
          - Store Run, Events, Incidents, IOCs
                    |
                    v
          [SOC Dashboard & Reports]
```

---

## 3. Database Entity-Relationship Model

```
+-------------------+        1:N        +-------------------+
|   analysis_runs   | ----------------< |      events       |
+-------------------+                   +-------------------+
| id (PK)           |                   | id (PK)           |
| run_uuid          |                   | run_id (FK)       |
| filename          |                   | timestamp         |
| total_events      |                   | source_ip         |
| total_incidents   |                   | username          |
| max_risk_score    |                   | event_type        |
+-------------------+                   | severity          |
        |                               | message           |
        | 1:N                           +-------------------+
        |                                         |
        v                                         | M:N
+-------------------+       1:N         +-------------------+
|     incidents     | <---------------< |  incident_events  |
+-------------------+                   +-------------------+
| id (PK)           |                   | incident_id (FK)  |
| run_id (FK)       |                   | event_id (FK)     |
| incident_code     |                   +-------------------+
| title             |
| risk_score        |
| risk_level        |
| attack_pattern    |
+-------------------+
        |
        | 1:N
        v
+-------------------+
|       iocs        |
+-------------------+
| id (PK)           |
| run_id (FK)       |
| ioc_type          |
| ioc_value         |
| is_suspicious     |
+-------------------+
```

---

## 4. Key Design Decisions for Academic Viva
1. **Monolithic over Microservices:** Eliminates distributed networking failure modes and serialization overhead.
2. **SQLite over PostgreSQL/NoSQL:** Zero-configuration setup, fully portable database file, standard library support.
3. **Vanilla JS over React/Angular:** Completely transparent client code without heavy node_modules build steps.
4. **Deterministic Rules over Machine Learning:** 100% explainable verdicts satisfying academic auditability.
