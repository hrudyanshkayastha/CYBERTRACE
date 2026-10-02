# CYBERTRACE Viva Voce Guide & Examiner Q&A
### Comprehensive Preparation for 3rd-Year BSc Cybersecurity Students

> **Student Tip:** When answering examiners, keep your answers concise, structured, and confident. Use the phrases in bold.

---

### Q1: What is a security log?
**Answer:**
A security log is an automated, time-stamped record of system, network, or application activity. It records actions such as user logins, file accesses, permission changes, and network connections to maintain an audit trail.

---

### Q2: What is the fundamental difference between an Event and an Incident?
**Answer:**
- An **Event** is any observable occurrence on a system (for example, a single failed login or a firewall block). Most events are routine.
- An **Incident** is an event or series of correlated events that compromises or threatens the security, confidentiality, or integrity of a system.
- *Simple analogy:* A car engine clicking is an event; the engine catching fire is an incident.

---

### Q3: What is a Security Operations Center (SOC)?
**Answer:**
A **SOC (Security Operations Center)** is an organization's centralized defense team responsible for continuously monitoring, detecting, analyzing, and responding to cybersecurity incidents using security tools and logs.

---

### Q4: What is an Indicator of Compromise (IOC)?
**Answer:**
An **IOC** is a forensic artifact or piece of evidence found in logs that suggests a system has been targeted or breached. Common IOCs include suspicious external IP addresses, malicious domains, unauthorized URLs, unexpected administrator usernames, and staging file paths.

---

### Q5: What is Brute-Force authentication?
**Answer:**
A **brute-force attack** is an automated trial-and-error method where an attacker submits numerous passwords or passphrases with the hope of eventually guessing correctly. In CYBERTRACE, we detect this when $\ge 5$ failed attempts occur within 5 minutes.

---

### Q6: What is Event Correlation, and why is it important?
**Answer:**
Event correlation is the process of linking separate, isolated events together into a meaningful attack pattern based on common attributes (such as the same IP address, username, or time window).
Without correlation, analysts suffer from **alert fatigue** viewing isolated alerts. Correlation allows us to see the complete attack chain: `Brute Force → Login Success → Privilege Escalation → Network Connection`.

---

### Q7: How does CYBERTRACE calculate the Risk Score?
**Answer:**
CYBERTRACE uses a **transparent, additive scoring model** capped at 100 points:
- Failed login burst: **+20**
- Successful login after multiple failures: **+20**
- Privilege escalation: **+25**
- Suspicious external connection: **+20**
- Account lockout: **+10**
- Multiple correlated indicators: **+15**
Scores are categorized into **LOW (0–29)**, **MEDIUM (30–59)**, **HIGH (60–79)**, and **CRITICAL (80–100)**.

---

### Q8: Why did you choose deterministic rule-based detection over Machine Learning?
**Answer:**
Three key reasons:
1. **Explainability:** In a security audit or legal review, every alert must be explainable. Rule-based detection provides 100% transparent reasoning, whereas ML models are often black boxes.
2. **Deterministic Reliability:** Rule-based detection produces predictable results without false positives caused by training data drift.
3. **Appropriate for Scope:** For a third-year undergraduate demonstration, deterministic rules teach core defensive fundamentals without unnecessary complexity.

---

### Q9: Why did you use SQLite instead of a heavy database like PostgreSQL or MongoDB?
**Answer:**
- **Zero Configuration:** SQLite is serverless and built directly into Python.
- **Portability:** The entire database is stored in a single file (`data/cybertrace.db`), making it completely portable and easy to inspect or reset during a viva.
- **Academic Transparency:** Simple SQL queries make the relational data flow easy to demonstrate.

---

### Q10: Why did you use FastAPI?
**Answer:**
FastAPI is a modern, high-performance Python web framework. It provides:
1. **Automatic Data Validation:** Built-in with Pydantic schemas.
2. **Speed & Asynchrony:** Native ASGI compliance with Uvicorn.
3. **Clean REST Architecture:** Simple route declarations and automatic interactive OpenAPI documentation (`/docs`).

---

### Q11: What is the difference between Detection and Proof of Attack?
**Answer:**
**Detection** means the system observed an activity pattern that matches known suspicious indicators. **Proof of attack** requires full forensic corroboration, attacker attribution, and verification that the activity was unauthorized.
This is why CYBERTRACE uses objective SOC wording: *"Potential attack pattern detected"*.

---

### Q12: What are the main limitations of CYBERTRACE?
**Answer:**
1. **Deterministic Thresholds:** An adversary who executes "low-and-slow" attacks (e.g. 1 failed login every hour) would bypass the 5-minute brute-force threshold.
2. **Encrypted Payloads:** The system analyzes log headers and metadata; it does not inspect encrypted HTTPS/TLS payload contents.
3. **Log Reliance:** If an adversary disables or alters local logging, no events can be detected.

---

### Q13: If an examiner asks: "Walk me through what happens when I upload a log file", what do you say?
**Answer:**
1. The file is uploaded to `POST /api/logs/upload`.
2. The **Log Parser** safely reads the lines without crashing and passes them to the **Normalizer**.
3. The **Normalizer** standardizes timestamps into ISO-8601 and maps events to canonical types.
4. The **IOC Extractor** finds IPs, domains, users, and file paths.
5. The **Rule Engine** evaluates the 5 deterministic rules.
6. The **Correlation Engine** groups matching events by IP/user into an **Incident** with an attack chain.
7. The **Risk Scorer** calculates the explainable risk score.
8. The entire run is persisted to **SQLite**, and the dashboard displays the results immediately.
