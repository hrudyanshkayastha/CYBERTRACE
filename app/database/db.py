"""
CYBERTRACE - SQLite Database Layer
Provides lightweight, transparent relational storage using Python's standard sqlite3.
Clean schema designed for beginner student understanding and viva explanation.
"""

import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.config import DATABASE_PATH, DATA_DIR

def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Returns a SQLite connection with dict-like row access."""
    path = db_path or DATABASE_PATH
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path: Optional[Path] = None) -> None:
    """Initializes the database schema if tables do not exist."""
    conn = get_connection(db_path)
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_uuid TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            uploaded_at TEXT NOT NULL,
            total_events INTEGER DEFAULT 0,
            suspicious_events INTEGER DEFAULT 0,
            total_incidents INTEGER DEFAULT 0,
            critical_incidents INTEGER DEFAULT 0,
            max_risk_score INTEGER DEFAULT 0,
            summary_json TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            event_index INTEGER NOT NULL,
            timestamp TEXT,
            source_ip TEXT,
            username TEXT,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'LOW',
            raw_log TEXT,
            extra_json TEXT DEFAULT '{}',
            FOREIGN KEY(run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_code TEXT NOT NULL,
            run_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            source_ip TEXT,
            username TEXT,
            first_observed TEXT,
            last_observed TEXT,
            event_count INTEGER NOT NULL,
            attack_pattern TEXT NOT NULL,
            factors_json TEXT NOT NULL DEFAULT '[]',
            recommendations_json TEXT NOT NULL DEFAULT '[]',
            rules_triggered_json TEXT NOT NULL DEFAULT '[]',
            FOREIGN KEY(run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS incident_events (
            incident_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            PRIMARY KEY(incident_id, event_id),
            FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            is_suspicious INTEGER DEFAULT 0,
            context TEXT,
            first_seen TEXT,
            FOREIGN KEY(run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
        CREATE INDEX IF NOT EXISTS idx_incidents_run ON incidents(run_id);
        CREATE INDEX IF NOT EXISTS idx_iocs_run ON iocs(run_id);
        """)
    conn.close()

def save_analysis_run(
    run_uuid: str,
    filename: str,
    file_size: int,
    events: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
    iocs: List[Dict[str, Any]],
    db_path: Optional[Path] = None
) -> int:
    """
    Persists a complete analysis run, its normalized events, incidents, and IOCs.
    Returns the generated run_id.
    """
    conn = get_connection(db_path)
    now_iso = datetime.now().isoformat()
    
    suspicious_count = sum(1 for e in events if e.get("severity") in ("MEDIUM", "HIGH", "CRITICAL"))
    total_incidents = len(incidents)
    critical_incidents = sum(1 for inc in incidents if inc.get("risk_level") == "CRITICAL")
    max_risk = max([inc.get("risk_score", 0) for inc in incidents], default=0)

    summary = {
        "event_types": {},
        "unique_ips": len(set(e.get("source_ip") for e in events if e.get("source_ip"))),
        "unique_users": len(set(e.get("username") for e in events if e.get("username")))
    }
    for e in events:
        etype = e.get("event_type", "OTHER")
        summary["event_types"][etype] = summary["event_types"].get(etype, 0) + 1

    with conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analysis_runs 
            (run_uuid, filename, file_size, uploaded_at, total_events, suspicious_events, 
             total_incidents, critical_incidents, max_risk_score, summary_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_uuid, filename, file_size, now_iso, len(events), suspicious_count,
            total_incidents, critical_incidents, max_risk, json.dumps(summary)
        ))
        run_id = cursor.lastrowid

        # Insert events and keep track of index -> db id
        event_id_map = {}
        for idx, ev in enumerate(events):
            cursor.execute("""
                INSERT INTO events 
                (run_id, event_index, timestamp, source_ip, username, event_type, message, severity, raw_log, extra_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id, idx, ev.get("timestamp"), ev.get("source_ip"), ev.get("username"),
                ev.get("event_type", "OTHER"), ev.get("message", ""), ev.get("severity", "LOW"),
                ev.get("raw_log", ""), json.dumps(ev.get("extra_data", {}))
            ))
            event_id_map[idx] = cursor.lastrowid

        # Insert incidents and incident_events mapping
        for inc in incidents:
            cursor.execute("""
                INSERT INTO incidents
                (incident_code, run_id, title, incident_type, risk_score, risk_level, source_ip, username,
                 first_observed, last_observed, event_count, attack_pattern, factors_json, recommendations_json, rules_triggered_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                inc.get("incident_code", "INC-001"), run_id, inc.get("title", "Security Incident"),
                inc.get("incident_type", "SUSPICIOUS_ACTIVITY"), inc.get("risk_score", 0),
                inc.get("risk_level", "LOW"), inc.get("source_ip"), inc.get("username"),
                inc.get("first_observed"), inc.get("last_observed"), inc.get("event_count", 0),
                inc.get("attack_pattern", ""), json.dumps(inc.get("contributing_factors", [])),
                json.dumps(inc.get("recommendations", [])), json.dumps(inc.get("rules_triggered", []))
            ))
            inc_db_id = cursor.lastrowid
            
            # Map events related to this incident
            for ev_idx in inc.get("event_indices", []):
                if ev_idx in event_id_map:
                    cursor.execute("""
                        INSERT OR IGNORE INTO incident_events (incident_id, event_id)
                        VALUES (?, ?)
                    """, (inc_db_id, event_id_map[ev_idx]))

        # Insert IOCs
        for ioc in iocs:
            cursor.execute("""
                INSERT INTO iocs (run_id, ioc_type, ioc_value, is_suspicious, context, first_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                run_id, ioc.get("ioc_type"), ioc.get("ioc_value"),
                1 if ioc.get("is_suspicious") else 0,
                ioc.get("context", ""), ioc.get("first_seen")
            ))

    conn.close()
    return run_id

def get_latest_run(db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Retrieves the most recent analysis run."""
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM analysis_runs ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    return dict(row) if row else None

def get_run_by_id(run_id: int, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Retrieves a specific run by primary key."""
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_runs(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Lists all stored analysis runs."""
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM analysis_runs ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_events_for_run(run_id: int, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Returns all normalized events associated with an analysis run."""
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM events WHERE run_id = ? ORDER BY event_index ASC", (run_id,)).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["extra_data"] = json.loads(d.get("extra_json") or "{}")
        results.append(d)
    return results

def get_incidents_for_run(run_id: int, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Returns all incidents associated with an analysis run."""
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM incidents WHERE run_id = ? ORDER BY risk_score DESC", (run_id,)).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["contributing_factors"] = json.loads(d.get("factors_json") or "[]")
        d["recommendations"] = json.loads(d.get("recommendations_json") or "[]")
        d["rules_triggered"] = json.loads(d.get("rules_triggered_json") or "[]")
        results.append(d)
    return results

def get_incident_by_id(incident_id: int, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Returns an incident along with its linked chronological events."""
    conn = get_connection(db_path)
    inc_row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not inc_row:
        conn.close()
        return None
    inc = dict(inc_row)
    inc["contributing_factors"] = json.loads(inc.get("factors_json") or "[]")
    inc["recommendations"] = json.loads(inc.get("recommendations_json") or "[]")
    inc["rules_triggered"] = json.loads(inc.get("rules_triggered_json") or "[]")

    # Fetch associated events
    ev_rows = conn.execute("""
        SELECT e.* FROM events e
        JOIN incident_events ie ON e.id = ie.event_id
        WHERE ie.incident_id = ?
        ORDER BY e.timestamp ASC, e.event_index ASC
    """, (incident_id,)).fetchall()
    inc["timeline"] = [dict(ev) for ev in ev_rows]
    conn.close()
    return inc

def get_iocs_for_run(run_id: int, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Returns all IOCs recorded for a run."""
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM iocs WHERE run_id = ? ORDER BY is_suspicious DESC, id ASC", (run_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_global_statistics(run_id: Optional[int] = None, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Generates overall SOC metrics for dashboard display."""
    conn = get_connection(db_path)
    if run_id:
        target_run = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        if not target_run:
            conn.close()
            return {}
        events_count = target_run["total_events"]
        suspicious_count = target_run["suspicious_events"]
        incidents_count = target_run["total_incidents"]
        critical_count = target_run["critical_incidents"]
        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) as cnt FROM events WHERE run_id = ? AND source_ip IS NOT NULL", 
            (run_id,)
        ).fetchone()["cnt"]
        iocs_count = conn.execute("SELECT COUNT(*) as cnt FROM iocs WHERE run_id = ?", (run_id,)).fetchone()["cnt"]
    else:
        runs = conn.execute("SELECT COUNT(*) as cnt FROM analysis_runs").fetchone()["cnt"]
        if runs == 0:
            conn.close()
            return {
                "total_events": 0, "suspicious_events": 0, "total_incidents": 0,
                "critical_incidents": 0, "unique_ips": 0, "total_iocs": 0
            }
        events_count = conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()["cnt"]
        suspicious_count = conn.execute("SELECT COUNT(*) as cnt FROM events WHERE severity IN ('MEDIUM','HIGH','CRITICAL')").fetchone()["cnt"]
        incidents_count = conn.execute("SELECT COUNT(*) as cnt FROM incidents").fetchone()["cnt"]
        critical_count = conn.execute("SELECT COUNT(*) as cnt FROM incidents WHERE risk_level = 'CRITICAL'").fetchone()["cnt"]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) as cnt FROM events WHERE source_ip IS NOT NULL").fetchone()["cnt"]
        iocs_count = conn.execute("SELECT COUNT(*) as cnt FROM iocs").fetchone()["cnt"]

    conn.close()
    return {
        "total_events": events_count,
        "suspicious_events": suspicious_count,
        "total_incidents": incidents_count,
        "critical_incidents": critical_count,
        "unique_ips": unique_ips,
        "total_iocs": iocs_count
    }
