"""
Unit tests for SQLite database operations.
"""

import tempfile
from pathlib import Path
from app.database.db import (
    init_db,
    save_analysis_run,
    get_run_by_id,
    get_events_for_run,
    get_incidents_for_run,
    get_iocs_for_run,
    get_incident_by_id,
    get_global_statistics
)

def test_sqlite_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_cybertrace.db"
        init_db(db_path)

        events = [
            {"timestamp": "2026-10-01T10:00:00", "source_ip": "10.0.0.1", "username": "admin", "event_type": "LOGIN_FAILED", "message": "fail", "severity": "LOW"},
            {"timestamp": "2026-10-01T10:00:05", "source_ip": "10.0.0.1", "username": "admin", "event_type": "LOGIN_SUCCESS", "message": "success", "severity": "LOW"},
        ]
        incidents = [
            {
                "incident_code": "INC-001",
                "title": "Test Incident",
                "incident_type": "TEST",
                "risk_score": 50,
                "risk_level": "MEDIUM",
                "source_ip": "10.0.0.1",
                "username": "admin",
                "first_observed": "2026-10-01T10:00:00",
                "last_observed": "2026-10-01T10:00:05",
                "event_count": 2,
                "attack_pattern": "Fail → Success",
                "contributing_factors": ["+20 test"],
                "recommendations": ["Review user"],
                "rules_triggered": ["RULE_002"],
                "event_indices": [0, 1]
            }
        ]
        iocs = [
            {"ioc_type": "IPv4", "ioc_value": "10.0.0.1", "is_suspicious": False, "context": "client", "first_seen": "2026-10-01T10:00:00"}
        ]

        run_id = save_analysis_run(
            run_uuid="test-uuid-1",
            filename="test.log",
            file_size=500,
            events=events,
            incidents=incidents,
            iocs=iocs,
            db_path=db_path
        )

        assert run_id > 0
        run = get_run_by_id(run_id, db_path=db_path)
        assert run["filename"] == "test.log"
        assert run["total_events"] == 2

        db_events = get_events_for_run(run_id, db_path=db_path)
        assert len(db_events) == 2

        db_incidents = get_incidents_for_run(run_id, db_path=db_path)
        assert len(db_incidents) == 1
        assert db_incidents[0]["incident_code"] == "INC-001"

        db_iocs = get_iocs_for_run(run_id, db_path=db_path)
        assert len(db_iocs) == 1

        single_inc = get_incident_by_id(db_incidents[0]["id"], db_path=db_path)
        assert len(single_inc["timeline"]) == 2

        stats = get_global_statistics(run_id=run_id, db_path=db_path)
        assert stats["total_events"] == 2
        assert stats["total_incidents"] == 1
