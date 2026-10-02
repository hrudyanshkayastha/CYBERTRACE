"""
Unit tests for event correlation engine.
"""

from app.correlation.engine import CorrelationEngine
from app.detection.rules import RuleMatch

def test_correlation_groups_by_source_ip():
    events = [
        {"timestamp": "2026-10-01T10:00:00", "source_ip": "192.168.1.50", "username": "admin", "event_type": "LOGIN_FAILED", "message": "Failed 1"},
        {"timestamp": "2026-10-01T10:00:02", "source_ip": "192.168.1.50", "username": "admin", "event_type": "LOGIN_FAILED", "message": "Failed 2"},
        {"timestamp": "2026-10-01T10:00:05", "source_ip": "192.168.1.50", "username": "admin", "event_type": "LOGIN_SUCCESS", "message": "Success"},
        {"timestamp": "2026-10-01T10:00:10", "source_ip": "192.168.1.50", "username": "admin", "event_type": "PRIVILEGE_ESCALATION", "message": "sudo su"},
    ]
    rule_matches = [
        RuleMatch(
            rule_id="RULE_002_LOGIN_AFTER_FAILURES",
            rule_name="Successful Login Following Repeated Failures",
            finding="Successful login following multiple authentication failures",
            severity="HIGH",
            source_ip="192.168.1.50",
            username="admin",
            matched_event_indices=[0, 1, 2]
        ),
        RuleMatch(
            rule_id="RULE_004_PRIVILEGE_ESCALATION",
            rule_name="Privilege Escalation Activity",
            finding="Potential unauthorized privilege escalation",
            severity="HIGH",
            source_ip="192.168.1.50",
            username="admin",
            matched_event_indices=[3]
        )
    ]

    incidents = CorrelationEngine.correlate(events, rule_matches)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["incident_code"] == "INC-001"
    assert inc["source_ip"] == "192.168.1.50"
    assert inc["username"] == "admin"
    assert inc["event_count"] == 4
    # Check attack chain synthesized correctly
    assert "Successful Authentication" in inc["attack_pattern"]
    assert "Privilege Escalation" in inc["attack_pattern"]
    assert inc["risk_score"] >= 60

def test_correlation_empty_input():
    incidents = CorrelationEngine.correlate([], [])
    assert incidents == []
