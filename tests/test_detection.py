"""
Unit tests for security detection rules.
"""

from app.detection.rules import (
    RuleBruteForce,
    RuleLoginAfterFailures,
    RuleAccountLockout,
    RulePrivilegeEscalation,
    RuleSuspiciousExternalConnection,
)
from app.detection.engine import DetectionEngine

def test_rule_brute_force_detection():
    rule = RuleBruteForce(threshold=5, window_seconds=300)
    # Generate 5 failed logins within 60 seconds
    events = [
        {
            "timestamp": f"2026-10-01T10:00:0{i}",
            "source_ip": "192.168.1.100",
            "username": "root",
            "event_type": "LOGIN_FAILED",
            "message": "Auth failure",
            "severity": "LOW"
        }
        for i in range(5)
    ]
    matches = rule.evaluate(events)
    assert len(matches) == 1
    assert matches[0].rule_id == "RULE_001_BRUTE_FORCE"
    assert matches[0].finding == "Possible brute-force attack"
    assert len(matches[0].matched_event_indices) == 5

def test_rule_login_after_failures():
    rule = RuleLoginAfterFailures(threshold=3, window_seconds=600)
    events = [
        {"timestamp": "2026-10-01T10:00:01", "source_ip": "10.0.0.2", "username": "admin", "event_type": "LOGIN_FAILED", "message": "Failed"},
        {"timestamp": "2026-10-01T10:00:02", "source_ip": "10.0.0.2", "username": "admin", "event_type": "LOGIN_FAILED", "message": "Failed"},
        {"timestamp": "2026-10-01T10:00:03", "source_ip": "10.0.0.2", "username": "admin", "event_type": "LOGIN_FAILED", "message": "Failed"},
        {"timestamp": "2026-10-01T10:00:05", "source_ip": "10.0.0.2", "username": "admin", "event_type": "LOGIN_SUCCESS", "message": "Success"},
    ]
    matches = rule.evaluate(events)
    assert len(matches) == 1
    assert matches[0].rule_id == "RULE_002_LOGIN_AFTER_FAILURES"
    assert matches[0].finding == "Successful login following multiple authentication failures"

def test_rule_account_lockout():
    rule = RuleAccountLockout(threshold=3, window_seconds=600)
    events = [
        {"timestamp": "2026-10-01T10:00:01", "source_ip": "10.0.0.3", "username": "victim", "event_type": "LOGIN_FAILED", "message": "Failed"},
        {"timestamp": "2026-10-01T10:00:02", "source_ip": "10.0.0.3", "username": "victim", "event_type": "LOGIN_FAILED", "message": "Failed"},
        {"timestamp": "2026-10-01T10:00:03", "source_ip": "10.0.0.3", "username": "victim", "event_type": "LOGIN_FAILED", "message": "Failed"},
        {"timestamp": "2026-10-01T10:00:05", "source_ip": "10.0.0.3", "username": "victim", "event_type": "ACCOUNT_LOCKED", "message": "Locked"},
    ]
    matches = rule.evaluate(events)
    assert len(matches) == 1
    assert matches[0].rule_id == "RULE_003_ACCOUNT_LOCKOUT"

def test_rule_privilege_escalation():
    rule = RulePrivilegeEscalation()
    events = [
        {"timestamp": "2026-10-01T10:00:00", "source_ip": "10.0.0.4", "username": "dev", "event_type": "PRIVILEGE_ESCALATION", "message": "sudo su root", "severity": "HIGH"},
        {"timestamp": "2026-10-01T10:00:05", "source_ip": "10.0.0.4", "username": "dev", "event_type": "PROCESS_EXECUTED", "message": "Executed powershell -ep bypass", "severity": "MEDIUM"}
    ]
    matches = rule.evaluate(events)
    assert len(matches) == 2
    assert all(m.rule_id == "RULE_004_PRIVILEGE_ESCALATION" for m in matches)

def test_rule_external_network_connection():
    rule = RuleSuspiciousExternalConnection()
    events = [
        {
            "timestamp": "2026-10-01T10:00:00",
            "source_ip": "10.0.0.5",
            "username": "user",
            "event_type": "NETWORK_CONNECTION",
            "message": "Connected to remote server",
            "severity": "MEDIUM",
            "extra_data": {"destination_ip": "203.0.113.10"}  # Public IP
        }
    ]
    matches = rule.evaluate(events)
    assert len(matches) == 1
    assert matches[0].rule_id == "RULE_005_EXTERNAL_CONNECTION"

def test_detection_engine_aggregator():
    engine = DetectionEngine()
    events = [
        {"timestamp": "2026-10-01T10:00:00", "source_ip": "10.0.0.1", "username": "admin", "event_type": "PRIVILEGE_ESCALATION", "message": "sudo su", "severity": "LOW"}
    ]
    matches = engine.analyze(events)
    assert len(matches) >= 1
    # Check severity updated in-place to HIGH
    assert events[0]["severity"] == "HIGH"
