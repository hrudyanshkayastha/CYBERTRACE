"""
Unit tests for event normalizer.
"""

from app.parser.normalizer import normalize_event, normalize_timestamp, infer_event_type

def test_normalize_timestamp():
    # ISO string
    assert normalize_timestamp("2026-10-01T10:31:02") == "2026-10-01T10:31:02"
    # Space separated
    assert normalize_timestamp("2026-10-01 10:31:02") == "2026-10-01T10:31:02"
    # Syslog format
    res = normalize_timestamp("Oct 01 10:31:02")
    assert res is not None
    assert "10:31:02" in res
    # Invalid
    assert normalize_timestamp("invalid-date") is None
    assert normalize_timestamp("") is None
    assert normalize_timestamp(None) is None

def test_infer_event_type():
    assert infer_event_type(None, "Failed SSH login") == "LOGIN_FAILED"
    assert infer_event_type(None, "Accepted password for admin") == "LOGIN_SUCCESS"
    assert infer_event_type(None, "sudo su - executed") == "PRIVILEGE_ESCALATION"
    assert infer_event_type(None, "Account locked after maximum retries") == "ACCOUNT_LOCKED"
    assert infer_event_type(None, "Outbound connection to host") == "NETWORK_CONNECTION"
    assert infer_event_type("UNKNOWN", "Arbitrary non-security message") == "OTHER"

def test_normalize_event_complete():
    raw = {
        "timestamp": "2026-10-01 10:31:02",
        "source_ip": "192.168.1.20",
        "username": "admin",
        "event_type": "LOGIN_FAILED",
        "message": "Failed SSH password",
        "severity": "LOW"
    }
    norm = normalize_event(raw)
    assert norm["timestamp"] == "2026-10-01T10:31:02"
    assert norm["source_ip"] == "192.168.1.20"
    assert norm["username"] == "admin"
    assert norm["event_type"] == "LOGIN_FAILED"
    assert norm["severity"] == "LOW"

def test_normalize_event_missing_fields():
    raw = {"message": "Generic alert"}
    norm = normalize_event(raw)
    assert norm["timestamp"] is None
    assert norm["source_ip"] is None
    assert norm["username"] is None
    assert norm["event_type"] == "OTHER"
    assert norm["severity"] == "LOW"

def test_normalize_event_invalid_ip():
    raw = {"source_ip": "999.999.999.999", "message": "Test"}
    norm = normalize_event(raw)
    # Invalid IP should be set to None rather than corrupting DB
    assert norm["source_ip"] is None
