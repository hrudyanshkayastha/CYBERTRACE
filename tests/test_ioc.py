"""
Unit tests for IOC extractor.
"""

from app.ioc.extractor import IOCExtractor, is_private_ip

def test_is_private_ip():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("172.16.5.10") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("203.0.113.50") is False
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("invalid-ip") is False

def test_extract_iocs_comprehensive():
    events = [
        {
            "timestamp": "2026-10-01T10:31:02",
            "source_ip": "192.168.1.20",
            "username": "admin",
            "event_type": "LOGIN_FAILED",
            "message": "Connection to http://suspicious-example.local/payload from 203.0.113.50",
            "severity": "HIGH",
            "raw_log": "Accessed file /tmp/stage_payload.sh"
        }
    ]
    iocs = IOCExtractor.extract_from_events(events)
    ioc_types = [i["ioc_type"] for i in iocs]
    ioc_values = [i["ioc_value"] for i in iocs]

    assert "IPv4" in ioc_types
    assert "192.168.1.20" in ioc_values
    assert "203.0.113.50" in ioc_values
    assert "USERNAME" in ioc_types
    assert "admin" in ioc_values
    assert "URL" in ioc_types
    assert "DOMAIN" in ioc_types
    assert "FILE_PATH" in ioc_types
    assert "/tmp/stage_payload.sh" in ioc_values

    # Check external IP flagged as suspicious
    ext_ip_ioc = next(i for i in iocs if i["ioc_value"] == "203.0.113.50")
    assert ext_ip_ioc["is_suspicious"] is True
