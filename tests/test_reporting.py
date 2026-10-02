"""
Unit tests for report generator.
"""

from app.reporting.generator import ReportGenerator

def test_generate_json_report():
    run_data = {
        "filename": "test.log",
        "file_size": 1024,
        "uploaded_at": "2026-10-01T10:00:00",
        "total_events": 10,
        "suspicious_events": 4,
        "total_incidents": 1,
        "critical_incidents": 0,
        "max_risk_score": 75
    }
    events = [{"event_type": "LOGIN_FAILED", "message": "fail"}]
    incidents = [{"incident_code": "INC-001", "title": "Test Incident", "risk_score": 75, "risk_level": "HIGH"}]
    iocs = [{"ioc_type": "IPv4", "ioc_value": "192.168.1.1", "is_suspicious": False, "context": "source IP"}]

    rep = ReportGenerator.generate_json_report(run_data, events, incidents, iocs)
    assert rep["project"].startswith("CYBERTRACE")
    assert rep["statistics"]["total_events"] == 10
    assert rep["statistics"]["max_risk_score"] == 75
    assert "disclaimer" in rep
    assert len(rep["incidents"]) == 1

def test_generate_html_report_disclaimer():
    run_data = {
        "filename": "sample_suspicious_incident.log",
        "total_events": 8,
        "suspicious_events": 5,
        "total_incidents": 1,
        "max_risk_score": 85
    }
    incidents = [{
        "incident_code": "INC-001",
        "title": "Account Compromise",
        "risk_score": 85,
        "risk_level": "CRITICAL",
        "source_ip": "192.168.1.20",
        "username": "admin",
        "event_count": 8,
        "attack_pattern": "Brute Force → Auth → PrivEsc",
        "contributing_factors": ["+20 Brute force", "+25 Privilege escalation"],
        "recommendations": ["Audit account"],
        "rules_triggered": ["RULE_001_BRUTE_FORCE"]
    }]
    iocs = [{"ioc_type": "IPv4", "ioc_value": "192.168.1.20", "is_suspicious": True, "context": "Source IP"}]

    html = ReportGenerator.generate_html_report(run_data, [], incidents, iocs)
    assert "<!DOCTYPE html>" in html
    assert "CYBERTRACE" in html
    assert "INC-001" in html
    assert "CRITICAL (85/100)" in html
    # Verify mandatory academic SOC disclaimer
    assert "Detection results indicate potentially suspicious activity and do not prove malicious intent." in html
