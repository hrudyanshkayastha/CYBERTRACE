"""
Integration tests for FastAPI REST endpoints and upload handling.
"""

import io
from fastapi.testclient import TestClient
from app.main import app
from app.database.db import init_db

client = TestClient(app)

def setup_module(module):
    """Ensure database schema is created before tests run."""
    init_db()

def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "CYBERTRACE" in data["service"]

def test_samples_list():
    res = client.get("/api/samples")
    assert res.status_code == 200
    samples = res.json()
    assert isinstance(samples, list)
    sample_names = [s["name"] for s in samples]
    assert "sample_clean.log" in sample_names
    assert "sample_suspicious_incident.log" in sample_names

def test_analyze_suspicious_incident_sample():
    res = client.post("/api/samples/analyze/sample_suspicious_incident.log")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["total_events"] > 0
    assert data["total_incidents"] >= 1
    assert data["max_risk_score"] >= 60

    run_id = data["run_id"]

    # Verify events endpoint
    ev_res = client.get(f"/api/events?run_id={run_id}")
    assert ev_res.status_code == 200
    assert ev_res.json()["total"] == data["total_events"]

    # Verify incidents endpoint
    inc_res = client.get(f"/api/incidents?run_id={run_id}")
    assert inc_res.status_code == 200
    incidents = inc_res.json()
    assert len(incidents) >= 1
    assert incidents[0]["risk_level"] in ("HIGH", "CRITICAL")
    assert "Brute Force" in incidents[0]["attack_pattern"]

    # Verify incident detail
    detail_res = client.get(f"/api/incidents/{incidents[0]['id']}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert len(detail["timeline"]) > 0
    assert len(detail["recommendations"]) > 0

    # Verify IOCs endpoint
    iocs_res = client.get(f"/api/iocs?run_id={run_id}")
    assert iocs_res.status_code == 200
    assert len(iocs_res.json()) > 0

    # Verify HTML report endpoint
    html_res = client.get(f"/api/reports/{run_id}/html")
    assert html_res.status_code == 200
    assert "<!DOCTYPE html>" in html_res.text
    assert "CYBERTRACE" in html_res.text

    # Verify JSON report endpoint
    json_res = client.get(f"/api/reports/{run_id}/json")
    assert json_res.status_code == 200
    assert json_res.json()["project"].startswith("CYBERTRACE")

def test_upload_valid_log_file():
    log_content = (
        "2026-10-01 10:00:00 [INFO] [10.0.0.1] [alice] LOGIN_SUCCESS: Logged in\n"
        "2026-10-01 10:10:00 [INFO] [10.0.0.1] [alice] LOGOUT: Logged out\n"
    )
    file_payload = {"file": ("uploaded_test.log", io.BytesIO(log_content.encode("utf-8")), "text/plain")}
    res = client.post("/api/logs/upload", files=file_payload)
    assert res.status_code == 200
    assert res.json()["total_events"] == 2

def test_upload_empty_file_rejected():
    file_payload = {"file": ("empty.log", io.BytesIO(b""), "text/plain")}
    res = client.post("/api/logs/upload", files=file_payload)
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()

def test_upload_unsupported_extension_rejected():
    file_payload = {"file": ("malicious.exe", io.BytesIO(b"dummy binary data"), "application/octet-stream")}
    res = client.post("/api/logs/upload", files=file_payload)
    assert res.status_code == 400
    assert "unsupported" in res.json()["detail"].lower()

def test_sample_not_found():
    res = client.post("/api/samples/analyze/nonexistent_sample.log")
    assert res.status_code == 404

def test_ui_and_static_assets():
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert "CYBERTRACE" in res_index.text

    res_css = client.get("/static/css/styles.css")
    assert res_css.status_code == 200
    assert "CYBERTRACE" in res_css.text

    res_js = client.get("/static/js/app.js")
    assert res_js.status_code == 200
    assert "CYBERTRACE" in res_js.text

