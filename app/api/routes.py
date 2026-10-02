"""
CYBERTRACE - REST API Endpoints
Defines clean, well-documented FastAPI endpoints for log upload, incident retrieval,
IOC inspection, SOC metrics, and report export.
"""

import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse

from app.config import (
    MAX_UPLOAD_SIZE_BYTES,
    ALLOWED_EXTENSIONS,
    SAMPLES_DIR,
    REPORTS_DIR,
)
from app.parser.log_parser import LogParser
from app.detection.engine import DetectionEngine
from app.correlation.engine import CorrelationEngine
from app.ioc.extractor import IOCExtractor
from app.reporting.generator import ReportGenerator
from app.database.db import (
    save_analysis_run,
    get_latest_run,
    get_run_by_id,
    get_all_runs,
    get_events_for_run,
    get_incidents_for_run,
    get_incident_by_id,
    get_iocs_for_run,
    get_global_statistics,
)

router = APIRouter(prefix="/api", tags=["CyberTrace API"])
detection_engine = DetectionEngine()

def process_log_content(filename: str, content_str: str, file_size: int) -> Dict[str, Any]:
    """Core analysis workflow executed upon log upload or sample selection."""
    # 1. Parse & Normalize
    events, warnings = LogParser.parse_content(content_str, filename=filename)
    if not events:
        raise HTTPException(
            status_code=400,
            detail="No valid log events could be parsed from the provided file."
        )

    # 2. Extract IOCs
    iocs = IOCExtractor.extract_from_events(events)

    # 3. Rule-Based Security Detection
    rule_matches = detection_engine.analyze(events)

    # 4. Event Correlation & Risk Scoring
    incidents = CorrelationEngine.correlate(events, rule_matches)

    # 5. Persist to SQLite
    run_uuid = str(uuid.uuid4())
    run_id = save_analysis_run(
        run_uuid=run_uuid,
        filename=filename,
        file_size=file_size,
        events=events,
        incidents=incidents,
        iocs=iocs
    )

    return {
        "success": True,
        "message": f"Successfully processed {len(events)} events from {filename}.",
        "run_id": run_id,
        "run_uuid": run_uuid,
        "filename": filename,
        "total_events": len(events),
        "suspicious_events": sum(1 for e in events if e.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")),
        "total_incidents": len(incidents),
        "critical_incidents": sum(1 for inc in incidents if inc.get("risk_level") == "CRITICAL"),
        "max_risk_score": max([inc.get("risk_score", 0) for inc in incidents], default=0),
        "warnings": warnings[:5],
    }

@router.get("/health")
def get_health() -> Dict[str, Any]:
    """Health check endpoint to verify backend service readiness."""
    return {
        "status": "healthy",
        "service": "CYBERTRACE Incident Detection Platform",
        "version": "1.0.0"
    }

@router.get("/samples")
def list_samples() -> List[Dict[str, Any]]:
    """Lists available built-in demonstration logs."""
    samples = []
    if SAMPLES_DIR.exists():
        for file in sorted(SAMPLES_DIR.glob("*.*")):
            if file.suffix in ALLOWED_EXTENSIONS:
                samples.append({
                    "name": file.name,
                    "size_bytes": file.stat().st_size,
                    "description": {
                        "sample_clean.log": "Clean routine administrator activity without anomalies.",
                        "sample_bruteforce.log": "High-frequency SSH login failure burst from single IP.",
                        "sample_privilege_escalation.log": "User login followed by unauthorized sudo elevation.",
                        "sample_suspicious_incident.log": "Full multi-stage attack: Brute-force -> Auth -> PrivEsc -> Outbound Connection.",
                        "sample_malformed.log": "Corrupted entries and invalid timestamps testing parser resilience.",
                        "sample_web_attacks.csv": "CSV log format illustrating web authentication anomalies.",
                        "sample_cloud_events.json": "Structured JSON log format depicting audit trail."
                    }.get(file.name, "Synthetic cybersecurity test log.")
                })
    return samples

@router.post("/samples/analyze/{sample_name}")
def analyze_sample(sample_name: str) -> Dict[str, Any]:
    """Executes instant 1-click analysis on a built-in synthetic test log."""
    # Prevent path traversal
    safe_name = Path(sample_name).name
    sample_path = SAMPLES_DIR / safe_name

    if not sample_path.exists() or not sample_path.is_file():
        raise HTTPException(status_code=404, detail=f"Sample '{safe_name}' not found.")

    try:
        content = sample_path.read_text(encoding="utf-8", errors="replace")
        return process_log_content(
            filename=safe_name,
            content_str=content,
            file_size=sample_path.stat().st_size
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing sample log: {str(e)}")

@router.post("/logs/upload")
async def upload_log_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Accepts log file uploads (.log, .txt, .csv, .json), validates input safely,
    executes the SOC analysis pipeline, and stores records in SQLite.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename cannot be empty.")

    # Validate file extension
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension '{ext}'. Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    # Read content with size check
    try:
        content_bytes = await file.read()
        if len(content_bytes) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")
        if len(content_bytes) > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"File exceeds maximum allowed size of {MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB."
            )

        content_str = content_bytes.decode("utf-8", errors="replace")
        safe_filename = Path(file.filename).name
        return process_log_content(
            filename=safe_filename,
            content_str=content_str,
            file_size=len(content_bytes)
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process uploaded log: {str(e)}")

@router.get("/runs")
def list_runs() -> List[Dict[str, Any]]:
    """Returns a list of all historical analysis runs."""
    return get_all_runs()

@router.get("/runs/{run_id}")
def get_run(run_id: int) -> Dict[str, Any]:
    """Retrieves metadata for a specific analysis run."""
    run = get_run_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Analysis run #{run_id} not found.")
    return run

@router.get("/events")
def list_events(
    run_id: Optional[int] = Query(None),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
) -> Dict[str, Any]:
    """
    Returns normalized events with search, severity filtering, and pagination.
    Defaults to the latest run if run_id is omitted.
    """
    target_run_id = run_id
    if target_run_id is None:
        latest = get_latest_run()
        target_run_id = latest["id"] if latest else None

    if not target_run_id:
        return {"total": 0, "events": []}

    all_events = get_events_for_run(target_run_id)

    # Filtering
    filtered = all_events
    if severity:
        sev_upper = severity.upper()
        filtered = [e for e in filtered if e.get("severity") == sev_upper]
    if event_type:
        et_upper = event_type.upper()
        filtered = [e for e in filtered if e.get("event_type") == et_upper]
    if search:
        s_lower = search.lower()
        filtered = [
            e for e in filtered
            if s_lower in (e.get("message", "") or "").lower()
            or s_lower in (e.get("source_ip", "") or "").lower()
            or s_lower in (e.get("username", "") or "").lower()
        ]

    total_count = len(filtered)
    paginated = filtered[offset: offset + limit]

    return {
        "run_id": target_run_id,
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "events": paginated
    }

@router.get("/incidents")
def list_incidents(run_id: Optional[int] = Query(None)) -> List[Dict[str, Any]]:
    """Returns all correlated incidents for a given analysis run (or latest)."""
    target_run_id = run_id
    if target_run_id is None:
        latest = get_latest_run()
        target_run_id = latest["id"] if latest else None

    if not target_run_id:
        return []

    return get_incidents_for_run(target_run_id)

@router.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: int) -> Dict[str, Any]:
    """Returns detailed incident breakdown, chronological timeline, and recommendations."""
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident #{incident_id} not found.")
    return inc

@router.get("/iocs")
def list_iocs(
    run_id: Optional[int] = Query(None),
    ioc_type: Optional[str] = Query(None),
    suspicious_only: bool = Query(False)
) -> List[Dict[str, Any]]:
    """Returns observed and suspicious IOCs for a run."""
    target_run_id = run_id
    if target_run_id is None:
        latest = get_latest_run()
        target_run_id = latest["id"] if latest else None

    if not target_run_id:
        return []

    iocs = get_iocs_for_run(target_run_id)
    if ioc_type:
        iocs = [i for i in iocs if i.get("ioc_type") == ioc_type]
    if suspicious_only:
        iocs = [i for i in iocs if i.get("is_suspicious")]

    return iocs

@router.get("/statistics")
def get_statistics(run_id: Optional[int] = Query(None)) -> Dict[str, Any]:
    """Returns high-level SOC dashboard metrics."""
    target_run_id = run_id
    if target_run_id is None:
        latest = get_latest_run()
        target_run_id = latest["id"] if latest else None

    return get_global_statistics(target_run_id)

@router.get("/reports/{run_id}/json")
def export_json_report(run_id: int):
    """Exports a comprehensive JSON report for offline audit."""
    run = get_run_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Analysis run #{run_id} not found.")

    events = get_events_for_run(run_id)
    incidents = get_incidents_for_run(run_id)
    iocs = get_iocs_for_run(run_id)

    report_dict = ReportGenerator.generate_json_report(run, events, incidents, iocs)
    return JSONResponse(
        content=report_dict,
        headers={"Content-Disposition": f'attachment; filename="cybertrace_report_{run_id}.json"'}
    )

@router.get("/reports/{run_id}/html", response_class=HTMLResponse)
def export_html_report(run_id: int):
    """Exports an executive, standalone printable HTML report."""
    run = get_run_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Analysis run #{run_id} not found.")

    events = get_events_for_run(run_id)
    incidents = get_incidents_for_run(run_id)
    # Populate timeline for incidents
    for inc in incidents:
        full_inc = get_incident_by_id(inc["id"])
        if full_inc:
            inc["timeline"] = full_inc.get("timeline", [])
    iocs = get_iocs_for_run(run_id)

    html_content = ReportGenerator.generate_html_report(run, events, incidents, iocs)
    return HTMLResponse(content=html_content)
