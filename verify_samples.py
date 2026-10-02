"""
Diagnostic verification script to validate all sample log files through the entire pipeline.
"""
from pathlib import Path
from app.parser.log_parser import LogParser
from app.detection.engine import DetectionEngine
from app.correlation.engine import CorrelationEngine
from app.ioc.extractor import IOCExtractor
from app.reporting.generator import ReportGenerator

engine = DetectionEngine()
samples_dir = Path("samples")

print("=" * 80)
print("CYBERTRACE END-TO-END SAMPLE VERIFICATION")
print("=" * 80)

for p in sorted(samples_dir.iterdir()):
    if not p.is_file():
        continue
    text = p.read_text(encoding="utf-8", errors="replace")
    events, warnings = LogParser.parse_content(text, p.name)
    iocs = IOCExtractor.extract_from_events(events)
    matches = engine.analyze(events)
    incidents = CorrelationEngine.correlate(events, matches)

    print(f"\n[FILE] {p.name}")
    print(f"       Events Parsed: {len(events)}")
    print(f"       Rule Matches : {len(matches)}")
    print(f"       Incidents    : {len(incidents)}")
    print(f"       IOCs Found   : {len(iocs)}")
    if warnings:
        print(f"       Warnings     : {warnings[:2]}")

    for idx, inc in enumerate(incidents, 1):
        print(f"       -> Incident #{idx:02d}: {inc['incident_code']} - {inc['title']}")
        clean_pattern = inc['attack_pattern'].encode('ascii', errors='replace').decode('ascii')
        print(f"          Risk Score  : {inc['risk_level']} ({inc['risk_score']}/100)")
        print(f"          Attack Chain: {clean_pattern}")
        print(f"          Factors     : {inc['contributing_factors']}")
        print(f"          Actions     : {inc['recommendations'][:2]}")

    # Verify report generation without exceptions
    run_meta = {
        "filename": p.name,
        "file_size": len(text),
        "total_events": len(events),
        "suspicious_events": sum(1 for e in events if e.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")),
        "total_incidents": len(incidents),
        "critical_incidents": sum(1 for i in incidents if i.get("risk_level") == "CRITICAL"),
        "max_risk_score": max([i.get("risk_score", 0) for i in incidents], default=0)
    }
    json_rep = ReportGenerator.generate_json_report(run_meta, events, incidents, iocs)
    html_rep = ReportGenerator.generate_html_report(run_meta, events, incidents, iocs)
    assert len(json_rep["project"]) > 0
    assert "<!DOCTYPE html>" in html_rep

print("\n" + "=" * 80)
print("[+] ALL SAMPLES PROCESSED SUCCESSFULLY THROUGH FULL PIPELINE WITH 0 ERRORS!")
print("=" * 80)
