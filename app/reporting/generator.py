"""
CYBERTRACE - Incident Report Generator
Generates structured JSON reports and standalone styled HTML executive reports.
Includes executive summary, event statistics, correlated incidents, risk breakdowns,
observed IOCs, attack chains, and mandatory academic SOC disclaimers.
"""

import json
from datetime import datetime
from typing import Dict, Any, List
from app.config import SOC_DISCLAIMER

class ReportGenerator:
    """Generates standalone JSON and HTML incident investigation reports."""

    @classmethod
    def generate_json_report(
        cls,
        run_data: Dict[str, Any],
        events: List[Dict[str, Any]],
        incidents: List[Dict[str, Any]],
        iocs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Produces a comprehensive structured dictionary for JSON export."""
        return {
            "project": "CYBERTRACE: Security Incident Detection & Investigation System",
            "report_version": "1.0",
            "generated_at": datetime.now().isoformat(),
            "disclaimer": SOC_DISCLAIMER,
            "target_artifact": {
                "filename": run_data.get("filename"),
                "file_size_bytes": run_data.get("file_size"),
                "uploaded_at": run_data.get("uploaded_at"),
            },
            "statistics": {
                "total_events": run_data.get("total_events", len(events)),
                "suspicious_events": run_data.get("suspicious_events", 0),
                "total_incidents": run_data.get("total_incidents", len(incidents)),
                "critical_incidents": run_data.get("critical_incidents", 0),
                "max_risk_score": run_data.get("max_risk_score", 0),
                "total_observed_iocs": len(iocs),
            },
            "incidents": incidents,
            "observed_iocs": iocs,
            "events_sample": events[:50],  # First 50 normalized events for sample audit
            "academic_limitations": [
                "Rule-based detection relies on deterministic thresholds and does not account for low-and-slow evasions.",
                "Log data is synthetic or simulated for educational demonstration.",
                "Network analysis does not inspect encrypted payload contents."
            ]
        }

    @classmethod
    def generate_html_report(
        cls,
        run_data: Dict[str, Any],
        events: List[Dict[str, Any]],
        incidents: List[Dict[str, Any]],
        iocs: List[Dict[str, Any]]
    ) -> str:
        """Renders an executive, self-contained HTML incident report."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        fn = run_data.get("filename", "Unknown")
        total_ev = run_data.get("total_events", len(events))
        susp_ev = run_data.get("suspicious_events", 0)
        tot_inc = run_data.get("total_incidents", len(incidents))
        max_risk = max([inc.get("risk_score", 0) for inc in incidents], default=run_data.get("max_risk_score", 0))

        # Build Incident HTML blocks
        incidents_html = ""
        for inc in incidents:
            r_level = inc.get("risk_level", "LOW")
            color_class = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#10b981"
            }.get(r_level, "#64748b")

            factors_li = "".join(f"<li><code>{f}</code></li>" for f in inc.get("contributing_factors", []))
            recs_li = "".join(f"<li>{r}</li>" for r in inc.get("recommendations", []))
            rules_li = "".join(f"<span class='badge-rule'>{rule}</span> " for rule in inc.get("rules_triggered", []))

            # Incident Timeline snippet
            inc_events = [e for e in inc.get("timeline", [])] if inc.get("timeline") else []
            timeline_rows = ""
            for ev in inc_events[:10]:
                timeline_rows += f"""
                <tr>
                    <td>{ev.get('timestamp') or 'N/A'}</td>
                    <td><strong>{ev.get('event_type')}</strong></td>
                    <td>{ev.get('source_ip') or '-'}</td>
                    <td>{ev.get('username') or '-'}</td>
                    <td>{ev.get('message')}</td>
                </tr>
                """

            timeline_block = f"""
            <div style="margin-top:12px;">
                <h4 style="margin-bottom:6px;">Incident Timeline ({len(inc_events)} events):</h4>
                <table class="report-table" style="font-size:12px;">
                    <thead>
                        <tr><th>Timestamp</th><th>Event Type</th><th>Source IP</th><th>User</th><th>Message</th></tr>
                    </thead>
                    <tbody>{timeline_rows or '<tr><td colspan="5">Timeline linked events stored in audit log.</td></tr>'}</tbody>
                </table>
            </div>
            """ if timeline_rows else ""

            incidents_html += f"""
            <div class="incident-card" style="border-left: 5px solid {color_class};">
                <div class="incident-header">
                    <div>
                        <span class="incident-id">{inc.get('incident_code')}</span>
                        <h3 style="display:inline; margin-left:10px;">{inc.get('title')}</h3>
                    </div>
                    <div style="text-align:right;">
                        <span class="risk-badge" style="background:{color_class};">{r_level} ({inc.get('risk_score')}/100)</span>
                    </div>
                </div>

                <div class="incident-meta-grid">
                    <div><strong>Source IP:</strong> {inc.get('source_ip') or 'N/A'}</div>
                    <div><strong>Username:</strong> {inc.get('username') or 'N/A'}</div>
                    <div><strong>First Seen:</strong> {inc.get('first_observed') or 'N/A'}</div>
                    <div><strong>Last Seen:</strong> {inc.get('last_observed') or 'N/A'}</div>
                    <div><strong>Related Events:</strong> {inc.get('event_count')}</div>
                    <div><strong>Incident Type:</strong> <code>{inc.get('incident_type')}</code></div>
                </div>

                <div style="margin-top:12px;">
                    <strong>Observed Attack Pattern:</strong>
                    <div class="attack-pattern-box">{inc.get('attack_pattern')}</div>
                </div>

                <div style="margin-top:12px;">
                    <strong>Triggered Rules:</strong><br/>
                    {rules_li or '<em>None</em>'}
                </div>

                <div style="margin-top:12px;">
                    <strong>Risk Score Breakdown:</strong>
                    <ul class="factors-list">{factors_li or '<li>Standard baseline event</li>'}</ul>
                </div>

                <div style="margin-top:12px;">
                    <strong>Recommended Defensive Actions:</strong>
                    <ul class="recs-list">{recs_li}</ul>
                </div>

                {timeline_block}
            </div>
            """

        # Build IOC Table HTML
        ioc_rows = ""
        for ioc in iocs[:30]:
            susp_badge = "<span style='color:#ef4444;font-weight:bold;'>Suspicious</span>" if ioc.get("is_suspicious") else "<span style='color:#10b981;'>Observed</span>"
            ioc_rows += f"""
            <tr>
                <td><span class="badge-type">{ioc.get('ioc_type')}</span></td>
                <td><code>{ioc.get('ioc_value')}</code></td>
                <td>{susp_badge}</td>
                <td>{ioc.get('context')}</td>
                <td>{ioc.get('first_seen') or 'N/A'}</td>
            </tr>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CYBERTRACE Incident Investigation Report - {fn}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --accent: #38bdf8;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            margin: 0 0 6px 0;
            color: var(--accent);
            letter-spacing: -0.5px;
        }}
        .header .meta {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        .disclaimer-box {{
            background: #1e1b4b;
            border-left: 4px solid #818cf8;
            padding: 14px 18px;
            border-radius: 6px;
            margin-bottom: 24px;
            font-size: 13px;
            color: #c7d2fe;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 14px;
            margin-bottom: 28px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            text-align: center;
        }}
        .stat-num {{
            font-size: 26px;
            font-weight: bold;
            color: var(--accent);
        }}
        .stat-label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
        }}
        .section-title {{
            font-size: 20px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
            margin-top: 32px;
            margin-bottom: 16px;
            color: #e2e8f0;
        }}
        .incident-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .incident-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            margin-bottom: 14px;
        }}
        .incident-id {{
            background: #0284c7;
            color: #fff;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        .risk-badge {{
            color: #fff;
            padding: 5px 12px;
            border-radius: 12px;
            font-weight: bold;
            font-size: 13px;
        }}
        .incident-meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 8px;
            background: #0f172a;
            padding: 12px;
            border-radius: 6px;
            font-size: 13px;
        }}
        .attack-pattern-box {{
            background: #0f172a;
            border: 1px dashed var(--accent);
            color: var(--accent);
            padding: 10px 14px;
            border-radius: 6px;
            margin-top: 6px;
            font-family: monospace;
            font-size: 13px;
        }}
        .badge-rule {{
            background: #334155;
            color: #cbd5e1;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 11px;
            font-family: monospace;
        }}
        .factors-list {{
            margin: 6px 0 0 18px;
            padding: 0;
            font-size: 13px;
            color: #fbbf24;
        }}
        .recs-list {{
            margin: 6px 0 0 18px;
            padding: 0;
            font-size: 13px;
            color: #38bdf8;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            background: var(--card-bg);
            border-radius: 8px;
            overflow: hidden;
        }}
        .report-table th, .report-table td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        .report-table th {{
            background: #0f172a;
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
        }}
        .badge-type {{
            background: #334155;
            color: #94a3b8;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
        }}
        .limitations-box {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            font-size: 13px;
            color: var(--text-muted);
        }}
        .print-btn {{
            background: var(--accent);
            color: #0f172a;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            float: right;
        }}
        @media print {{
            .print-btn {{ display: none; }}
            body {{ background: #fff; color: #000; padding: 0; }}
            .incident-card, .stat-card, .disclaimer-box, .report-table {{
                background: #fff; color: #000; border-color: #ccc;
            }}
            .incident-meta-grid, .attack-pattern-box {{ background: #f8fafc; color: #000; }}
            .stat-num {{ color: #0284c7; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <button class="print-btn" onclick="window.print()">Print / Save PDF</button>
        <div class="header">
            <h1>CYBERTRACE</h1>
            <div style="font-size:16px; font-weight:600; color:#38bdf8; margin-bottom:4px;">Security Incident Detection & Investigation Report</div>
            <div class="meta">
                Analyzed Target: <strong>{fn}</strong> &bull; Generated: {now_str} &bull; Classification: Educational SOC Investigation
            </div>
        </div>

        <div class="disclaimer-box">
            <strong>System Notice & Academic Disclaimer:</strong><br/>
            {SOC_DISCLAIMER}
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-num">{total_ev}</div>
                <div class="stat-label">Total Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-num">{susp_ev}</div>
                <div class="stat-label">Suspicious Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-num">{tot_inc}</div>
                <div class="stat-label">Correlated Incidents</div>
            </div>
            <div class="stat-card">
                <div class="stat-num">{max_risk} / 100</div>
                <div class="stat-label">Max Risk Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-num">{len(iocs)}</div>
                <div class="stat-label">Observed IOCs</div>
            </div>
        </div>

        <h2 class="section-title">Correlated Security Incidents</h2>
        {incidents_html or '<p style="color:var(--text-muted)">No security incidents were correlated in this analysis run.</p>'}

        <h2 class="section-title">Indicators of Compromise (IOC) Findings</h2>
        <table class="report-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Observed Value</th>
                    <th>Assessment</th>
                    <th>Operational Context</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                {ioc_rows or '<tr><td colspan="5">No Indicators of Compromise observed.</td></tr>'}
            </tbody>
        </table>

        <h2 class="section-title">Methodology & System Limitations</h2>
        <div class="limitations-box">
            <ul>
                <li><strong>Deterministic Rule-Based Detection:</strong> Rules evaluate configured thresholds (e.g., 5 failures in 300s). Low-frequency attacks spanning hours may remain unflagged.</li>
                <li><strong>Log Dependency:</strong> Detection quality relies strictly on the fidelity and completeness of supplied log headers and event records.</li>
                <li><strong>Synthetic Demonstration Data:</strong> Sample logs are synthetically generated for educational demonstration; no live malicious infrastructure is targeted.</li>
                <li><strong>Defensive Scope:</strong> Designed solely for detection, correlation, and defensive containment analysis.</li>
            </ul>
        </div>

        <div style="text-align:center; margin-top:30px; font-size:12px; color:var(--text-muted);">
            Generated by CYBERTRACE &bull; Third-Year BSc Cybersecurity Project
        </div>
    </div>
</body>
</html>
"""
        return html_template
