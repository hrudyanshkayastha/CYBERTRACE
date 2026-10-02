"""
CYBERTRACE - Event Correlation Engine
Groups related security events and detection findings into unified Incidents.
Synthesizes chronological attack chains and calculates holistic risk posture.
Uses deterministic, transparent grouping logic suitable for viva explanation.
"""

from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict
from app.detection.rules import RuleMatch
from app.risk.scorer import RiskScorer
from app.config import CORRELATION_WINDOW_SECONDS

class CorrelationEngine:
    """Correlates individual events and rule matches into coherent security incidents."""

    @classmethod
    def correlate(
        cls,
        events: List[Dict[str, Any]],
        rule_matches: List[RuleMatch]
    ) -> List[Dict[str, Any]]:
        """
        Groups events and rule matches by entity (source IP and/or username).
        Constructs attack chains and calculates risk scores.
        """
        if not events and not rule_matches:
            return []

        # 1. Group rule matches and related events by entity key
        # Primary key priority: source_ip, then username
        entity_matches = defaultdict(list)
        for rm in rule_matches:
            key = rm.source_ip or rm.username or "GLOBAL_ANOMALY"
            entity_matches[key].append(rm)

        incidents: List[Dict[str, Any]] = []
        incident_counter = 1

        # If there are rule matches, build incidents around them
        for entity_key, matches in entity_matches.items():
            # Collect all event indices involved in these rule matches
            related_indices: Set[int] = set()
            triggered_rules: Set[str] = set()
            src_ip = None
            user = None

            for m in matches:
                triggered_rules.add(m.rule_id)
                related_indices.update(m.matched_event_indices)
                if m.source_ip and not src_ip:
                    src_ip = m.source_ip
                if m.username and not user:
                    user = m.username

            # Also correlate nearby events from same source IP or username within the event sequence
            for idx, ev in enumerate(events):
                match_ip = src_ip and (ev.get("source_ip") == src_ip)
                match_user = user and (ev.get("username") == user)
                if match_ip or match_user:
                    # Include in incident context
                    related_indices.add(idx)

            sorted_indices = sorted(list(related_indices))
            if not sorted_indices:
                continue

            # Gather correlated event records
            correlated_events = [events[i] for i in sorted_indices if 0 <= i < len(events)]
            event_types = [e.get("event_type", "OTHER") for e in correlated_events]

            # Timestamps
            timestamps = [e.get("timestamp") for e in correlated_events if e.get("timestamp")]
            first_seen = timestamps[0] if timestamps else None
            last_seen = timestamps[-1] if timestamps else None

            # Synthesize Attack Chain
            attack_chain, title, inc_type = cls._build_attack_chain(correlated_events, list(triggered_rules))

            # Multiple indicators check
            has_multi = len(triggered_rules) >= 2 or len(set(event_types)) >= 3

            # Calculate explainable risk score
            score, level, factors, recs = RiskScorer.calculate_incident_risk(
                triggered_rule_ids=list(triggered_rules),
                event_types=event_types,
                has_multiple_indicators=has_multi
            )

            incidents.append({
                "incident_code": f"INC-{incident_counter:03d}",
                "title": title,
                "incident_type": inc_type,
                "risk_score": score,
                "risk_level": level,
                "source_ip": src_ip,
                "username": user,
                "first_observed": first_seen,
                "last_observed": last_seen,
                "event_count": len(sorted_indices),
                "attack_pattern": attack_chain,
                "contributing_factors": factors,
                "recommendations": recs,
                "rules_triggered": sorted(list(triggered_rules)),
                "event_indices": sorted_indices,
            })
            incident_counter += 1

        # Fallback: if no rule matches triggered but high-severity events exist
        if not incidents:
            high_sev_indices = [
                i for i, e in enumerate(events)
                if e.get("severity") in ("HIGH", "CRITICAL")
            ]
            if high_sev_indices:
                sample_ev = events[high_sev_indices[0]]
                incidents.append({
                    "incident_code": "INC-001",
                    "title": "Uncorrelated High Severity Security Event",
                    "incident_type": sample_ev.get("event_type", "SECURITY_ALERT"),
                    "risk_score": 35,
                    "risk_level": "MEDIUM",
                    "source_ip": sample_ev.get("source_ip"),
                    "username": sample_ev.get("username"),
                    "first_observed": sample_ev.get("timestamp"),
                    "last_observed": sample_ev.get("timestamp"),
                    "event_count": len(high_sev_indices),
                    "attack_pattern": f"Isolated {sample_ev.get('event_type')}",
                    "contributing_factors": ["+35 Standalone high-severity security event observed"],
                    "recommendations": ["Investigate origin of individual elevated alert."],
                    "rules_triggered": [],
                    "event_indices": high_sev_indices,
                })

        return incidents

    @classmethod
    def _build_attack_chain(cls, correlated_events: List[Dict[str, Any]], rule_ids: List[str]) -> Tuple[str, str, str]:
        """
        Synthesizes a visual attack chain progression from the chronological events.
        Returns: (attack_pattern_string, descriptive_title, incident_type)
        """
        stages = []
        seen_stages = set()

        def add_stage(name: str):
            if name not in seen_stages:
                seen_stages.add(name)
                stages.append(name)

        has_failed = any(e.get("event_type") == "LOGIN_FAILED" for e in correlated_events)
        has_success = any(e.get("event_type") == "LOGIN_SUCCESS" for e in correlated_events)
        has_priv = any(e.get("event_type") == "PRIVILEGE_ESCALATION" for e in correlated_events)
        has_net = any(e.get("event_type") == "NETWORK_CONNECTION" for e in correlated_events)
        has_proc = any(e.get("event_type") == "PROCESS_EXECUTED" for e in correlated_events)
        has_file = any(e.get("event_type") == "FILE_CREATED" for e in correlated_events)
        has_lock = any(e.get("event_type") == "ACCOUNT_LOCKED" for e in correlated_events)

        if "RULE_001_BRUTE_FORCE" in rule_ids or (has_failed and len(correlated_events) >= 5):
            add_stage("Brute Force")
        elif has_failed:
            add_stage("Authentication Attempts")

        if has_lock:
            add_stage("Account Lockout")

        if "RULE_002_LOGIN_AFTER_FAILURES" in rule_ids or (has_failed and has_success):
            add_stage("Successful Authentication")
        elif has_success:
            add_stage("User Authentication")

        if has_priv:
            add_stage("Privilege Escalation")

        if has_proc:
            add_stage("Command Execution")

        if has_file:
            add_stage("File Artifact Creation")

        if has_net or "RULE_005_EXTERNAL_CONNECTION" in rule_ids:
            add_stage("Suspicious Network Connection")

        if not stages:
            stages = ["Observed Anomalous Activity"]

        pattern = " → ".join(stages)

        # Title & Type Synthesis
        if "Brute Force" in stages and "Privilege Escalation" in stages:
            title = "Potential Account Takeover & Privilege Escalation"
            inc_type = "ACCOUNT_COMPROMISE"
        elif "Brute Force" in stages and "Successful Authentication" in stages:
            title = "Brute-Force Followed by Successful Authentication"
            inc_type = "CREDENTIAL_COMPROMISE"
        elif "Brute Force" in stages:
            title = "Possible Brute-Force Authentication Attack"
            inc_type = "BRUTE_FORCE"
        elif "Privilege Escalation" in stages:
            title = "Potential Unauthorized Privilege Escalation"
            inc_type = "PRIVILEGE_ESCALATION"
        elif "Account Lockout" in stages:
            title = "Account Lockout Following Failed Logins"
            inc_type = "ACCOUNT_LOCKOUT"
        elif "Suspicious Network Connection" in stages:
            title = "Suspicious Outbound Network Connection"
            inc_type = "NETWORK_ANOMALY"
        else:
            title = "Correlated Suspicious Activity"
            inc_type = "SUSPICIOUS_ACTIVITY"

        return pattern, title, inc_type
