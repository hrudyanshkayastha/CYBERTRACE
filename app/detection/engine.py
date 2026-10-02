"""
CYBERTRACE - Detection Engine
Coordinates the evaluation of all registered security detection rules.
Returns aggregated rule matches and flags suspicious events.
"""

from typing import List, Dict, Any
from app.detection.rules import (
    BaseRule,
    RuleMatch,
    RuleBruteForce,
    RuleLoginAfterFailures,
    RuleAccountLockout,
    RulePrivilegeEscalation,
    RuleSuspiciousExternalConnection,
)

class DetectionEngine:
    """Executes deterministic security rules against normalized events."""

    def __init__(self, rules: List[BaseRule] = None):
        self.rules = rules or [
            RuleBruteForce(),
            RuleLoginAfterFailures(),
            RuleAccountLockout(),
            RulePrivilegeEscalation(),
            RuleSuspiciousExternalConnection(),
        ]

    def analyze(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        """Runs each active rule against the event stream and returns all matches."""
        all_matches: List[RuleMatch] = []
        for rule in self.rules:
            matches = rule.evaluate(events)
            all_matches.extend(matches)

        # Update event severity if matched by high-severity rule
        for match in all_matches:
            for idx in match.matched_event_indices:
                if 0 <= idx < len(events):
                    curr_sev = events[idx].get("severity", "LOW")
                    if match.severity == "CRITICAL":
                        events[idx]["severity"] = "CRITICAL"
                    elif match.severity == "HIGH" and curr_sev != "CRITICAL":
                        events[idx]["severity"] = "HIGH"
                    elif match.severity == "MEDIUM" and curr_sev in ("LOW", "INFO"):
                        events[idx]["severity"] = "MEDIUM"

        return all_matches
