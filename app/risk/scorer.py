"""
CYBERTRACE - Explainable Risk Scoring Engine
Calculates transparent, additive risk scores (0–100) with detailed contributing factors.
Every point addition is explicitly accounted for to facilitate beginner viva explanation.
"""

from typing import List, Dict, Any, Tuple
from app.config import RISK_WEIGHTS, RISK_LEVEL_THRESHOLDS

class RiskScorer:
    """Calculates explainable risk scores and provides tailored defensive recommendations."""

    @classmethod
    def calculate_incident_risk(
        cls,
        triggered_rule_ids: List[str],
        event_types: List[str],
        has_multiple_indicators: bool
    ) -> Tuple[int, str, List[str], List[str]]:
        """
        Computes risk score, risk level, breakdown factors, and recommended SOC actions.
        Returns: (risk_score, risk_level, contributing_factors, recommendations)
        """
        score = 0
        factors: List[str] = []
        recommendations: List[str] = []

        # 1. Failed login burst
        if "RULE_001_BRUTE_FORCE" in triggered_rule_ids or event_types.count("LOGIN_FAILED") >= 5:
            pts = RISK_WEIGHTS["failed_login_burst"]
            score += pts
            factors.append(f"+{pts} Multiple failed login attempts (possible brute-force)")
            recommendations.append("Audit authentication logs and consider temporary source IP rate-limiting or blocking.")

        # 2. Successful login after failures
        if "RULE_002_LOGIN_AFTER_FAILURES" in triggered_rule_ids:
            pts = RISK_WEIGHTS["success_after_failures"]
            score += pts
            factors.append(f"+{pts} Successful login following multiple authentication failures")
            recommendations.append("Immediately verify whether user authentication was authorized or credential stuffing.")

        # 3. Account lockout
        if "RULE_003_ACCOUNT_LOCKOUT" in triggered_rule_ids or "ACCOUNT_LOCKED" in event_types:
            pts = RISK_WEIGHTS["account_lockout"]
            score += pts
            factors.append(f"+{pts} Account lockout enforced due to excessive failed attempts")
            recommendations.append("Contact the account owner to confirm legitimate activity before unlocking.")

        # 4. Privilege escalation
        if "RULE_004_PRIVILEGE_ESCALATION" in triggered_rule_ids or "PRIVILEGE_ESCALATION" in event_types:
            pts = RISK_WEIGHTS["privilege_escalation"]
            score += pts
            factors.append(f"+{pts} Privilege escalation activity detected (sudo / administrator rights)")
            recommendations.append("Review sudoers logs and active root sessions to confirm authorized administrative change.")

        # 5. Suspicious external connection
        if "RULE_005_EXTERNAL_CONNECTION" in triggered_rule_ids:
            pts = RISK_WEIGHTS["suspicious_external_connection"]
            score += pts
            factors.append(f"+{pts} Suspicious outbound connection to external IP address")
            recommendations.append("Inspect perimeter firewall and DNS logs for outbound C2 or data staging channels.")

        # 6. Multiple correlated indicators
        if has_multiple_indicators and len(factors) >= 2:
            pts = RISK_WEIGHTS["multiple_correlated_indicators"]
            score += pts
            factors.append(f"+{pts} Multiple correlated attack indicators originating from same source")
            recommendations.append("Escalate to Tier-2 SOC analyst for comprehensive incident containment.")

        # Cap score at 100
        score = min(score, 100)

        # Determine risk level
        if score >= RISK_LEVEL_THRESHOLDS["CRITICAL"]:
            level = "CRITICAL"
        elif score >= RISK_LEVEL_THRESHOLDS["HIGH"]:
            level = "HIGH"
        elif score >= RISK_LEVEL_THRESHOLDS["MEDIUM"]:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Baseline fallback recommendation if list empty
        if not recommendations:
            recommendations.append("Continue routine baseline monitoring.")

        return score, level, factors, recommendations
