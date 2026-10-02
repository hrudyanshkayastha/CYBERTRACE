"""
Unit tests for explainable risk scoring system.
"""

from app.risk.scorer import RiskScorer

def test_risk_scorer_single_rule():
    score, level, factors, recs = RiskScorer.calculate_incident_risk(
        triggered_rule_ids=["RULE_001_BRUTE_FORCE"],
        event_types=["LOGIN_FAILED"],
        has_multiple_indicators=False
    )
    assert score == 20
    assert level == "LOW"
    assert len(factors) == 1
    assert "+20" in factors[0]
    assert len(recs) > 0

def test_risk_scorer_multi_step_attack():
    score, level, factors, recs = RiskScorer.calculate_incident_risk(
        triggered_rule_ids=[
            "RULE_001_BRUTE_FORCE",
            "RULE_002_LOGIN_AFTER_FAILURES",
            "RULE_004_PRIVILEGE_ESCALATION",
            "RULE_005_EXTERNAL_CONNECTION"
        ],
        event_types=["LOGIN_FAILED", "LOGIN_SUCCESS", "PRIVILEGE_ESCALATION", "NETWORK_CONNECTION"],
        has_multiple_indicators=True
    )
    # Expected: 20 + 20 + 25 + 20 + 15 (multiple indicators) = 100
    assert score == 100
    assert level == "CRITICAL"
    assert len(factors) == 5
    assert any("+20" in f for f in factors)
    assert any("+25" in f for f in factors)
    assert any("+15" in f for f in factors)

def test_risk_scorer_capping_at_100():
    # Even if scores sum to > 100, max score is strictly 100
    score, level, factors, recs = RiskScorer.calculate_incident_risk(
        triggered_rule_ids=[
            "RULE_001_BRUTE_FORCE",
            "RULE_002_LOGIN_AFTER_FAILURES",
            "RULE_003_ACCOUNT_LOCKOUT",
            "RULE_004_PRIVILEGE_ESCALATION",
            "RULE_005_EXTERNAL_CONNECTION"
        ],
        event_types=["LOGIN_FAILED", "LOGIN_SUCCESS", "ACCOUNT_LOCKED", "PRIVILEGE_ESCALATION", "NETWORK_CONNECTION"],
        has_multiple_indicators=True
    )
    assert score <= 100
    assert level == "CRITICAL"

def test_risk_level_boundaries():
    # Low: 0-29
    s1, l1, _, _ = RiskScorer.calculate_incident_risk(["RULE_003_ACCOUNT_LOCKOUT"], ["ACCOUNT_LOCKED"], False)
    assert s1 == 10 and l1 == "LOW"

    # Medium: 30-59
    s2, l2, _, _ = RiskScorer.calculate_incident_risk(["RULE_001_BRUTE_FORCE", "RULE_003_ACCOUNT_LOCKOUT"], ["LOGIN_FAILED", "ACCOUNT_LOCKED"], False)
    assert s2 == 30 and l2 == "MEDIUM"

    # High: 60-79
    s3, l3, _, _ = RiskScorer.calculate_incident_risk(
        ["RULE_001_BRUTE_FORCE", "RULE_002_LOGIN_AFTER_FAILURES", "RULE_004_PRIVILEGE_ESCALATION"],
        ["LOGIN_FAILED", "LOGIN_SUCCESS", "PRIVILEGE_ESCALATION"],
        False
    )
    assert s3 == 65 and l3 == "HIGH"
