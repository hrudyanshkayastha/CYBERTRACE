# Detection package
from app.detection.rules import (
    BaseRule,
    RuleMatch,
    RuleBruteForce,
    RuleLoginAfterFailures,
    RuleAccountLockout,
    RulePrivilegeEscalation,
    RuleSuspiciousExternalConnection,
)
from app.detection.engine import DetectionEngine
