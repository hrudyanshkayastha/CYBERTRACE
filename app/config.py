"""
CYBERTRACE - Configuration Settings
Defines configurable thresholds, risk weights, and system paths.
Every threshold can be easily explained during an academic viva.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "cybertrace.db"
REPORTS_DIR = BASE_DIR / "reports"
SAMPLES_DIR = BASE_DIR / "samples"

# Ingestion Constraints
MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit for educational safety
ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}

# Security Detection Rule Thresholds
# All time windows are in seconds.
BRUTE_FORCE_THRESHOLD = 5                 # >= 5 failed logins within window
BRUTE_FORCE_WINDOW_SECONDS = 300          # 5 minutes window

LOGIN_AFTER_FAILURES_THRESHOLD = 3        # >= 3 failed logins prior to a success
LOGIN_AFTER_FAILURES_WINDOW = 600         # 10 minutes window

ACCOUNT_LOCKOUT_THRESHOLD = 3             # >= 3 failed logins prior to lockout
ACCOUNT_LOCKOUT_WINDOW = 600              # 10 minutes window

CORRELATION_WINDOW_SECONDS = 1800         # 30 minutes correlation window

# Risk Scoring Model (Transparent Additive Weights)
# Score capped at 100.
RISK_WEIGHTS = {
    "failed_login_burst": 20,
    "success_after_failures": 20,
    "account_lockout": 10,
    "privilege_escalation": 25,
    "suspicious_external_connection": 20,
    "multiple_correlated_indicators": 15,
}

RISK_LEVEL_THRESHOLDS = {
    "CRITICAL": 80,  # 80 - 100
    "HIGH": 60,      # 60 - 79
    "MEDIUM": 30,    # 30 - 59
    "LOW": 0         # 0 - 29
}

# Standard Academic SOC Disclaimer
SOC_DISCLAIMER = (
    "This system performs rule-based security event analysis. "
    "Detection results indicate potentially suspicious activity and do not prove malicious intent."
)
