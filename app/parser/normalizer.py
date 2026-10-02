"""
CYBERTRACE - Event Normalizer
Transforms heterogeneous log records into a standardized canonical event representation.
Ensures beginner-friendly consistency and robust missing-value handling (null instead of guessing).
"""

import re
import ipaddress
from datetime import datetime
from typing import Dict, Any, Optional

# Supported canonical event types
VALID_EVENT_TYPES = {
    "LOGIN_FAILED",
    "LOGIN_SUCCESS",
    "ACCOUNT_LOCKED",
    "PRIVILEGE_ESCALATION",
    "PASSWORD_CHANGED",
    "PROCESS_EXECUTED",
    "FILE_CREATED",
    "NETWORK_CONNECTION",
    "LOGOUT",
    "OTHER",
}

# Default severity mappings based on event impact
DEFAULT_SEVERITY_MAP = {
    "LOGIN_FAILED": "LOW",
    "LOGIN_SUCCESS": "LOW",
    "LOGOUT": "LOW",
    "ACCOUNT_LOCKED": "MEDIUM",
    "PASSWORD_CHANGED": "LOW",
    "FILE_CREATED": "LOW",
    "PROCESS_EXECUTED": "MEDIUM",
    "NETWORK_CONNECTION": "MEDIUM",
    "PRIVILEGE_ESCALATION": "HIGH",
    "OTHER": "LOW",
}

def normalize_timestamp(ts_str: Optional[str]) -> Optional[str]:
    """
    Normalizes timestamps to ISO-8601 (YYYY-MM-DDTHH:MM:SS) format.
    Handles ISO dates, standard YYYY-MM-DD HH:MM:SS, and syslog 'Oct 01 10:31:02' formats.
    Returns None if timestamp cannot be parsed.
    """
    if not ts_str or not isinstance(ts_str, str):
        return None

    cleaned = ts_str.strip()
    # Try ISO or standard SQL formats
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(cleaned, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass

    # Syslog format: "Oct  1 10:31:02" or "Oct 01 10:31:02"
    syslog_match = re.match(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})", cleaned)
    if syslog_match:
        try:
            month_str, day_str, time_str = syslog_match.groups()
            curr_year = datetime.now().year
            full_str = f"{curr_year} {month_str} {int(day_str):02d} {time_str}"
            dt = datetime.strptime(full_str, "%Y %b %d %H:%M:%S")
            return dt.strftime("%Y-%m-%dT%H:%M:%S")
        except Exception:
            pass

    return None

def infer_event_type(raw_type: Optional[str], message: str = "") -> str:
    """
    Infers the canonical event type using the provided type and message content.
    Uses deterministic keyword matching.
    """
    combined = f"{raw_type or ''} {message}".upper()

    if re.search(r"\b(ACCOUNT[_\s-]?LOCKED|USER[_\s-]?LOCKED|MAX[_\s-]?RETRIES|LOCKOUT)\b", combined):
        return "ACCOUNT_LOCKED"
    if re.search(r"\b(PRIVILEGE[_\s-]?ESCALATION|SUDO|SU[_\s-]ROOT|RUNAS|ELEVAT)\b", combined):
        return "PRIVILEGE_ESCALATION"
    if (
        re.search(r"\b(LOGIN[_\s-]?FAILED|FAILED[_\s-]?LOGIN|FAILED[_\s-]?PASSWORD|AUTH[_\s-]?FAIL|AUTHENTICATION[_\s-]?FAILED|INVALID[_\s-]?PASSWORD)\b", combined)
        or (re.search(r"\b(FAIL|FAILED|FAILURE|INVALID)\b", combined) and re.search(r"\b(LOGIN|PASSWORD|AUTH|CREDENTIAL)\b", combined))
    ):
        return "LOGIN_FAILED"
    if (
        re.search(r"\b(LOGIN[_\s-]?SUCCESS|ACCEPTED[_\s-]?PASSWORD|ACCEPTED[_\s-]?PUBLICKEY|AUTH[_\s-]?SUCCESS|SUCCESSFUL[_\s-]?LOGIN)\b", combined)
        or (re.search(r"\b(SUCCESS|SUCCESSFUL|ACCEPTED)\b", combined) and re.search(r"\b(LOGIN|PASSWORD|AUTH|AUTHENTICATION)\b", combined))
    ):
        return "LOGIN_SUCCESS"
    if re.search(r"\b(PASSWORD[_\s-]?CHANGED|PASSWD|PASSWORD[_\s-]?UPDATE)\b", combined):
        return "PASSWORD_CHANGED"
    if re.search(r"\b(FILE[_\s-]?CREATED|TOUCH|CREATED[_\s-]?FILE|NEW[_\s-]?FILE)\b", combined):
        return "FILE_CREATED"
    if re.search(r"\b(NETWORK[_\s-]?CONNECTION|OUTBOUND[_\s-]?CONNECTION|CONNECT|TCP|UFW|FIREWALL)\b", combined):
        return "NETWORK_CONNECTION"
    if re.search(r"\b(PROCESS[_\s-]?EXECUTED|EXECVE|PROC[_\s-]?START|SPAWNED|COMMAND)\b", combined):
        return "PROCESS_EXECUTED"
    if re.search(r"\b(LOGOUT|LOGGED[_\s-]?OUT|SESSION[_\s-]?CLOSED|DISCONNECT)\b", combined):
        return "LOGOUT"

    return "OTHER"

def normalize_event(raw_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes a dictionary of raw extracted attributes into the standard schema:
    {
        "timestamp": ISO or null,
        "source_ip": IP or null,
        "username": username or null,
        "event_type": Canonical string,
        "message": non-empty string,
        "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "raw_log": string or null,
        "extra_data": dict
    }
    """
    # 1. Timestamp normalization
    ts = normalize_timestamp(raw_dict.get("timestamp"))

    # 2. IP normalization
    source_ip = raw_dict.get("source_ip")
    if source_ip:
        source_ip = str(source_ip).strip()
        try:
            ipaddress.IPv4Address(source_ip)
        except ValueError:
            source_ip = None

    # 3. Username normalization
    username = raw_dict.get("username")
    if username:
        username = str(username).strip()
        if not username or username.lower() in ("none", "null", "unknown", "-"):
            username = None

    # 4. Message & Raw
    message = str(raw_dict.get("message") or raw_dict.get("details") or "").strip()
    raw_log = raw_dict.get("raw_log")
    if not message and raw_log:
        message = str(raw_log).strip()

    # 5. Event Type
    raw_event_type = raw_dict.get("event_type")
    if raw_event_type and str(raw_event_type).upper() in VALID_EVENT_TYPES:
        event_type = str(raw_event_type).upper()
    else:
        event_type = infer_event_type(str(raw_event_type) if raw_event_type else None, message)

    # 6. Severity
    raw_sev = str(raw_dict.get("severity") or "").upper()
    if raw_sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        severity = raw_sev
    else:
        severity = DEFAULT_SEVERITY_MAP.get(event_type, "LOW")

    extra_data = raw_dict.get("extra_data") or {}
    if not isinstance(extra_data, dict):
        extra_data = {}

    return {
        "timestamp": ts,
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "message": message or "Security event recorded",
        "severity": severity,
        "raw_log": str(raw_log) if raw_log is not None else None,
        "extra_data": extra_data,
    }
