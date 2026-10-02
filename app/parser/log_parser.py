"""
CYBERTRACE - Multi-Format Log Parser
Parses .log, .txt, .csv, and .json log files into normalized security events.
Engineered for beginner readability and robust defensive error resilience.
Never crashes on corrupt, empty, or malformed input.
"""

import re
import csv
import json
import io
from typing import List, Dict, Any, Tuple
from app.parser.normalizer import normalize_event

# Regular expressions for text log parsing
# 1. Bracketed format:
# 2026-10-01 10:31:02 [LEVEL] [IP] [USER] EVENT_TYPE: Message
BRACKETED_REGEX = re.compile(
    r"^(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?:\[(?P<severity>[A-Za-z]+)\]\s+)?"
    r"(?:\[(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|-)\]\s+)?"
    r"(?:\[(?P<username>[^\]]+)\]\s+)?"
    r"(?:(?P<event_type>[A-Za-z_-]+):\s*)?"
    r"(?P<message>.*)$"
)

# 2. Syslog / Auth.log formats
SYSLOG_PREFIX_REGEX = re.compile(
    r"^(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s]+)\s+"
    r"(?P<daemon>[a-zA-Z0-9_\-\.]+)(?:\[\d+\])?:\s+"
    r"(?P<content>.*)$"
)

# Patterns within syslog messages
SSHD_FAILED_REGEX = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user\s+)?(?P<user>[^\s]+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
SSHD_ACCEPTED_REGEX = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>[^\s]+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
SUDO_REGEX = re.compile(
    r"(?P<user>[^\s]+)\s+:\s+TTY=.*COMMAND=(?P<cmd>.*)"
)
UFW_FIREWALL_REGEX = re.compile(
    r".*SRC=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+DST=(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)

# Generic fallback pattern
GENERIC_TIMESTAMP_REGEX = re.compile(
    r"(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2})"
)
IPV4_REGEX = re.compile(
    r"\b(?P<ip>(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b"
)

class LogParser:
    """Multi-format resilient log parsing engine."""

    @classmethod
    def parse_content(cls, raw_content: str, filename: str = "") -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parses raw text content into a list of normalized events.
        Returns: (normalized_events_list, parsing_warnings_list)
        """
        if not raw_content or not raw_content.strip():
            return [], ["Uploaded file is empty."]

        fn_lower = filename.lower()
        content_stripped = raw_content.strip()

        # Route by extension or auto-detection
        if fn_lower.endswith(".json") or content_stripped.startswith(("[", "{")):
            return cls._parse_json(content_stripped)
        elif fn_lower.endswith(".csv") or ("," in content_stripped.split("\n")[0] and "\n" in content_stripped):
            return cls._parse_csv(content_stripped)
        else:
            return cls._parse_text_lines(content_stripped)

    @classmethod
    def _parse_json(cls, content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parses standard JSON array or JSON Lines."""
        events: List[Dict[str, Any]] = []
        warnings: List[str] = []

        # Attempt full JSON parse (array or object)
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        item["raw_log"] = json.dumps(item)
                        events.append(normalize_event(item))
                    else:
                        warnings.append(f"Ignored non-object JSON item: {str(item)[:50]}")
                return events, warnings
            elif isinstance(parsed, dict):
                parsed["raw_log"] = json.dumps(parsed)
                return [normalize_event(parsed)], warnings
        except json.JSONDecodeError:
            pass

        # Fallback to JSON Lines (one JSON object per line)
        for line_no, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    item["raw_log"] = line
                    events.append(normalize_event(item))
                else:
                    warnings.append(f"Line {line_no}: JSON element is not an object.")
            except json.JSONDecodeError:
                # If a line fails JSON, treat as text line
                fallback_event = cls._parse_single_text_line(line)
                events.append(normalize_event(fallback_event))
                warnings.append(f"Line {line_no}: Malformed JSON line parsed via text fallback.")

        return events, warnings

    @classmethod
    def _parse_csv(cls, content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parses CSV with header resolution and field mapping."""
        events: List[Dict[str, Any]] = []
        warnings: List[str] = []

        try:
            reader = csv.DictReader(io.StringIO(content))
            # Normalize column names to lowercase with underscores
            fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]
            
            # Map common column aliases
            col_map = {}
            for original in (reader.fieldnames or []):
                cleaned = original.strip().lower().replace(" ", "_")
                if cleaned in ("timestamp", "time", "date", "datetime", "logged_at"):
                    col_map["timestamp"] = original
                elif cleaned in ("source_ip", "src_ip", "ip", "client_ip", "remote_ip"):
                    col_map["source_ip"] = original
                elif cleaned in ("username", "user", "account", "user_id"):
                    col_map["username"] = original
                elif cleaned in ("event_type", "action", "event", "type"):
                    col_map["event_type"] = original
                elif cleaned in ("message", "msg", "details", "description"):
                    col_map["message"] = original
                elif cleaned in ("severity", "level", "priority"):
                    col_map["severity"] = original

            for line_no, row in enumerate(reader, start=2):
                if not any(row.values()):
                    continue
                raw_dict = {
                    "timestamp": row.get(col_map.get("timestamp", "timestamp")),
                    "source_ip": row.get(col_map.get("source_ip", "source_ip")),
                    "username": row.get(col_map.get("username", "username")),
                    "event_type": row.get(col_map.get("event_type", "event_type")),
                    "message": row.get(col_map.get("message", "message")),
                    "severity": row.get(col_map.get("severity", "severity")),
                    "raw_log": json.dumps(row),
                    "extra_data": {k: v for k, v in row.items() if k not in col_map.values()}
                }
                events.append(normalize_event(raw_dict))

        except Exception as e:
            warnings.append(f"CSV parsing error: {str(e)}. Attempting line fallback.")
            return cls._parse_text_lines(content)

        return events, warnings

    @classmethod
    def _parse_text_lines(cls, content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parses line-by-line text and syslog logs."""
        events: List[Dict[str, Any]] = []
        warnings: List[str] = []

        for line_no, line in enumerate(content.splitlines(), start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                parsed_dict = cls._parse_single_text_line(line_str)
                events.append(normalize_event(parsed_dict))
            except Exception as e:
                # Absolute guarantee: no crash
                events.append(normalize_event({
                    "raw_log": line_str,
                    "message": f"Malformed log entry: {line_str}",
                    "event_type": "OTHER",
                    "severity": "LOW"
                }))
                warnings.append(f"Line {line_no} parsing notice: {str(e)}")

        return events, warnings

    @classmethod
    def _parse_single_text_line(cls, line: str) -> Dict[str, Any]:
        """Attempts bracketed, syslog, and fallback regex patterns on a line."""
        # 1. Bracketed structured format
        match_bracket = BRACKETED_REGEX.match(line)
        if match_bracket:
            data = match_bracket.groupdict()
            return {
                "timestamp": data.get("timestamp"),
                "source_ip": data.get("source_ip") if data.get("source_ip") != "-" else None,
                "username": data.get("username") if data.get("username") != "-" else None,
                "event_type": data.get("event_type"),
                "severity": data.get("severity"),
                "message": data.get("message") or line,
                "raw_log": line
            }

        # 2. Syslog / Auth.log format
        match_syslog = SYSLOG_PREFIX_REGEX.match(line)
        if match_syslog:
            sd = match_syslog.groupdict()
            ts = sd.get("timestamp")
            daemon = sd.get("daemon")
            content = sd.get("content", "")

            # Check SSHD failed login
            sshd_fail = SSHD_FAILED_REGEX.search(content)
            if sshd_fail:
                return {
                    "timestamp": ts,
                    "source_ip": sshd_fail.group("ip"),
                    "username": sshd_fail.group("user"),
                    "event_type": "LOGIN_FAILED",
                    "message": content,
                    "severity": "LOW",
                    "raw_log": line
                }

            # Check SSHD accepted login
            sshd_acc = SSHD_ACCEPTED_REGEX.search(content)
            if sshd_acc:
                return {
                    "timestamp": ts,
                    "source_ip": sshd_acc.group("ip"),
                    "username": sshd_acc.group("user"),
                    "event_type": "LOGIN_SUCCESS",
                    "message": content,
                    "severity": "LOW",
                    "raw_log": line
                }

            # Check Sudo privilege escalation
            sudo_match = SUDO_REGEX.search(content)
            if sudo_match:
                return {
                    "timestamp": ts,
                    "username": sudo_match.group("user"),
                    "event_type": "PRIVILEGE_ESCALATION",
                    "message": f"sudo privilege escalation: {sudo_match.group('cmd')}",
                    "severity": "HIGH",
                    "raw_log": line
                }

            # Check UFW firewall network connection
            ufw_match = UFW_FIREWALL_REGEX.search(content)
            if ufw_match:
                return {
                    "timestamp": ts,
                    "source_ip": ufw_match.group("src_ip"),
                    "event_type": "NETWORK_CONNECTION",
                    "message": f"Network connection to {ufw_match.group('dst_ip')}",
                    "severity": "MEDIUM",
                    "raw_log": line,
                    "extra_data": {"destination_ip": ufw_match.group("dst_ip")}
                }

            # Generic syslog line
            return {
                "timestamp": ts,
                "message": f"[{daemon}] {content}",
                "raw_log": line
            }

        # 3. Fallback generic parsing
        ts_match = GENERIC_TIMESTAMP_REGEX.search(line)
        ip_match = IPV4_REGEX.search(line)

        return {
            "timestamp": ts_match.group("timestamp") if ts_match else None,
            "source_ip": ip_match.group("ip") if ip_match else None,
            "message": line,
            "raw_log": line
        }
