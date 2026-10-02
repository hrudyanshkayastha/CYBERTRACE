"""
CYBERTRACE - Deterministic Security Detection Rules
Modular rule implementations with configurable thresholds and transparent logic.
Every detection rule is directly explainable in beginner terms during an academic viva.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from app.config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    LOGIN_AFTER_FAILURES_THRESHOLD,
    LOGIN_AFTER_FAILURES_WINDOW,
    ACCOUNT_LOCKOUT_THRESHOLD,
    ACCOUNT_LOCKOUT_WINDOW,
)
from app.ioc.extractor import is_private_ip, IPV4_REGEX

def parse_iso(ts_str: Optional[str]) -> Optional[datetime]:
    """Helper to parse normalized ISO timestamp to datetime object."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        return None

class RuleMatch:
    """Represents a security finding produced when a rule condition is met."""
    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        finding: str,
        severity: str,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        matched_event_indices: Optional[List[int]] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.finding = finding
        self.severity = severity
        self.source_ip = source_ip
        self.username = username
        self.matched_event_indices = matched_event_indices or []
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "finding": self.finding,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "username": self.username,
            "matched_event_indices": self.matched_event_indices,
            "details": self.details,
        }

class BaseRule(ABC):
    """Abstract Base Class for all CyberTrace detection rules."""
    rule_id: str
    name: str
    description: str

    @abstractmethod
    def evaluate(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        """Evaluates the sequence of events and returns detected matches."""
        pass

class RuleBruteForce(BaseRule):
    """
    Detects brute-force authentication attempts:
    Threshold: >= 5 failed logins from the same source IP within configured time window.
    """
    rule_id = "RULE_001_BRUTE_FORCE"
    name = "Brute-Force Authentication Attempt"
    description = "Detects high-frequency failed login attempts from a single source."

    def __init__(self, threshold: int = BRUTE_FORCE_THRESHOLD, window_seconds: int = BRUTE_FORCE_WINDOW_SECONDS):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        # Group failed logins by IP (or user if IP is null)
        ip_groups: Dict[str, List[tuple]] = {}
        for idx, ev in enumerate(events):
            if ev.get("event_type") == "LOGIN_FAILED":
                key = ev.get("source_ip") or ev.get("username") or "UNKNOWN_SRC"
                ip_groups.setdefault(key, []).append((idx, ev))

        for key, fail_list in ip_groups.items():
            if len(fail_list) < self.threshold:
                continue

            # Check sliding time window or consecutive count
            n = len(fail_list)
            for i in range(n):
                window_indices = [fail_list[i][0]]
                start_dt = parse_iso(fail_list[i][1].get("timestamp"))

                for j in range(i + 1, n):
                    curr_dt = parse_iso(fail_list[j][1].get("timestamp"))
                    if start_dt and curr_dt:
                        diff = (curr_dt - start_dt).total_seconds()
                        if 0 <= diff <= self.window_seconds:
                            window_indices.append(fail_list[j][0])
                    else:
                        # Fallback: count nearby events
                        if j - i < self.threshold * 2:
                            window_indices.append(fail_list[j][0])

                if len(window_indices) >= self.threshold:
                    sample_ev = fail_list[i][1]
                    matches.append(RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        finding="Possible brute-force attack",
                        severity="HIGH",
                        source_ip=sample_ev.get("source_ip"),
                        username=sample_ev.get("username"),
                        matched_event_indices=sorted(list(set(window_indices))),
                        details={"attempts": len(window_indices), "threshold": self.threshold}
                    ))
                    break  # Matched for this source key

        return matches

class RuleLoginAfterFailures(BaseRule):
    """
    Detects successful authentication immediately preceded by multiple authentication failures:
    Threshold: >= 3 failed logins followed by a successful login.
    """
    rule_id = "RULE_002_LOGIN_AFTER_FAILURES"
    name = "Successful Login Following Repeated Failures"
    description = "Identifies potential password guessing or credential spray success."

    def __init__(self, threshold: int = LOGIN_AFTER_FAILURES_THRESHOLD, window_seconds: int = LOGIN_AFTER_FAILURES_WINDOW):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for idx, ev in enumerate(events):
            if ev.get("event_type") == "LOGIN_SUCCESS":
                target_ip = ev.get("source_ip")
                target_user = ev.get("username")
                succ_dt = parse_iso(ev.get("timestamp"))

                # Look back at preceding events
                prior_fails = []
                for p_idx in range(idx - 1, -1, -1):
                    p_ev = events[p_idx]
                    if p_ev.get("event_type") == "LOGIN_FAILED":
                        same_ip = target_ip and (p_ev.get("source_ip") == target_ip)
                        same_user = target_user and (p_ev.get("username") == target_user)
                        if same_ip or same_user:
                            p_dt = parse_iso(p_ev.get("timestamp"))
                            if succ_dt and p_dt:
                                if 0 <= (succ_dt - p_dt).total_seconds() <= self.window_seconds:
                                    prior_fails.append(p_idx)
                            else:
                                if idx - p_idx <= 15:
                                    prior_fails.append(p_idx)

                if len(prior_fails) >= self.threshold:
                    all_indices = sorted(prior_fails + [idx])
                    matches.append(RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        finding="Successful login following multiple authentication failures",
                        severity="HIGH",
                        source_ip=target_ip,
                        username=target_user,
                        matched_event_indices=all_indices,
                        details={"prior_failures_count": len(prior_fails)}
                    ))

        return matches

class RuleAccountLockout(BaseRule):
    """
    Detects repeated failed logins culminating in account lockout.
    """
    rule_id = "RULE_003_ACCOUNT_LOCKOUT"
    name = "Account Lockout Event"
    description = "Detects authentication failures leading to account lockout enforcement."

    def __init__(self, threshold: int = ACCOUNT_LOCKOUT_THRESHOLD, window_seconds: int = ACCOUNT_LOCKOUT_WINDOW):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for idx, ev in enumerate(events):
            if ev.get("event_type") == "ACCOUNT_LOCKED":
                target_user = ev.get("username")
                target_ip = ev.get("source_ip")
                lock_dt = parse_iso(ev.get("timestamp"))

                prior_fails = []
                for p_idx in range(idx - 1, -1, -1):
                    p_ev = events[p_idx]
                    if p_ev.get("event_type") == "LOGIN_FAILED":
                        if (target_user and p_ev.get("username") == target_user) or (target_ip and p_ev.get("source_ip") == target_ip):
                            p_dt = parse_iso(p_ev.get("timestamp"))
                            if lock_dt and p_dt:
                                if 0 <= (lock_dt - p_dt).total_seconds() <= self.window_seconds:
                                    prior_fails.append(p_idx)
                            else:
                                if idx - p_idx <= 10:
                                    prior_fails.append(p_idx)

                matched_indices = sorted(prior_fails + [idx])
                matches.append(RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    finding="Account lockout following multiple authentication failures",
                    severity="MEDIUM",
                    source_ip=target_ip,
                    username=target_user,
                    matched_event_indices=matched_indices,
                    details={"failures_before_lock": len(prior_fails)}
                ))

        return matches

class RulePrivilegeEscalation(BaseRule):
    """
    Detects unauthorized or suspicious privilege escalation (sudo, root elevation, administrator rights).
    """
    rule_id = "RULE_004_PRIVILEGE_ESCALATION"
    name = "Privilege Escalation Activity"
    description = "Detects elevation to root, administrator, or high privilege execution."

    def evaluate(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for idx, ev in enumerate(events):
            if ev.get("event_type") == "PRIVILEGE_ESCALATION":
                matches.append(RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    finding="Potential unauthorized privilege escalation",
                    severity="HIGH",
                    source_ip=ev.get("source_ip"),
                    username=ev.get("username"),
                    matched_event_indices=[idx],
                    details={"action": ev.get("message")}
                ))
            elif ev.get("event_type") == "PROCESS_EXECUTED":
                msg = ev.get("message", "").lower()
                is_elevated_kw = any(kw in msg for kw in ("sudo", "su root", "runas", "powershell -ep bypass", "powershell.exe -enc"))
                is_root_shell = (ev.get("username") == "root" and any(sh in msg for sh in ("/bin/bash", "/bin/sh", "cmd.exe")))
                if is_elevated_kw or is_root_shell:
                    matches.append(RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        finding="Potential unauthorized privilege escalation",
                        severity="HIGH",
                        source_ip=ev.get("source_ip"),
                        username=ev.get("username"),
                        matched_event_indices=[idx],
                        details={"process": ev.get("message")}
                    ))
        return matches

class RuleSuspiciousExternalConnection(BaseRule):
    """
    Detects network connections directed to public or external IP addresses.
    """
    rule_id = "RULE_005_EXTERNAL_CONNECTION"
    name = "Suspicious External Network Connection"
    description = "Detects outbound network communication to external internet addresses."

    def evaluate(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for idx, ev in enumerate(events):
            is_net = ev.get("event_type") == "NETWORK_CONNECTION"
            msg = ev.get("message", "")
            raw = ev.get("raw_log", "") or ""
            extra = ev.get("extra_data", {})

            dest_ip = extra.get("destination_ip")
            if not dest_ip:
                all_ips = IPV4_REGEX.findall(f"{msg} {raw}")
                for ip in all_ips:
                    if ip != ev.get("source_ip") and not is_private_ip(ip):
                        dest_ip = ip
                        break

            if dest_ip and not is_private_ip(dest_ip):
                matches.append(RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    finding="Outbound network connection to external IP",
                    severity="MEDIUM",
                    source_ip=ev.get("source_ip"),
                    username=ev.get("username"),
                    matched_event_indices=[idx],
                    details={"destination_ip": dest_ip}
                ))
            elif is_net and ev.get("source_ip") and not is_private_ip(ev.get("source_ip")):
                matches.append(RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    finding="Outbound network connection to external IP",
                    severity="MEDIUM",
                    source_ip=ev.get("source_ip"),
                    username=ev.get("username"),
                    matched_event_indices=[idx],
                    details={"external_ip": ev.get("source_ip")}
                ))
        return matches

class RuleMultiSuspiciousSource(BaseRule):
    """
    Correlates multiple suspicious findings originating from the same source IP or user identity.
    """
    rule_id = "RULE_006_MULTI_SUSPICIOUS_SOURCE"
    name = "Multiple Suspicious Signals from Same Source"
    description = "Flags sources responsible for multiple distinct anomalous actions."

    def evaluate(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        # Handled at the correlation stage or across event indices
        return []
