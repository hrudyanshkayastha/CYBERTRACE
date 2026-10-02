"""
CYBERTRACE - Indicator of Compromise (IOC) Extractor
Identifies observed artifacts (IPv4, domains, URLs, usernames, file paths) from normalized events.
Maintains academic neutrality ("Observed IOC") while flagging potentially suspicious indicators.
"""

import re
import ipaddress
from typing import List, Dict, Any, Set

# Regex patterns for IOC extraction
IPV4_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
URL_REGEX = re.compile(
    r"\bhttps?://[a-zA-Z0-9\.\-_]+(?::\d+)?(?:/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]*)?"
)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|local|xyz|ru|cn|top|online|edu|gov|co|info|biz)\b",
    re.IGNORECASE
)
FILEPATH_REGEX = re.compile(
    r"(?:/[a-zA-Z0-9_.\-]+(?:/[a-zA-Z0-9_.\-]+)+|[A-Za-z]:\\[a-zA-Z0-9_.\-\\]+)"
)

# Sensitive and suspicious indicators for educational flagging
SUSPICIOUS_PATHS = {
    "/etc/shadow", "/etc/passwd", "/bin/bash", "/bin/sh", "/tmp/",
    "cmd.exe", "powershell.exe", "mimikatz", ".exe", ".sh", "nc"
}

SUSPICIOUS_KEYWORDS = {
    "malware", "backdoor", "c2", "c2-server", "suspicious", "payload", "revshell", "exploit"
}

def is_private_ip(ip_str: str) -> bool:
    """Checks whether an IPv4 string is an internal private IP (RFC 1918 / Loopback)."""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        if ip.is_loopback:
            return True
        # Check standard RFC 1918 ranges
        return (
            ip in ipaddress.IPv4Network("10.0.0.0/8") or
            ip in ipaddress.IPv4Network("172.16.0.0/12") or
            ip in ipaddress.IPv4Network("192.168.0.0/16")
        )
    except ValueError:
        return False

class IOCExtractor:
    """Extracts, categorizes, and de-duplicates Indicators of Compromise from event sets."""

    @classmethod
    def extract_from_events(cls, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans all event records and extracts structured IOC dictionaries:
        {
            "ioc_type": "IPv4" | "DOMAIN" | "URL" | "USERNAME" | "FILE_PATH",
            "ioc_value": str,
            "is_suspicious": bool,
            "context": str,
            "first_seen": timestamp or None
        }
        """
        seen_keys: Set[str] = set()
        iocs: List[Dict[str, Any]] = []

        for ev in events:
            timestamp = ev.get("timestamp")
            msg = ev.get("message", "")
            raw = ev.get("raw_log", "") or ""
            search_text = f"{msg} {raw}"

            # 1. Source IP
            src_ip = ev.get("source_ip")
            if src_ip:
                cls._add_ip(src_ip, f"Observed as source IP in {ev.get('event_type')}", timestamp, ev.get("severity") in ("HIGH", "CRITICAL"), seen_keys, iocs)

            # 2. IPs in message/raw
            for found_ip in IPV4_REGEX.findall(search_text):
                is_ext = not is_private_ip(found_ip)
                susp = is_ext or ev.get("severity") in ("HIGH", "CRITICAL")
                ctx = f"{'External' if is_ext else 'Internal'} IP observed in event log"
                cls._add_ip(found_ip, ctx, timestamp, susp, seen_keys, iocs)

            # 3. Usernames
            user = ev.get("username")
            if user and len(user) > 1 and user.lower() not in ("unknown", "system", "none", "null"):
                is_priv = user.lower() in ("root", "admin", "administrator", "wheel")
                key = f"USER:{user.lower()}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    iocs.append({
                        "ioc_type": "USERNAME",
                        "ioc_value": user,
                        "is_suspicious": is_priv and ev.get("event_type") in ("LOGIN_FAILED", "PRIVILEGE_ESCALATION"),
                        "context": f"{'Privileged' if is_priv else 'Standard'} user identity observed in event",
                        "first_seen": timestamp
                    })

            # 4. URLs
            for url in URL_REGEX.findall(search_text):
                key = f"URL:{url}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    is_susp = any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS)
                    iocs.append({
                        "ioc_type": "URL",
                        "ioc_value": url,
                        "is_suspicious": is_susp,
                        "context": "Observed web endpoint reference in log",
                        "first_seen": timestamp
                    })

            # 5. Domains
            for domain in DOMAIN_REGEX.findall(search_text):
                key = f"DOMAIN:{domain.lower()}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    is_susp = any(kw in domain.lower() for kw in SUSPICIOUS_KEYWORDS)
                    iocs.append({
                        "ioc_type": "DOMAIN",
                        "ioc_value": domain,
                        "is_suspicious": is_susp,
                        "context": "Observed network domain identifier in event log",
                        "first_seen": timestamp
                    })

            # 6. File Paths
            for path in FILEPATH_REGEX.findall(search_text):
                # Clean trailing punctuation
                cleaned_path = path.rstrip(";,):")
                if len(cleaned_path) > 3:
                    key = f"FILE:{cleaned_path}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        is_susp = any(sp in cleaned_path.lower() for sp in SUSPICIOUS_PATHS)
                        iocs.append({
                            "ioc_type": "FILE_PATH",
                            "ioc_value": cleaned_path,
                            "is_suspicious": is_susp,
                            "context": "File system artifact referenced in activity log",
                            "first_seen": timestamp
                        })

        return iocs

    @staticmethod
    def _add_ip(ip: str, context: str, timestamp: Any, is_suspicious: bool, seen_keys: Set[str], iocs: List[Dict[str, Any]]) -> None:
        key = f"IP:{ip}"
        if key not in seen_keys:
            seen_keys.add(key)
            ext = not is_private_ip(ip)
            iocs.append({
                "ioc_type": "IPv4",
                "ioc_value": ip,
                "is_suspicious": is_suspicious or ext,
                "context": f"{'External public' if ext else 'Private local'} IP address - {context}",
                "first_seen": timestamp
            })
