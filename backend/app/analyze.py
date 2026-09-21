"""Turn raw email headers + body into hops, IOCs, and MITRE ATT&CK labels."""

from __future__ import annotations

import hashlib
import re
from email.parser import HeaderParser
from email.policy import default

from .geoip import geolocate, is_public_ip

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
RECEIVED_IP_RE = re.compile(r"[\[(](" + IPV4_RE.pattern + r")[\])]")
RECEIVED_HOST_RE = re.compile(r"from\s+(\S+)", re.IGNORECASE)
FILE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".exe", ".zip", ".js", ".html", ".iso", ".scr", ".vbs")

PHISH_WORDS = (
    "verify your account",
    "confirm your password",
    "urgent",
    "account suspended",
    "login immediately",
    "reset your password",
    "unusual activity",
    "click here",
)
CREDENTIAL_WORDS = ("password", "otp", "one-time", "credential", "ssn", "bank login")
ATTACHMENT_HINTS = (".exe", ".iso", ".js", ".vbs", ".scr", ".zip", ".html")


def unfold_headers(raw: str) -> dict[str, str]:
    parsed = HeaderParser(policy=default).parsestr(raw or "")
    headers: dict[str, str] = {}
    for key in parsed.keys():
        values = parsed.get_all(key) or []
        headers[key] = " | ".join(v.replace("\n", " ").strip() for v in values)
    return headers


def _all_received(raw: str) -> list[str]:
    parsed = HeaderParser(policy=default).parsestr(raw or "")
    return [v.replace("\n", " ").strip() for v in (parsed.get_all("Received") or [])]


def hop_path(raw_headers: str) -> list[dict]:
    """Oldest hop first (how the message actually travelled)."""
    hops = []
    for index, line in enumerate(reversed(_all_received(raw_headers))):
        ip_match = RECEIVED_IP_RE.search(line)
        host_match = RECEIVED_HOST_RE.search(line)
        ip = ip_match.group(1) if ip_match else None
        hop = {
            "order": index + 1,
            "host": host_match.group(1).strip(";") if host_match else None,
            "ip": ip,
            "raw": line[:300],
            "geo": geolocate(ip) if ip else None,
        }
        hops.append(hop)
    return hops


def extract_iocs(headers: dict[str, str], body: str) -> dict[str, list[str]]:
    blob = "\n".join(headers.values()) + "\n" + (body or "")
    urls = sorted(set(URL_RE.findall(blob)))
    emails = sorted(set(EMAIL_RE.findall(blob)))
    ips = sorted({ip for ip in IPV4_RE.findall(blob) if is_public_ip(ip)})
    hashes = sorted(set(HASH_RE.findall(blob)))
    skip = {e.split("@", 1)[-1].lower() for e in emails}
    domains = sorted(
        {
            d.lower()
            for d in DOMAIN_RE.findall(blob)
            if d.lower() not in skip and not d.lower().endswith(FILE_SUFFIXES)
        }
    )
    return {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "emails": emails,
        "hashes": hashes,
    }


def map_mitre(headers: dict[str, str], body: str, iocs: dict, hops: list[dict]) -> list[dict]:
    text = f"{headers.get('Subject', '')}\n{body}".lower()
    techniques: list[dict] = []

    if any(word in text for word in PHISH_WORDS) or iocs["urls"]:
        techniques.append(
            {
                "tactic": "Initial Access",
                "technique_id": "T1566.002",
                "technique": "Phishing: Spearphishing Link",
                "reason": "Urgent language and/or embedded links typical of phishing.",
            }
        )

    if any(word in text for word in CREDENTIAL_WORDS):
        techniques.append(
            {
                "tactic": "Credential Access",
                "technique_id": "T1056",
                "technique": "Input Capture",
                "reason": "Message asks the user for passwords or one-time codes.",
            }
        )

    from_header = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    if reply_to and reply_to.split("@")[-1].lower() not in from_header.lower():
        techniques.append(
            {
                "tactic": "Defense Evasion",
                "technique_id": "T1036",
                "technique": "Masquerading",
                "reason": "Reply-To domain does not match the visible From address.",
            }
        )

    if any(hint in text for hint in ATTACHMENT_HINTS):
        techniques.append(
            {
                "tactic": "Execution",
                "technique_id": "T1204.002",
                "technique": "User Execution: Malicious File",
                "reason": "Body or headers mention a risky attachment type.",
            }
        )

    if any((hop.get("geo") or {}).get("is_tor") or (hop.get("geo") or {}).get("is_threat") for hop in hops):
        techniques.append(
            {
                "tactic": "Command and Control",
                "technique_id": "T1090.003",
                "technique": "Proxy: Multi-hop Proxy",
                "reason": "A hop IP is on the demo Tor/threat list.",
            }
        )

    if not techniques:
        techniques.append(
            {
                "tactic": "Reconnaissance",
                "technique_id": "T1598",
                "technique": "Phishing for Information",
                "reason": "No strong phishing signals; logged for investigator review.",
            }
        )
    return techniques


def risk_from(techniques: list[dict], hops: list[dict]) -> str:
    score = len(techniques)
    if any((hop.get("geo") or {}).get("is_threat") for hop in hops):
        score += 2
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def analyze_email(headers_raw: str, body: str) -> dict:
    headers = unfold_headers(headers_raw)
    hops = hop_path(headers_raw)
    iocs = extract_iocs(headers, body)
    mitre = map_mitre(headers, body, iocs, hops)
    body_sha256 = hashlib.sha256((body or "").encode("utf-8", errors="ignore")).hexdigest()
    return {
        "subject": headers.get("Subject"),
        "from": headers.get("From"),
        "risk": risk_from(mitre, hops),
        "headers": headers,
        "hops": hops,
        "iocs": iocs,
        "mitre": mitre,
        "body_sha256": body_sha256,
    }
