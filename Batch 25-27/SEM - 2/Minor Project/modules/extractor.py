"""
IOC Extractor Module
Extracts Indicators of Compromise from raw text using regex patterns
"""

import re
from typing import Dict, List


# ─────────────────────────────────────────────
#  Defang / Refang helpers
# ─────────────────────────────────────────────

def refang(text: str) -> str:
    """Convert defanged IOCs back to normal form for extraction."""
    replacements = [
        ("hxxps://", "https://"),
        ("hxxp://",  "http://"),
        ("[.]",      "."),
        ("(dot)",    "."),
        ("[dot]",    "."),
        ("[at]",     "@"),
        ("[@]",      "@"),
        ("[:]",      ":"),
        ("(:)",      ":"),
    ]
    for old, new in replacements:
        text = text.replace(old, new)
    return text


# ─────────────────────────────────────────────
#  Regex Patterns
# ─────────────────────────────────────────────

PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|gov|edu|mil|int|ru|cn|io|co|uk|de|fr|'
        r'in|jp|br|au|ca|info|biz|onion|tk|xyz|top|club|site|online|'
        r'live|shop|store|tech|app|dev|cloud|hack|pw|cc|su)\b',
        re.IGNORECASE
    ),
    "url": re.compile(
        r'https?://[^\s<>"\'{}|\\^`\[\]]{4,}'
    ),
    "md5": re.compile(
        r'\b[a-fA-F0-9]{32}\b'
    ),
    "sha1": re.compile(
        r'\b[a-fA-F0-9]{40}\b'
    ),
    "sha256": re.compile(
        r'\b[a-fA-F0-9]{64}\b'
    ),
    "sha512": re.compile(
        r'\b[a-fA-F0-9]{128}\b'
    ),
    "email": re.compile(
        r'\b[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+\b'
    ),
    "cve": re.compile(
        r'CVE-\d{4}-\d{4,7}',
        re.IGNORECASE
    ),
    "bitcoin_wallet": re.compile(
        r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    ),
    "registry_key": re.compile(
        r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)'
        r'(?:\\[^\s\'"<>]+)+',
        re.IGNORECASE
    ),
    "file_path_windows": re.compile(
        r'[A-Za-z]:\\(?:[^\s<>:"/\\|?*\n]+\\)*[^\s<>:"/\\|?*\n]+'
    ),
    "file_path_linux": re.compile(
        r'/(?:etc|var|tmp|usr|home|root|bin|sbin|opt|proc|sys)'
        r'(?:/[^\s<>\'"\n]+)+'
    ),
    "mitre_attack": re.compile(
        r'T\d{4}(?:\.\d{3})?',
    ),
    "asn": re.compile(
        r'\bAS\d{1,6}\b'
    ),
}

# Private/reserved IP ranges to filter out
PRIVATE_IP_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^0\.0\.0\.0$'),
    re.compile(r'^255\.255\.255\.255$'),
    re.compile(r'^169\.254\.'),
]

# Common false-positive domains to filter
FALSE_POSITIVE_DOMAINS = {
    "example.com", "test.com", "localhost.com",
    "google.com", "microsoft.com", "apple.com",
    "github.com", "stackoverflow.com", "wikipedia.org",
}


def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_IP_RANGES)


def extract_iocs(text: str, include_private_ips: bool = False) -> Dict[str, List[str]]:
    """
    Main extraction function.
    Returns a dict of IOC type → sorted unique list of matches.
    """
    text = refang(text)
    results: Dict[str, List[str]] = {}

    for ioc_type, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        unique = sorted(set(matches))

        # Filter private IPs unless requested
        if ioc_type == "ipv4" and not include_private_ips:
            unique = [ip for ip in unique if not is_private_ip(ip)]

        # Filter obvious false-positive domains
        if ioc_type == "domain":
            unique = [d for d in unique if d.lower() not in FALSE_POSITIVE_DOMAINS]

        if unique:
            results[ioc_type] = unique

    return results


def get_ioc_summary(iocs: Dict[str, List[str]]) -> Dict[str, int]:
    """Return count per IOC type."""
    return {k: len(v) for k, v in iocs.items()}


def get_total_count(iocs: Dict[str, List[str]]) -> int:
    return sum(len(v) for v in iocs.values())