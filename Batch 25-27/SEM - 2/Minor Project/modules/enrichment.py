"""
VirusTotal Enrichment Module
Enriches extracted IOCs with threat data from VirusTotal API v3
Uses only Python standard library (urllib)
"""

import urllib.request
import urllib.error
import json
import time
from typing import Dict, Optional


VT_BASE = "https://www.virustotal.com/api/v3"

# Cache results to avoid duplicate API calls
_cache: Dict[str, dict] = {}


def _vt_request(endpoint: str, api_key: str) -> Optional[dict]:
    """Make a VirusTotal API request."""
    url = f"{VT_BASE}/{endpoint}"
    req = urllib.request.Request(url)
    req.add_header("x-apikey", api_key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "not_found"}
        elif e.code == 429:
            return {"error": "rate_limited"}
        return {"error": f"http_{e.code}"}
    except Exception as e:
        return {"error": str(e)}


def enrich_ip(ip: str, api_key: str) -> dict:
    """Get VirusTotal data for an IP address."""
    cache_key = f"ip:{ip}"
    if cache_key in _cache:
        return _cache[cache_key]

    data = _vt_request(f"ip_addresses/{ip}", api_key)
    result = _parse_vt_response(data, "ip", ip)
    _cache[cache_key] = result
    time.sleep(15)  # Respect free tier rate limit
    return result


def enrich_domain(domain: str, api_key: str) -> dict:
    """Get VirusTotal data for a domain."""
    cache_key = f"domain:{domain}"
    if cache_key in _cache:
        return _cache[cache_key]

    data = _vt_request(f"domains/{domain}", api_key)
    result = _parse_vt_response(data, "domain", domain)
    _cache[cache_key] = result
    time.sleep(0.2)
    return result


def enrich_hash(file_hash: str, api_key: str) -> dict:
    """Get VirusTotal data for a file hash (MD5/SHA1/SHA256)."""
    cache_key = f"hash:{file_hash}"
    if cache_key in _cache:
        return _cache[cache_key]

    data = _vt_request(f"files/{file_hash}", api_key)
    result = _parse_vt_response(data, "hash", file_hash)
    _cache[cache_key] = result
    time.sleep(0.2)
    return result


def enrich_url(url: str, api_key: str) -> dict:
    """Get VirusTotal data for a URL."""
    import base64
    cache_key = f"url:{url}"
    if cache_key in _cache:
        return _cache[cache_key]

    # VT API v3 requires URL-safe base64 encoded URL
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data = _vt_request(f"urls/{url_id}", api_key)
    result = _parse_vt_response(data, "url", url)
    _cache[cache_key] = result
    time.sleep(0.2)
    return result


def _parse_vt_response(data: Optional[dict], ioc_type: str, value: str) -> dict:
    """Parse VT API response into a clean enrichment dict."""
    if not data:
        return _empty_enrichment(value)

    if "error" in data:
        return {
            "value": value,
            "type": ioc_type,
            "vt_status": data["error"],
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "risk_level": "unknown",
            "tags": [],
            "country": "",
            "malware_family": "",
        }

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious  = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless",   0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected

    # Determine risk level
    if total == 0:
        risk = "unknown"
    elif malicious >= 10:
        risk = "critical"
    elif malicious >= 5:
        risk = "high"
    elif malicious >= 1 or suspicious >= 3:
        risk = "medium"
    else:
        risk = "clean"

    # Extract malware family names
    families = list(attrs.get("popular_threat_classification", {})
                    .get("suggested_threat_label", "").split("."))
    family_str = attrs.get("popular_threat_classification", {}) \
                      .get("suggested_threat_label", "")

    return {
        "value": value,
        "type": ioc_type,
        "vt_status": "found",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "risk_level": risk,
        "tags": attrs.get("tags", []),
        "country": attrs.get("country", ""),
        "malware_family": family_str,
        "last_analysis_date": attrs.get("last_analysis_date", ""),
    }


def _empty_enrichment(value: str) -> dict:
    return {
        "value": value,
        "vt_status": "not_checked",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total_engines": 0,
        "risk_level": "unknown",
        "tags": [],
        "country": "",
        "malware_family": "",
    }


def enrich_iocs(iocs: dict, api_key: str, max_per_type: int = 5) -> dict:
    """
    Enrich a subset of extracted IOCs with VirusTotal data.
    Limits per type to avoid burning API quota.
    """
    enriched = {}

    type_handlers = {
        "ipv4":   enrich_ip,
        "domain": enrich_domain,
        "md5":    enrich_hash,
        "sha1":   enrich_hash,
        "sha256": enrich_hash,
        "url":    enrich_url,
    }

    for ioc_type, handler in type_handlers.items():
        values = iocs.get(ioc_type, [])[:max_per_type]
        if not values:
            continue

        enriched[ioc_type] = []
        for val in values:
            result = handler(val, api_key)
            enriched[ioc_type].append(result)

    return enriched