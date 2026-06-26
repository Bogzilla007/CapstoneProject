"""
threat_intel.py — Project Aegis (Session 16)
Threat intelligence enrichment layer.

1. lookup(ip)            — AbuseIPDB reputation check, 1hr in-memory cache,
                            skips private/loopback IPs.
2. maybe_escalate(...)   — auto-upgrades verdict severity based on
                            AbuseIPDB abuse_confidence_score.
3. fallback_classify(...)— rule-based classifier used when Groq is down
                            or returns invalid JSON.
"""

import time
import ipaddress
import requests
import config

_cache = {}


def _is_private_or_loopback(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return True


def lookup(ip):
    if _is_private_or_loopback(ip):
        return {}

    cache_ttl = getattr(config, "ABUSEIPDB_CACHE_TTL", 3600)
    cached = _cache.get(ip)
    if cached and (time.time() - cached["fetched_at"]) < cache_ttl:
        return cached["data"]

    api_key = getattr(config, "ABUSEIPDB_API_KEY", "")
    if not api_key or api_key == "your_abuseipdb_key_here":
        print("  [!] AbuseIPDB API key not configured. Skipping lookup.")
        return {}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if response.status_code != 200:
            print(f"  [!] AbuseIPDB returned {response.status_code}: {response.text[:200]}")
            return {}

        result = response.json().get("data", {})
        score = result.get("abuseConfidenceScore", 0)
        reports = result.get("totalReports", 0)
        data = {
            "abuse_confidence_score": score,
            "total_reports": reports,
            "country_code": result.get("countryCode", "Unknown"),
            "isp": result.get("isp", "Unknown"),
            "domain": result.get("domain", "Unknown"),
        }
        _cache[ip] = {"data": data, "fetched_at": time.time()}
        print("  [+] AbuseIPDB: " + ip + " - score=" + str(score) + " reports=" + str(reports))
        return data

    except Exception as e:
        print(f"  [!] AbuseIPDB lookup failed: {e}")
        return {}


_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def maybe_escalate(verdict, abuse_data):
    if not abuse_data:
        return verdict

    score = abuse_data.get("abuse_confidence_score", 0)
    current = verdict.get("severity", "LOW")

    if score >= 80:
        target = "CRITICAL"
    elif score >= 50:
        target = "HIGH"
    elif score >= 20:
        target = "MEDIUM"
    else:
        return verdict

    if _SEVERITY_RANK.get(target, 0) > _SEVERITY_RANK.get(current, 0):
        print(f"  [+] AbuseIPDB escalation: {current} -> {target} (score={score})")
        verdict["severity"] = target
        if target in ("HIGH", "CRITICAL"):
            verdict["action"] = "BLOCK"
        old_summary = verdict.get("summary", "")
        verdict["summary"] = old_summary + " [Escalated to " + target + " based on AbuseIPDB score " + str(score) + ".]"

    return verdict


def fallback_classify(forensics, abuse_data=None):
    if abuse_data is None:
        abuse_data = {}

    failed_attempts = forensics.get("failed_attempts", 0)
    if not isinstance(failed_attempts, (int, float)):
        failed_attempts = 0

    abuse_score = abuse_data.get("abuse_confidence_score", 0)

    if failed_attempts >= 20 or abuse_score >= 80:
        severity, action = "CRITICAL", "BLOCK"
    elif failed_attempts >= 10 or abuse_score >= 50:
        severity, action = "HIGH", "BLOCK"
    elif failed_attempts >= 5 or abuse_score >= 20:
        severity, action = "MEDIUM", "MONITOR"
    else:
        severity, action = "LOW", "IGNORE"

    ip = forensics.get("attacker_ip", "unknown")
    summary = (
        f"Fallback classifier (Groq unavailable): {ip} had {failed_attempts} "
        f"failed attempts, AbuseIPDB score {abuse_score}. "
        f"Classified as {severity} based on rule thresholds."
    )

    print(f"  [~] Fallback classifier used: {severity} - {action}")

    return {
        "severity": severity,
        "action": action,
        "summary": summary
    }
