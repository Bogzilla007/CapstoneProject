#!/usr/bin/env python3
"""
Project Aegis - LLM Analyst
Sends forensics data to Groq and returns a structured verdict + summary.
Session 16: enriched with AbuseIPDB context, auto-escalation, and a
rule-based fallback classifier for when Groq is down or returns garbage.
"""
import sys
sys.path.insert(0, "/usr/lib/python3/dist-packages")
sys.path.insert(0, "/usr/local/lib/python3.13/dist-packages")
import json
import re
from groq import Groq
import config
import threat_intel

client = Groq(api_key=config.GROQ_API_KEY)

# Prompt Builder

def build_prompt(forensics, abuse_data=None):
    """Packages forensics data (+ optional AbuseIPDB context) into a prompt for the LLM."""
    geo = forensics.get("geo", {})
    if abuse_data is None:
        abuse_data = {}

    telemetry = forensics.get("system_telemetry", {})

    base = f"""
You are a SOC (Security Operations Center) analyst AI.
Analyze the following SSH brute-force attack data and respond ONLY with a JSON object.
Do NOT include any explanation, markdown, or text outside the JSON.

ATTACK DATA:
- Attacker IP     : {forensics.get("attacker_ip", "Unknown")}
- Failed Attempts : {forensics.get("failed_attempts", "Unknown")}
- Country         : {geo.get("country", "Unknown")}
- Region          : {geo.get("region", "Unknown")}
- City            : {geo.get("city", "Unknown")}
- ISP             : {geo.get("isp", "Unknown")}
- Org             : {geo.get("org", "Unknown")}

RAW LOG SAMPLE:
{forensics.get("raw_log_sample", "N/A")}

PROCESS SNAPSHOT (SSH processes at time of attack):
{forensics.get("process_snapshot", "N/A")}

WHOIS DATA:
{str(forensics.get("whois", "N/A"))[:1000]}

SYSTEM STATE AT TIME OF ATTACK:
- Hostname : {telemetry.get("hostname", "Unknown")}
- CPU      : {telemetry.get("cpu_percent", "Unknown")}%
- RAM      : {telemetry.get("ram_percent", "Unknown")}%
"""

    enrichment = ""
    if abuse_data:
        enrichment += f"""
ABUSEIPDB THREAT INTELLIGENCE:
- Abuse Confidence Score : {abuse_data.get("abuse_confidence_score", "Unknown")}/100
- Total Reports          : {abuse_data.get("total_reports", "Unknown")}
- Reported Country       : {abuse_data.get("country_code", "Unknown")}
- ISP (AbuseIPDB)        : {abuse_data.get("isp", "Unknown")}
"""

    if forensics.get("repeat_offender"):
        count = forensics.get("previous_incident_count", "?")
        enrichment += "\n- Repeat Offender: Yes, " + str(count) + " prior incidents\n"
    if forensics.get("detected_usernames"):
        names = ", ".join(forensics["detected_usernames"])
        enrichment += "- Usernames Tried: " + names + "\n"
    if forensics.get("timing_pattern"):
        enrichment += "- Timing Pattern: " + str(forensics["timing_pattern"]) + "\n"
    if forensics.get("detection_label"):
        enrichment += "- Detection Source: " + str(forensics["detection_label"]) + "\n"
    if forensics.get("threat_labels"):
        labels = ", ".join(forensics["threat_labels"])
        enrichment += "- Threat Labels: " + labels + "\n"

    schema = """
Based on this data, respond ONLY with this exact JSON format:
{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "action": "BLOCK" | "MONITOR" | "IGNORE",
  "summary": "A 2-3 sentence executive summary of the threat for a security report."
}

Rules:
- CRITICAL + BLOCK if: high attempt count, suspicious ISP/org, known hostile region, high AbuseIPDB score
- HIGH + BLOCK if: clear brute force pattern, moderate AbuseIPDB score
- MEDIUM + MONITOR if: low attempts, residential ISP
- LOW + IGNORE if: likely benign or internal traffic
"""

    return base + enrichment + schema

# JSON Parser with Fallback

def parse_verdict(raw_response):
    """
    Extracts JSON from LLM response.
    Returns None if no valid JSON could be extracted (caller should fall back).
    """
    try:
        return json.loads(raw_response.strip())
    except json.JSONDecodeError:
        pass

    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_response, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    json_match = re.search(r"\{.*?\}", raw_response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    print("  [!] WARNING: Could not parse LLM JSON response.")
    return None

# Main Analyst Function

def analyze_threat(forensics):
    """
    Sends forensics data to Groq (enriched with AbuseIPDB context) and
    returns a clean verdict dict: {"severity": ..., "action": ..., "summary": ...}

    On Groq failure or invalid JSON, falls back to threat_intel.fallback_classify().
    Verdict severity is auto-escalated based on AbuseIPDB score before returning.
    """
    ip = forensics.get("attacker_ip", "unknown")

    abuse_data = threat_intel.lookup(ip)
    forensics["abuse_score"]         = abuse_data.get("abuse_confidence_score", 0)
    forensics["abuse_total_reports"] = abuse_data.get("total_reports", 0)

    print("  [*] Sending forensics to Groq (" + str(config.GROQ_MODEL) + ")...")
    prompt = build_prompt(forensics, abuse_data=abuse_data)

    verdict = None
    try:
        response = client.chat.completions.create(
            model=config.GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a SOC analyst AI. You respond ONLY with valid JSON. No markdown, no explanation, just the JSON object."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=500
        )

        raw = response.choices[0].message.content
        print("  [*] Raw Groq response: " + raw[:200])
        verdict = parse_verdict(raw)

    except Exception as e:
        print(f"  [!] Groq API error: {e}")
        verdict = None

    if verdict is None:
        verdict = threat_intel.fallback_classify(forensics, abuse_data=abuse_data)
    else:
        print("  [+] Verdict: " + str(verdict.get("severity")) + " - " + str(verdict.get("action")))
        print("  [+] Summary: " + str(verdict.get("summary", ""))[:100] + "...")

    verdict = threat_intel.maybe_escalate(verdict, abuse_data)

    return verdict


# Standalone Test

if __name__ == "__main__":
    print("[*] Testing LLM analyst with mock forensics data...\n")

    mock_forensics = {
        "timestamp": "2026-06-23 02:45:56",
        "attacker_ip": "198.51.100.44",
        "failed_attempts": 7,
        "raw_log_sample": "Failed password for invalid user root from 198.51.100.44 port 54321 ssh2\n" * 5,
        "geo": {
            "country": "Russia",
            "region": "Moscow",
            "city": "Moscow",
            "isp": "Selectel",
            "org": "Selectel Network"
        },
        "whois": "NetName: SELECTEL-NET\nCountry: RU\nOrgName: Selectel Ltd",
        "process_snapshot": "root  1234  0.0  sshd: /usr/sbin/sshd -D",
        "system_telemetry": {
            "hostname": "kali",
            "cpu_percent": 12.5,
            "ram_percent": 51.0
        },
        "detected_usernames": ["root", "admin"],
        "timing_pattern": "AUTOMATED_TOOL",
        "detection_label": "BRUTE_FORCE",
        "threat_labels": ["AUTOMATED_ATTACK"]
    }

    verdict = analyze_threat(mock_forensics)
    print("\nFinal Verdict:")
    print(json.dumps(verdict, indent=2))
