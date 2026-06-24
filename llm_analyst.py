#!/usr/bin/env python3
"""
Project Aegis - LLM Analyst
Sends forensics data to Groq and returns a structured verdict + summary.
"""
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
sys.path.insert(0, '/usr/local/lib/python3.13/dist-packages')
import json
import re
from groq import Groq
import config

client = Groq(api_key=config.GROQ_API_KEY)

# ─── Prompt Builder ────────────────────────────────────────────────────────────

def build_prompt(forensics):
    """Packages forensics data into a tight prompt for the LLM."""
    geo = forensics.get("geo", {})
    return f"""
You are a SOC (Security Operations Center) analyst AI.
Analyze the following SSH brute-force attack data and respond ONLY with a JSON object.
Do NOT include any explanation, markdown, or text outside the JSON.

ATTACK DATA:
- Attacker IP     : {forensics['attacker_ip']}
- Failed Attempts : {forensics['failed_attempts']}
- Country         : {geo.get('country', 'Unknown')}
- Region          : {geo.get('region', 'Unknown')}
- City            : {geo.get('city', 'Unknown')}
- ISP             : {geo.get('isp', 'Unknown')}
- Org             : {geo.get('org', 'Unknown')}

RAW LOG SAMPLE:
{forensics['raw_log_sample']}

PROCESS SNAPSHOT (SSH processes at time of attack):
{forensics['process_snapshot']}

WHOIS DATA:
{forensics['whois'][:1000]}

SYSTEM STATE AT TIME OF ATTACK:
- Hostname : {forensics['system_telemetry']['hostname']}
- CPU      : {forensics['system_telemetry']['cpu_percent']}%
- RAM      : {forensics['system_telemetry']['ram_percent']}%

Based on this data, respond ONLY with this exact JSON format:
{{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "action": "BLOCK" | "MONITOR" | "IGNORE",
  "summary": "A 2-3 sentence executive summary of the threat for a security report."
}}

Rules:
- CRITICAL + BLOCK if: high attempt count, suspicious ISP/org, known hostile region
- HIGH + BLOCK if: clear brute force pattern
- MEDIUM + MONITOR if: low attempts, residential ISP
- LOW + IGNORE if: likely benign or internal traffic
"""

# ─── JSON Parser with Fallback ─────────────────────────────────────────────────

def parse_verdict(raw_response):
    """
    Extracts JSON from LLM response.
    Handles cases where model wraps output in markdown fences or adds commentary.
    """
    # Try direct parse first
    try:
        return json.loads(raw_response.strip())
    except json.JSONDecodeError:
        pass

    # Try extracting JSON from markdown fences
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_response, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding any JSON object in the response
    json_match = re.search(r"\{.*?\}", raw_response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    # All parsing failed — return a safe fallback
    print("  [!] WARNING: Could not parse LLM JSON response. Using fallback verdict.")
    return {
        "severity": "HIGH",
        "action": "BLOCK",
        "summary": f"LLM parsing failed. Raw response: {raw_response[:200]}"
    }

# ─── Main Analyst Function ─────────────────────────────────────────────────────

def analyze_threat(forensics):
    """
    Sends forensics data to Groq and returns a clean verdict dict.
    Returns: {"severity": ..., "action": ..., "summary": ...}
    """
    print(f"  [*] Sending forensics to Groq ({config.GROQ_MODEL})...")

    prompt = build_prompt(forensics)

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
            temperature=0.1,  # Low temperature for consistent structured output
            max_tokens=500
        )

        raw = response.choices[0].message.content
        print(f"  [*] Raw Groq response: {raw[:200]}")
        verdict = parse_verdict(raw)
        print(f"  [+] Verdict: {verdict['severity']} — {verdict['action']}")
        print(f"  [+] Summary: {verdict['summary'][:100]}...")
        return verdict

    except Exception as e:
        print(f"  [!] Groq API error: {e}")
        return {
            "severity": "HIGH",
            "action": "BLOCK",
            "summary": f"LLM analysis failed due to API error: {str(e)}"
        }


# ─── Standalone Test ───────────────────────────────────────────────────────────

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
        }
    }

    verdict = analyze_threat(mock_forensics)
    print(f"\nFinal Verdict:\n{json.dumps(verdict, indent=2)}")
