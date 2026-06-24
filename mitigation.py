#!/usr/bin/env python3
"""
Project Aegis - Active Mitigation & Discord Alerting
Handles ufw blocking and Discord webhook notifications.
"""

import subprocess
import requests
import json
import os
from datetime import datetime
import config

# ─── Blocklist ─────────────────────────────────────────────────────────────────

BLOCKLIST_PATH = "reports/blocklist.txt"

def load_blocklist():
    """Returns set of already blocked IPs."""
    if not os.path.exists(BLOCKLIST_PATH):
        return set()
    with open(BLOCKLIST_PATH, "r") as f:
        return set(line.strip().split(",")[0] for line in f if line.strip())

def save_to_blocklist(ip, severity, summary):
    """Appends a blocked IP to the blocklist log."""
    os.makedirs("reports", exist_ok=True)
    with open(BLOCKLIST_PATH, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{ip},{severity},{timestamp},{summary[:80]}\n")

# ─── UFW Blocking ──────────────────────────────────────────────────────────────

def block_ip(ip):
    """
    Executes ufw deny for the given IP.
    Respects DRY_RUN mode — logs but does not execute if True.
    """
    if ip in load_blocklist():
        print(f"  [*] {ip} is already in blocklist. Skipping.")
        return False

    if config.DRY_RUN:
        print(f"  [DRY RUN] Would execute: sudo ufw deny from {ip}")
        print(f"  [DRY RUN] Would add {ip} to blocklist.")
        save_to_blocklist(ip, "DRY_RUN", "Dry run mode — not actually blocked")
        return True

    try:
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"  [+] BLOCKED: ufw rule added for {ip}")
            save_to_blocklist(ip, "BLOCKED", "ufw rule applied")
            return True
        else:
            print(f"  [!] ufw block failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"  [!] Block execution error: {e}")
        return False

# ─── Discord Alerting ──────────────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🟢"
}

ACTION_EMOJI = {
    "BLOCK":   "🔒",
    "MONITOR": "👁️",
    "IGNORE":  "✅"
}

def send_discord_alert(ip, verdict, forensics):
    """Fires a Discord webhook with the incident details."""
    if not config.DISCORD_WEBHOOK_URL or config.DISCORD_WEBHOOK_URL == "your_discord_webhook_url_here":
        print("  [!] Discord webhook not configured. Skipping alert.")
        return

    severity = verdict.get("severity", "UNKNOWN")
    action = verdict.get("action", "UNKNOWN")
    summary = verdict.get("summary", "No summary available.")
    geo = forensics.get("geo", {})

    sev_emoji = SEVERITY_EMOJI.get(severity, "⚠️")
    act_emoji = ACTION_EMOJI.get(action, "❓")

    message = {
        "username": "Project Aegis",
        "avatar_url": "https://i.imgur.com/4M34hi2.png",
        "embeds": [
            {
                "title": f"{sev_emoji} {severity} THREAT DETECTED — {action} {act_emoji}",
                "color": {
                    "CRITICAL": 0xFF0000,
                    "HIGH":     0xFF4500,
                    "MEDIUM":   0xFFA500,
                    "LOW":      0x00FF00
                }.get(severity, 0x808080),
                "fields": [
                    {"name": "🌐 Attacker IP",      "value": ip,                                        "inline": True},
                    {"name": "🏳️ Country",           "value": geo.get("country", "Unknown"),             "inline": True},
                    {"name": "🏢 ISP / Org",         "value": geo.get("isp", "Unknown"),                 "inline": True},
                    {"name": "❌ Failed Attempts",   "value": str(forensics.get("failed_attempts", "?")), "inline": True},
                    {"name": "⚡ Severity",          "value": severity,                                  "inline": True},
                    {"name": "🔧 Action Taken",      "value": action,                                    "inline": True},
                    {"name": "📋 AI Summary",        "value": summary,                                   "inline": False},
                ],
                "footer": {"text": f"Project Aegis EDR • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"},
                "thumbnail": {"url": "https://i.imgur.com/4M34hi2.png"}
            }
        ]
    }

    try:
        response = requests.post(
            config.DISCORD_WEBHOOK_URL,
            json=message,
            timeout=10
        )
        if response.status_code == 204:
            print(f"  [+] Discord alert sent successfully.")
        else:
            print(f"  [!] Discord alert failed: {response.status_code} {response.text}")
    except Exception as e:
        print(f"  [!] Discord request error: {e}")

# ─── Master Mitigation Handler ─────────────────────────────────────────────────

def handle_verdict(ip, verdict, forensics):
    """
    Master function called by the daemon.
    Decides whether to block and always sends Discord alert.
    """
    action = verdict.get("action", "IGNORE")
    severity = verdict.get("severity", "LOW")

    print(f"\n  [*] Handling verdict: {severity} — {action}")

    if action == "BLOCK":
        blocked = block_ip(ip)
        if blocked:
            print(f"  [+] IP {ip} has been {'flagged for blocking' if config.DRY_RUN else 'blocked'}.")
    elif action == "MONITOR":
        print(f"  [~] Monitoring mode — no block applied for {ip}.")
    else:
        print(f"  [*] Verdict is IGNORE — no action taken for {ip}.")

    send_discord_alert(ip, verdict, forensics)
