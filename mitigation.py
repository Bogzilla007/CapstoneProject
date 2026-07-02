#!/usr/bin/env python3
"""
Project Aegis - Active Mitigation & Discord Alerting
Handles ufw blocking, auto-expiry, and tiered Discord notifications.
"""

import subprocess
import requests
import json
import os
import time
from datetime import datetime
import config
import runtime_paths

# ─── Blocklist ─────────────────────────────────────────────────────────────────

BLOCKLIST_PATH = runtime_paths.as_str(runtime_paths.BLOCKLIST_PATH)

def load_blocklist():
    """Returns dict of ip -> {severity, timestamp, expiry} for all blocked IPs."""
    if not os.path.exists(BLOCKLIST_PATH):
        return {}
    entries = {}
    with open(BLOCKLIST_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            ip = parts[0]
            entries[ip] = {
                "severity": parts[1] if len(parts) > 1 else "UNKNOWN",
                "timestamp": parts[2] if len(parts) > 2 else "",
                "expiry": float(parts[3]) if len(parts) > 3 else 0,
                "summary": parts[4] if len(parts) > 4 else ""
            }
    return entries

def is_block_expired(ip):
    """Returns True if the block for this IP has expired."""
    entries = load_blocklist()
    if ip not in entries:
        return False
    expiry = entries[ip].get("expiry", 0)
    if expiry == 0:
        return False  # permanent block
    return time.time() > expiry

def save_to_blocklist(ip, severity, summary, expiry_seconds=0):
    """Appends or updates a blocked IP in the blocklist."""
    os.makedirs(os.path.dirname(BLOCKLIST_PATH), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    expiry_ts = time.time() + expiry_seconds if expiry_seconds > 0 else 0
    with open(BLOCKLIST_PATH, "a") as f:
        f.write(f"{ip},{severity},{timestamp},{expiry_ts},{summary[:80]}\n")

def get_active_blocks():
    """Returns dict of IPs that are currently blocked and not expired."""
    entries = load_blocklist()
    active = {}
    for ip, data in entries.items():
        expiry = data.get("expiry", 0)
        if expiry == 0 or time.time() < expiry:
            active[ip] = data
    return active

# ─── UFW Blocking ──────────────────────────────────────────────────────────────

def block_ip(ip, severity="HIGH"):
    """
    Executes ufw deny for the given IP.
    Respects DRY_RUN and auto-expiry from config.BLOCK_EXPIRY.
    Skips whitelisted IPs.
    """
    # Whitelist check
    whitelist = getattr(config, "IP_WHITELIST", [])
    if ip in whitelist:
        print(f"  [*] {ip} is whitelisted — skipping block.")
        return False

    # Already actively blocked?
    active = get_active_blocks()
    if ip in active and not is_block_expired(ip):
        print(f"  [*] {ip} is already actively blocked. Skipping.")
        return False

    # Get expiry duration for this severity
    expiry_map = getattr(config, "BLOCK_EXPIRY", {})
    expiry_seconds = expiry_map.get(severity, 0)
    expiry_label = f"{expiry_seconds//3600}hr" if expiry_seconds > 0 else "permanent"

    if config.DRY_RUN:
        print(f"  [DRY RUN] Would execute: sudo ufw deny from {ip}")
        print(f"  [DRY RUN] Block duration: {expiry_label}")
        save_to_blocklist(ip, "DRY_RUN", "Dry run mode", expiry_seconds)
        return True

    try:
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"  [+] BLOCKED: ufw rule added for {ip} ({expiry_label})")
            save_to_blocklist(ip, severity, "ufw rule applied", expiry_seconds)
            return True
        else:
            print(f"  [!] ufw block failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"  [!] Block execution error: {e}")
        return False

def unblock_ip(ip):
    """Removes ufw rule for an expired block. Returns True on success, False on failure."""
    if config.DRY_RUN:
        print(f"  [DRY RUN] Would execute: sudo ufw delete deny from {ip}")
        return True
    
    cmd = ["sudo", "ufw", "delete", "deny", "from", ip]
    # Check if running as non-root and pkexec is available for GUI escalation
    if os.name == "posix" and os.getuid() != 0:
        import shutil
        if shutil.which("pkexec"):
            cmd = ["pkexec", "ufw", "delete", "deny", "from", ip]
            
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"  [+] Unblocked {ip}")
            return True
        else:
            print(f"  [!] Unblock failed for {ip}: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"  [!] Unblock error for {ip}: {e}")
        return False

def remove_from_blocklist(ip):
    """Removes an IP entry from the blocklist file, handling permission issues using pkexec if needed."""
    if not os.path.exists(BLOCKLIST_PATH):
        return True
    try:
        lines = []
        with open(BLOCKLIST_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line_strip = line.strip()
                if not line_strip:
                    continue
                parts = line_strip.split(",")
                if parts[0] == ip:
                    continue
                lines.append(line)
        
        try:
            with open(BLOCKLIST_PATH, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True
        except PermissionError:
            if os.name == "posix":
                import tempfile
                fd, tmp_path = tempfile.mkstemp(suffix=".txt")
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.writelines(lines)
                    cmd = ["pkexec", "sh", "-c", f"cp {tmp_path} {BLOCKLIST_PATH} && chmod 0644 {BLOCKLIST_PATH} && rm -f {tmp_path}"]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    return result.returncode == 0
                finally:
                    if os.path.exists(tmp_path):
                        try: os.unlink(tmp_path)
                        except Exception: pass
            else:
                raise
    except Exception as e:
        print(f"  [!] Failed to remove {ip} from blocklist file: {e}")
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

SEVERITY_COLOR = {
    "CRITICAL": 0xFF0000,
    "HIGH":     0xFF4500,
    "MEDIUM":   0xFFA500,
    "LOW":      0x00FF00
}

def _build_embed(ip, verdict, forensics, include_full_forensics=False):
    """Build the Discord embed payload."""
    severity = verdict.get("severity", "UNKNOWN")
    action = verdict.get("action", "UNKNOWN")
    summary = verdict.get("summary", "No summary available.")
    geo = forensics.get("geo", {})
    detection_label = forensics.get("detection_label", "UNKNOWN")

    sev_emoji = SEVERITY_EMOJI.get(severity, "⚠️")
    act_emoji = ACTION_EMOJI.get(action, "❓")

    fields = [
        {"name": "🌐 Attacker IP",      "value": ip,                                         "inline": True},
        {"name": "🏷️ Detection",         "value": detection_label,                            "inline": True},
        {"name": "🏳️ Country",           "value": geo.get("country", "Unknown"),              "inline": True},
        {"name": "🏢 ISP / Org",         "value": geo.get("isp", "Unknown"),                  "inline": True},
        {"name": "❌ Failed Attempts",   "value": str(forensics.get("failed_attempts", "?")), "inline": True},
        {"name": "⚡ Severity",          "value": severity,                                   "inline": True},
        {"name": "🔧 Action Taken",      "value": action,                                     "inline": True},
        {"name": "📋 AI Summary",        "value": summary[:1000],                             "inline": False},
    ]

    # Extra threat intel fields if present
    if forensics.get("detected_usernames"):
        fields.append({"name": "👤 Usernames Tried", "value": ", ".join(forensics["detected_usernames"]), "inline": True})
    if forensics.get("timing_pattern"):
        fields.append({"name": "⏱️ Timing Pattern", "value": forensics["timing_pattern"], "inline": True})
    if forensics.get("threat_labels"):
        fields.append({"name": "🏴 Threat Labels", "value": ", ".join(forensics["threat_labels"]), "inline": False})
    if forensics.get("repeat_offender"):
        fields.append({"name": "🔁 Repeat Offender", "value": f"Yes — {forensics.get('previous_incident_count', '?')} prior incidents", "inline": True})
    if forensics.get("anomaly_score"):
        fields.append({"name": "🤖 ML Anomaly Score", "value": str(forensics["anomaly_score"]), "inline": True})

    if include_full_forensics:
        open_ports = forensics.get("open_ports", [])
        port_str = ", ".join(str(p.get("port", "?")) for p in open_ports) or "None"
        fields.append({"name": "🔌 Open Ports", "value": port_str, "inline": True})
        active_users = forensics.get("active_users", [])
        user_str = ", ".join(u.get("user", "?") for u in active_users) or "None"
        fields.append({"name": "👥 Active Users", "value": user_str, "inline": True})

    return {
        "title": f"{sev_emoji} {severity} — {detection_label} — {action} {act_emoji}",
        "color": SEVERITY_COLOR.get(severity, 0x808080),
        "fields": fields,
        "footer": {"text": f"Project Aegis EDR • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"},
        "thumbnail": {"url": "https://i.imgur.com/4M34hi2.png"}
    }

def send_discord_alert(ip, verdict, forensics):
    """
    Tiered Discord alert based on severity.
    LOW      → log only, no Discord message
    MEDIUM   → standard embed
    HIGH     → @here + embed
    CRITICAL → @here + full forensics embed
    """
    if not config.DISCORD_WEBHOOK_URL or config.DISCORD_WEBHOOK_URL == "your_discord_webhook_url_here":
        print("  [!] Discord webhook not configured. Skipping alert.")
        return

    severity = verdict.get("severity", "LOW")
    escalation_map = getattr(config, "DISCORD_ESCALATION", {})
    escalation = escalation_map.get(severity, "MESSAGE")

    if escalation == "LOG_ONLY":
        print(f"  [~] Discord: LOW severity — logged only, no message sent.")
        return

    include_full = escalation == "HERE_FORENSICS"
    mention = "@here\n" if escalation in ("HERE", "HERE_FORENSICS") else ""
    embed = _build_embed(ip, verdict, forensics, include_full_forensics=include_full)

    payload = {
        "username": "Project Aegis",
        "avatar_url": "https://i.imgur.com/4M34hi2.png",
        "content": mention,
        "embeds": [embed]
    }

    try:
        response = requests.post(config.DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        if response.status_code == 204:
            print(f"  [+] Discord alert sent ({escalation}).")
        else:
            print(f"  [!] Discord alert failed: {response.status_code} {response.text}")
    except Exception as e:
        print(f"  [!] Discord request error: {e}")

# ─── Master Mitigation Handler ─────────────────────────────────────────────────

def handle_verdict(ip, verdict, forensics):
    """
    Master function called by the daemon.
    Checks whitelist, applies block with expiry, sends tiered Discord alert.
    """
    action = verdict.get("action", "IGNORE")
    severity = verdict.get("severity", "LOW")

    print(f"\n  [*] Handling verdict: {severity} — {action}")

    # Whitelist check before any action
    whitelist = getattr(config, "IP_WHITELIST", [])
    if ip in whitelist:
        print(f"  [*] {ip} is whitelisted — no action taken.")
        send_discord_alert(ip, verdict, forensics)
        return

    if action == "BLOCK":
        blocked = block_ip(ip, severity=severity)
        if blocked:
            expiry_map = getattr(config, "BLOCK_EXPIRY", {})
            expiry_seconds = expiry_map.get(severity, 0)
            expiry_label = f"{expiry_seconds//3600}hr" if expiry_seconds > 0 else "permanent"
            print(f"  [+] IP {ip} {'flagged for blocking' if config.DRY_RUN else 'blocked'} ({expiry_label}).")
    elif action == "MONITOR":
        print(f"  [~] Monitoring mode — no block applied for {ip}.")
    else:
        print(f"  [*] Verdict is IGNORE — no action taken for {ip}.")

    send_discord_alert(ip, verdict, forensics)

