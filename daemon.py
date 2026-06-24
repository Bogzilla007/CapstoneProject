#!/usr/bin/env python3
"""
Project Aegis - Main Daemon
Monitors /var/log/auth.log for SSH brute force attempts
and triggers the forensics pipeline on threshold breach.
"""

import time
import subprocess
import psutil
import re
import csv
import os
from datetime import datetime
from collections import defaultdict
import config
from llm_analyst import analyze_threat
from mitigation import handle_verdict
from system_checks import get_full_system_snapshot

def get_system_telemetry():
    uptime_seconds = time.time() - psutil.boot_time()
    uptime_str = time.strftime("%H:%M:%S", time.gmtime(uptime_seconds))
    return {
        "hostname": os.uname().nodename,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": psutil.virtual_memory().percent,
        "ram_used_gb": round(psutil.virtual_memory().used / (1024**3), 2),
        "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "uptime": uptime_str,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def print_telemetry(telemetry):
    print(f"\n[{telemetry['timestamp']}] TELEMETRY | "
          f"Host: {telemetry['hostname']} | "
          f"CPU: {telemetry['cpu_percent']}% | "
          f"RAM: {telemetry['ram_percent']}% "
          f"({telemetry['ram_used_gb']}/{telemetry['ram_total_gb']} GB) | "
          f"Uptime: {telemetry['uptime']}")

def parse_failed_login(line):
    pattern = r"(?:Failed password for(?: invalid user)? \S+ from|Invalid user \S+ from) (\d+\.\d+\.\d+\.\d+)"
    match = re.search(pattern, line)
    if match:
        return match.group(1)
    return None

def run_whois(ip):
    print(f"  [*] Running whois on {ip}...")
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=15)
        return result.stdout[:3000]
    except Exception as e:
        return f"whois lookup failed: {e}"

def run_geoip(ip):
    print(f"  [*] Running GeoIP lookup on {ip}...")
    import requests
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = response.json()
        return {
            "country": data.get("country", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", "Unknown"),
            "status": data.get("status", "Unknown")
        }
    except Exception as e:
        return {"error": str(e)}

def run_process_snapshot():
    print(f"  [*] Capturing process snapshot...")
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
        lines = result.stdout.split("\n")
        header = lines[0]
        ssh_procs = [l for l in lines[1:] if "sshd" in l or "ssh" in l]
        return header + "\n" + "\n".join(ssh_procs)
    except Exception as e:
        return f"Process snapshot failed: {e}"

def gather_forensics(ip, failed_count, raw_log_lines):
    print(f"\n[!] SENTINEL TRIGGERED — Gathering forensics on {ip}")
    telemetry = get_system_telemetry()
    whois_data = run_whois(ip)
    geo_data = run_geoip(ip)
    process_snapshot = run_process_snapshot()
    system_snapshot = get_full_system_snapshot()
    forensics = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip": ip,
        "failed_attempts": failed_count,
        "raw_log_sample": "\n".join(raw_log_lines[-10:]),
        "geo": geo_data,
        "whois": whois_data,
        "process_snapshot": process_snapshot,
        "system_telemetry": telemetry,
        "open_ports": system_snapshot["open_ports"],
        "active_users": system_snapshot["active_users"],
        "running_services": system_snapshot["running_services"]
    }
    return forensics

def save_reports(forensics, verdict=None):
    os.makedirs("reports", exist_ok=True)
    csv_exists = os.path.exists(config.CSV_REPORT_PATH)
    with open(config.CSV_REPORT_PATH, "a", newline="") as f:
        fieldnames = ["timestamp", "attacker_ip", "failed_attempts",
                      "country", "isp", "org", "severity", "action", "summary"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not csv_exists:
            writer.writeheader()
        writer.writerow({
            "timestamp": forensics["timestamp"],
            "attacker_ip": forensics["attacker_ip"],
            "failed_attempts": forensics["failed_attempts"],
            "country": forensics["geo"].get("country", "Unknown"),
            "isp": forensics["geo"].get("isp", "Unknown"),
            "org": forensics["geo"].get("org", "Unknown"),
            "severity": verdict.get("severity", "N/A") if verdict else "PENDING",
            "action": verdict.get("action", "N/A") if verdict else "PENDING",
            "summary": verdict.get("summary", "") if verdict else ""
        })

    with open(config.TEXT_REPORT_PATH, "a") as f:
        f.write("=" * 70 + "\n")
        f.write(f"INCIDENT REPORT — {forensics['timestamp']}\n")
        f.write("=" * 70 + "\n")
        f.write(f"Attacker IP    : {forensics['attacker_ip']}\n")
        f.write(f"Failed Attempts: {forensics['failed_attempts']}\n")
        f.write(f"Country        : {forensics['geo'].get('country', 'Unknown')}\n")
        f.write(f"ISP            : {forensics['geo'].get('isp', 'Unknown')}\n")
        f.write(f"Org            : {forensics['geo'].get('org', 'Unknown')}\n")
        if verdict:
            f.write(f"Severity       : {verdict.get('severity', 'N/A')}\n")
            f.write(f"Action         : {verdict.get('action', 'N/A')}\n")
            f.write(f"AI Summary     : {verdict.get('summary', '')}\n")
        f.write(f"\nOpen Ports at Time of Attack:\n")
        for p in forensics.get("open_ports", []):
            f.write(f"  Port {p.get('port','?'):6} | {p.get('address','?')}\n")
        f.write(f"\nActive Users at Time of Attack:\n")
        for u in forensics.get("active_users", []):
            f.write(f"  {u.get('user','?')} on {u.get('terminal','?')} from {u.get('source','?')}\n")
        f.write(f"\nRunning Services at Time of Attack:\n")
        for s in forensics.get("running_services", []):
            f.write(f"  {s.get('name','?'):30} | {s.get('description','?')}\n")
        f.write(f"\nProcess Snapshot:\n{forensics['process_snapshot']}\n")
        f.write(f"\nRaw Log Sample:\n{forensics['raw_log_sample']}\n")
        f.write("=" * 70 + "\n\n")
    print(f"  [+] Reports saved to {config.CSV_REPORT_PATH} and {config.TEXT_REPORT_PATH}")

def run_daemon():
    print("=" * 70)
    print("  PROJECT AEGIS — Autonomous EDR Daemon")
    print(f"  Monitoring: {config.AUTH_LOG_PATH}")
    print(f"  Threshold : {config.FAILED_LOGIN_THRESHOLD} failures in {config.TIME_WINDOW_SECONDS}s")
    print(f"  Dry Run   : {config.DRY_RUN}")
    print("=" * 70)

    failed_attempts = defaultdict(list)
    triggered_ips = set()
    ip_log_lines = defaultdict(list)
    last_telemetry_time = 0
    last_syscheck_time = 0

    with open(config.AUTH_LOG_PATH, "r") as log_file:
        log_file.seek(0, 2)
        print("\n[*] Daemon running. Watching for attacks...\n")

        while True:
            now = time.time()

            if now - last_telemetry_time >= config.TELEMETRY_INTERVAL:
                telemetry = get_system_telemetry()
                print_telemetry(telemetry)
                last_telemetry_time = now

            if now - last_syscheck_time >= 300:
                snapshot = get_full_system_snapshot()
                port_list = [p.get('port','?') for p in snapshot['open_ports']]
                user_list = [u.get('user','?') for u in snapshot['active_users']]
                print(f"  [SYS] Open ports: {port_list} | Active users: {user_list}")
                last_syscheck_time = now

            line = log_file.readline()
            if not line:
                time.sleep(0.5)
                continue

            ip = parse_failed_login(line)
            if not ip:
                continue

            current_time = time.time()
            failed_attempts[ip].append(current_time)
            ip_log_lines[ip].append(line.strip())

            failed_attempts[ip] = [
                t for t in failed_attempts[ip]
                if current_time - t <= config.TIME_WINDOW_SECONDS
            ]

            attempt_count = len(failed_attempts[ip])
            print(f"  [~] Failed login from {ip} — {attempt_count}/{config.FAILED_LOGIN_THRESHOLD} in window")

            if attempt_count >= config.FAILED_LOGIN_THRESHOLD and ip not in triggered_ips:
                triggered_ips.add(ip)
                forensics = gather_forensics(ip, attempt_count, ip_log_lines[ip])
                verdict = analyze_threat(forensics)
                save_reports(forensics, verdict)
                handle_verdict(ip, verdict, forensics)
                print(f"\n  [+] VERDICT: {verdict['severity']} — {verdict['action']}")
                print(f"  [+] {verdict['summary']}")
                print(f"  [+] Reports saved. Check reports/ folder.\n")

if __name__ == "__main__":
    run_daemon()
