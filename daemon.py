#!/usr/bin/env python3
"""
Project Aegis - Main Daemon
Monitors /var/log/auth.log for SSH brute force attempts and triggers
the forensics pipeline on threshold breach.

Thread 1: Rule Engine      - 0.5s tick, Layer 1 brute force detection
Thread 2: Collector        - 10s tick, feeds ML detector + CSV
Thread 3: ML Inference     - 10s tick, Layer 2 LSTM anomaly detection
Thread 4: Trainer          - 60min or 200 new rows, background retrainer
"""

import time
import subprocess
import psutil
import re
import csv
import os
import threading
from datetime import datetime
from collections import defaultdict

import config
from llm_analyst import analyze_threat
from mitigation import handle_verdict
from system_checks import get_full_system_snapshot
import collector
import log_parser
import threat_tracker
import ml_detector
import trainer
import resilience

# Shared state
incident_lock = threading.Lock()

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

def _is_real_ip(ip):
    """Returns True if ip is a valid IPv4/IPv6 address. False for placeholder
    labels like SYSTEM_ANOMALY used by non-network detections (e.g. ML
    resource anomalies that have no real attacker IP)."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def gather_forensics(ip, failed_count, raw_log_lines, extra_context=None):
    print(f"\n[!] SENTINEL TRIGGERED - Gathering forensics on {ip}")
    telemetry = get_system_telemetry()

    if _is_real_ip(ip):
        whois_data = run_whois(ip)
        geo_data = run_geoip(ip)
    else:
        print(f"  [*] {ip} is not a network address — skipping whois/GeoIP lookups.")
        whois_data = "N/A — non-network detection (e.g. ML resource anomaly, no real attacker IP)"
        geo_data = {
            "country": "N/A", "region": "N/A", "city": "N/A",
            "isp": "N/A", "org": "N/A", "status": "N/A"
        }

    process_snapshot = run_process_snapshot()
    system_snapshot = get_full_system_snapshot()
    forensics = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip": ip,
        "failed_attempts": failed_count,
        "raw_log_sample": "\n".join(raw_log_lines[-10:]) if raw_log_lines else "N/A",
        "geo": geo_data,
        "whois": whois_data,
        "process_snapshot": process_snapshot,
        "system_telemetry": telemetry,
        "open_ports": system_snapshot["open_ports"],
        "active_users": system_snapshot["active_users"],
        "running_services": system_snapshot["running_services"]
    }
    if extra_context:
        forensics.update(extra_context)
    return forensics

def save_reports(forensics, verdict=None):
    os.makedirs("reports", exist_ok=True)
    csv_exists = os.path.exists(config.CSV_REPORT_PATH)
    with open(config.CSV_REPORT_PATH, "a", newline="") as f:
        fieldnames = ["timestamp", "attacker_ip", "failed_attempts",
                      "country", "isp", "org", "severity", "action", "summary",
                      "detection_label", "abuse_score", "timing_pattern",
                      "usernames", "repeat_offender", "anomaly_score"]
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        if not csv_exists:
            writer.writeheader()
        writer.writerow({
            "timestamp":       forensics["timestamp"],
            "attacker_ip":     forensics["attacker_ip"],
            "failed_attempts": forensics["failed_attempts"],
            "country":         forensics["geo"].get("country", "Unknown"),
            "isp":             forensics["geo"].get("isp", "Unknown"),
            "org":             forensics["geo"].get("org", "Unknown"),
            "severity":        verdict.get("severity", "N/A") if verdict else "PENDING",
            "action":          verdict.get("action", "N/A") if verdict else "PENDING",
            "summary":         verdict.get("summary", "") if verdict else "",
            "detection_label": forensics.get("detection_label", "BRUTE_FORCE"),
            "abuse_score":     forensics.get("abuse_score", 0),
            "timing_pattern":  forensics.get("timing_pattern", "INSUFFICIENT_DATA"),
            "usernames":       "|".join(forensics.get("detected_usernames", [])),
            "repeat_offender": forensics.get("repeat_offender", False),
            "anomaly_score":   forensics.get("anomaly_score", ""),
        })
    with open(config.TEXT_REPORT_PATH, "a") as f:
        f.write("=" * 70 + "\n")
        f.write(f"INCIDENT REPORT - {forensics['timestamp']}\n")
        f.write("=" * 70 + "\n")
        f.write(f"Attacker IP     : {forensics['attacker_ip']}\n")
        f.write(f"Detection Label : {forensics.get('detection_label', 'BRUTE_FORCE')}\n")
        f.write(f"Failed Attempts : {forensics['failed_attempts']}\n")
        f.write(f"Country         : {forensics['geo'].get('country', 'Unknown')}\n")
        f.write(f"ISP             : {forensics['geo'].get('isp', 'Unknown')}\n")
        f.write(f"Org             : {forensics['geo'].get('org', 'Unknown')}\n")
        if "anomaly_score" in forensics:
            f.write(f"Anomaly Score   : {forensics['anomaly_score']}\n")
            f.write(f"Anomaly Thresh  : {forensics['anomaly_threshold']}\n")
            f.write(f"ML Phase        : {forensics.get('ml_phase', 'N/A')}\n")
            f.write(f"Detection Desc  : {forensics.get('detection_description', '')}\n")
        if verdict:
            f.write(f"Severity        : {verdict.get('severity', 'N/A')}\n")
            f.write(f"Action          : {verdict.get('action', 'N/A')}\n")
            f.write(f"AI Summary      : {verdict.get('summary', '')}\n")
        f.write("\nOpen Ports at Time of Attack:\n")
        for p in forensics.get("open_ports", []):
            f.write(f"  Port {p.get('port','?'):6} | {p.get('address','?')}\n")
        f.write("\nActive Users at Time of Attack:\n")
        for u in forensics.get("active_users", []):
            f.write(f"  {u.get('user','?')} on {u.get('terminal','?')} from {u.get('source','?')}\n")
        f.write("\nRunning Services at Time of Attack:\n")
        for s in forensics.get("running_services", []):
            f.write(f"  {s.get('name','?'):30} | {s.get('description','?')}\n")
        f.write(f"\nProcess Snapshot:\n{forensics['process_snapshot']}\n")
        f.write(f"\nRaw Log Sample:\n{forensics['raw_log_sample']}\n")
        f.write("=" * 70 + "\n\n")
    print(f"  [+] Reports saved to {config.CSV_REPORT_PATH} and {config.TEXT_REPORT_PATH}")

def run_pipeline(ip, label, failed_count=0, raw_log_lines=None, extra_context=None):
    if raw_log_lines is None:
        raw_log_lines = []
    ec = {"detection_label": label}
    if extra_context:
        ec.update(extra_context)
    forensics = gather_forensics(ip, failed_count, raw_log_lines, extra_context=ec)
    verdict = analyze_threat(forensics)
    save_reports(forensics, verdict)
    handle_verdict(ip, verdict, forensics)
    print(f"\n  [+] VERDICT: {verdict['severity']} - {verdict['action']}")
    print(f"  [+] {verdict['summary']}")
    print(f"  [+] Reports saved. Check reports/ folder.\n")

def rule_engine_thread():
    print("[RULE ENGINE] Starting - tailing auth.log")
    failed_attempts = defaultdict(list)
    triggered_ips = set()
    ip_log_lines = defaultdict(list)
    ip_parsed_events = defaultdict(list)
    last_telemetry_time = 0
    last_syscheck_time = 0
    with open(config.AUTH_LOG_PATH, "r") as log_file:
        log_file.seek(0, 2)
        print("\n[RULE ENGINE] Watching for attacks...\n")
        while True:
            now = time.time()
            if now - last_telemetry_time >= config.TELEMETRY_INTERVAL:
                telemetry = get_system_telemetry()
                print_telemetry(telemetry)
                last_telemetry_time = now
            if now - last_syscheck_time >= 300:
                snapshot = get_full_system_snapshot()
                port_list = [p.get("port", "?") for p in snapshot["open_ports"]]
                user_list = [u.get("user", "?") for u in snapshot["active_users"]]
                print(f"  [SYS] Open ports: {port_list} | Active users: {user_list}")
                last_syscheck_time = now
            line = log_file.readline()
            if not line:
                time.sleep(0.5)
                continue

            parsed = log_parser.parse_line(line)
            ip = parsed.get("ip")
            event_type = parsed.get("event_type")

            # Track all parsed events per IP for threat classification
            if ip:
                ip_parsed_events[ip].append(parsed)

            # Only count failed logins toward brute force threshold
            if event_type != "FAILED_LOGIN" or not ip:
                continue

            current_time = time.time()
            failed_attempts[ip].append(current_time)
            ip_log_lines[ip].append(line.strip())
            failed_attempts[ip] = [
                t for t in failed_attempts[ip]
                if current_time - t <= config.TIME_WINDOW_SECONDS
            ]

            attempt_count = len(failed_attempts[ip])
            username = parsed.get("username", "unknown")
            print(f"  [~] Failed login from {ip} (user: {username}) - {attempt_count}/{config.FAILED_LOGIN_THRESHOLD} in window")

            # Layer 3 — record every fail and check slow/distributed
            threat_tracker.record_fail(ip)
            layer3_hits = threat_tracker.evaluate(ip)
            for hit in layer3_hits:
                print(f"  [L3] {hit['label']} detected for {ip}")
                trainer.register_incident()
                threading.Thread(
                    target=run_pipeline,
                    args=(ip, hit['label']),
                    kwargs={
                        "failed_count": attempt_count,
                        "raw_log_lines": ip_log_lines[ip],
                        "extra_context": hit['extra_context']
                    },
                    daemon=True
                ).start()

            if attempt_count >= config.FAILED_LOGIN_THRESHOLD and ip not in triggered_ips:
                triggered_ips.add(ip)
                trainer.register_incident()

                # Full threat classification
                threat_intel = log_parser.classify_threat(
                    ip,
                    ip_parsed_events[ip],
                    failed_attempts[ip]
                )

                # Pick the most severe label
                extra_labels = threat_intel.get("threat_labels", [])
                if "BREACH_SUSPECTED" in extra_labels:
                    label = "BREACH_SUSPECTED"
                elif "PRIV_ESC_ATTEMPT" in extra_labels:
                    label = "PRIV_ESC_ATTEMPT"
                else:
                    label = "BRUTE_FORCE"

                print(f"  [!] Threat labels: {extra_labels}")
                print(f"  [!] Usernames tried: {threat_intel.get('detected_usernames')}")
                print(f"  [!] Timing pattern: {threat_intel.get('timing_pattern')}")

                threading.Thread(
                    target=run_pipeline,
                    args=(ip, label),
                    kwargs={
                        "failed_count": attempt_count,
                        "raw_log_lines": ip_log_lines[ip],
                        "extra_context": {
                            "fail_count": attempt_count,
                            "window_seconds": config.TIME_WINDOW_SECONDS,
                            **threat_intel
                        }
                    },
                    daemon=True
                ).start()

ML_INFERENCE_INTERVAL = 10

# ML_ANOMALY pipeline trigger cooldown — prevents re-firing the full
# Groq pipeline every tick while a sustained anomaly stays above threshold.
ML_ANOMALY_COOLDOWN_SECONDS = 300  # 5 minutes, matches trainer.py blackout window
_last_ml_anomaly_trigger = 0
_ml_anomaly_lock = threading.Lock()


def ml_inference_thread():
    global _last_ml_anomaly_trigger
    print("[ML INFERENCE] Starting")
    time.sleep(15)
    while True:
        try:
            result = ml_detector.check_for_anomaly()
            if result is None:
                phase = ml_detector.get_status().get('phase', 'UNKNOWN')
                print(f"[ML INFERENCE] Phase: {phase} - waiting for model")
            else:
                score, is_anomaly = result
                phase = ml_detector.get_status().get('phase', 'UNKNOWN')
                print(f"[ML INFERENCE] Score: {score:.6f} | Threshold: {ml_detector.get_status().get('threshold', 0):.6f} | Phase: {phase}")
                if is_anomaly:
                    print(f"[ML INFERENCE] *** ML_ANOMALY DETECTED *** Score={score:.6f}")
                    trainer.register_incident()

                    with _ml_anomaly_lock:
                        now = time.time()
                        seconds_since_last = now - _last_ml_anomaly_trigger
                        if seconds_since_last < ML_ANOMALY_COOLDOWN_SECONDS:
                            print(f"[ML INFERENCE] Cooldown active ({seconds_since_last:.0f}s/{ML_ANOMALY_COOLDOWN_SECONDS}s) — skipping pipeline trigger, anomaly already logged.")
                        else:
                            _last_ml_anomaly_trigger = now
                            extra = {
                                "anomaly_score": round(float(score), 6),
                                "anomaly_threshold": round(float(ml_detector.get_status().get('threshold', 0)), 6),
                                "ml_phase": phase,
                                "detection_description": (
                                    "Behavioral anomaly detected by AI model. "
                                    f"Reconstruction error {score:.6f} exceeds threshold {ml_detector.get_status().get('threshold', 0):.6f}."
                                )
                            }
                            threading.Thread(
                                target=run_pipeline,
                                args=("SYSTEM_ANOMALY", "ML_ANOMALY"),
                                kwargs={
                                    "failed_count": 0,
                                    "raw_log_lines": [],
                                    "extra_context": extra
                                },
                                daemon=True
                            ).start()
        except Exception as e:
            print(f"[ML INFERENCE] Error: {e}")
        time.sleep(ML_INFERENCE_INTERVAL)


PORT_CHECK_INTERVAL = 60

def port_watcher_thread():
    """Checks for new open ports every 60s against baseline."""
    print("[PORT WATCHER] Starting")
    while True:
        time.sleep(PORT_CHECK_INTERVAL)
        try:
            new_ports, ports_set = threat_tracker.check_new_ports()
            if new_ports:
                print(f"[PORT WATCHER] *** NEW_PORT_DETECTED *** {ports_set}")
                trainer.register_incident()
                threading.Thread(
                    target=run_pipeline,
                    args=("0.0.0.0", "NEW_PORT_DETECTED"),
                    kwargs={
                        "failed_count": 0,
                        "raw_log_lines": [],
                        "extra_context": {
                            "detection_label": "NEW_PORT_DETECTED",
                            "new_ports": list(ports_set)
                        }
                    },
                    daemon=True
                ).start()
        except Exception as e:
            print(f"[PORT WATCHER] Error: {e}")

def print_banner():
    print("=" * 70)
    print("  PROJECT AEGIS - Autonomous Security Monitoring Daemon")
    print(f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Log File  : {config.AUTH_LOG_PATH}")
    print(f"  Threshold : {config.FAILED_LOGIN_THRESHOLD} failures in {config.TIME_WINDOW_SECONDS}s")
    print(f"  Dry Run   : {config.DRY_RUN}")
    print("=" * 70)
    print("  Thread 1  : Rule Engine   (Layer 1 - Brute Force, 0.5s tick)")
    print("  Thread 2  : Collector     (Layer 2 - Data feed, 10s tick)")
    print("  Thread 3  : ML Inference  (Layer 2 - LSTM Anomaly, 10s tick)")
    print("  Thread 4  : Trainer       (Layer 2 - Self-improving, 60min)")
    print("  Thread 5  : Port Watcher  (Layer 3 - New port detection, 60s)")
    print("  Thread 6  : Resilience    (Self-defense - UFW integrity 60s / Log tamper 30s)")
    print("=" * 70)

def main():
    print_banner()
    threat_tracker.initialize_port_baseline()
    collector.start()
    print("[MAIN] Thread 2 (Collector) started")
    trainer.start()
    print("[MAIN] Thread 4 (Trainer) started")
    t_ml = threading.Thread(target=ml_inference_thread, name="ML-Inference", daemon=True)
    t_ml.start()
    print("[MAIN] Thread 3 (ML Inference) started")
    t_port = threading.Thread(target=port_watcher_thread, name="Port-Watcher", daemon=True)
    t_port.start()
    print("[MAIN] Thread 5 (Port Watcher) started")
    t_rule = threading.Thread(target=rule_engine_thread, name="Rule-Engine", daemon=True)
    t_rule.start()
    print("[MAIN] Thread 1 (Rule Engine) started")
    resilience.start_resilience_threads()
    print("[MAIN] Thread 6 (Resilience) started")
    print("[MAIN] All threads live. Aegis is defending.\n")
    try:
        while True:
            time.sleep(60)
            living = [t.name for t in threading.enumerate() if t.is_alive()]
            print(f"[HEARTBEAT] Active threads: {living}")
    except KeyboardInterrupt:
        print("\n[MAIN] Shutdown signal received. Stopping Aegis.")

if __name__ == "__main__":
    main()
