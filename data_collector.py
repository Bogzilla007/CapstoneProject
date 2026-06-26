#!/usr/bin/env python3
"""
Project Aegis - Training Data Collector
Records system behavior every 10 seconds.
"""

import time
import csv
import os
import subprocess
import psutil
from datetime import datetime

DATA_FILE = "ml_data/normal_behavior.csv"
COLLECTION_INTERVAL = 10
AUTH_LOG_PATH = "/var/log/auth.log"

def get_cpu():
    return psutil.cpu_percent(interval=1)

def get_ram():
    return psutil.virtual_memory().percent

def get_active_users():
    try:
        result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
        return len(lines)
    except:
        return 0

def get_open_ports():
    try:
        result = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
        lines = [l for l in result.stdout.strip().split("\n")[1:] if l.strip()]
        return len(lines)
    except:
        return 0

def get_failed_logins_last_window(last_position):
    count = 0
    try:
        with open(AUTH_LOG_PATH, "r") as f:
            f.seek(last_position)
            for line in f:
                if "Failed password" in line or "Invalid user" in line:
                    count += 1
            new_position = f.tell()
        return count, new_position
    except:
        return 0, last_position

def get_hour():
    return datetime.now().hour

def collect_data():
    os.makedirs("ml_data", exist_ok=True)
    file_exists = os.path.exists(DATA_FILE)

    try:
        with open(AUTH_LOG_PATH, "r") as f:
            f.seek(0, 2)
            log_position = f.tell()
    except:
        log_position = 0

    print("=" * 60)
    print("  PROJECT AEGIS — Training Data Collector")
    print(f"  Saving to : {DATA_FILE}")
    print(f"  Interval  : {COLLECTION_INTERVAL} seconds")
    print("=" * 60)
    print("\n[*] Collecting normal behavior data...")
    print("[*] Let this run for at least 30 minutes")
    print("[*] Press Ctrl+C when done\n")

    row_count = 0

    with open(DATA_FILE, "a", newline="") as csvfile:
        fieldnames = [
            "timestamp", "cpu_percent", "ram_percent",
            "failed_logins", "active_users", "open_ports", "hour_of_day"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()

        while True:
            try:
                cpu = get_cpu()
                ram = get_ram()
                failed_logins, log_position = get_failed_logins_last_window(log_position)
                users = get_active_users()
                ports = get_open_ports()
                hour = get_hour()
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                writer.writerow({
                    "timestamp": timestamp,
                    "cpu_percent": cpu,
                    "ram_percent": ram,
                    "failed_logins": failed_logins,
                    "active_users": users,
                    "open_ports": ports,
                    "hour_of_day": hour
                })
                csvfile.flush()
                row_count += 1

                print(f"  [{timestamp}] Row {row_count:4d} | "
                      f"CPU: {cpu:5.1f}% | "
                      f"RAM: {ram:5.1f}% | "
                      f"Logins: {failed_logins} | "
                      f"Users: {users} | "
                      f"Ports: {ports} | "
                      f"Hour: {hour}")

                time.sleep(COLLECTION_INTERVAL)

            except KeyboardInterrupt:
                print(f"\n[+] Collection stopped.")
                print(f"[+] {row_count} rows saved to {DATA_FILE}")
                break
            except Exception as e:
                print(f"  [!] Error: {e}")
                time.sleep(COLLECTION_INTERVAL)

if __name__ == "__main__":
    collect_data()
