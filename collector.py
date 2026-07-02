"""
collector.py — Background data collection thread for Project Aegis

Samples 6 system features every 10 seconds.
Feeds ml_detector rolling window AND appends to training CSV.
Uses trainer._lock to protect CSV writes.
"""

import os
import csv
import time
import threading
import psutil
import subprocess
from datetime import datetime

import config
import ml_detector
import runtime_paths
import trainer

# ── Paths ────────────────────────────────────────────────────────────────────
CSV_PATH  = runtime_paths.as_str(runtime_paths.SYSTEM_METRICS_CSV)
AUTH_LOG  = config.AUTH_LOG_PATH

# ── Config ───────────────────────────────────────────────────────────────────
COLLECT_INTERVAL = 10   # seconds

# ── State ────────────────────────────────────────────────────────────────────
_running = False


# ─────────────────────────────────────────────────────────────────────────────
def _count_recent_failed_logins(window_seconds=120):
    """
    Count failed SSH login attempts in auth.log within the last window_seconds.
    Returns 0 if log unreadable.
    """
    try:
        now    = time.time()
        count  = 0
        cutoff = now - window_seconds

        with open(AUTH_LOG, "r", errors="ignore") as f:
            for line in f:
                if "Failed password" in line or "Invalid user" in line:
                    try:
                        # auth.log format: "Jun 26 14:32:01 ..."
                        parts    = line.split()
                        log_time = datetime.strptime(
                            f"{parts[0]} {parts[1]} {parts[2]} {datetime.now().year}",
                            "%b %d %H:%M:%S %Y"
                        ).timestamp()
                        if log_time >= cutoff:
                            count += 1
                    except Exception:
                        continue
        return count
    except Exception:
        return 0


def _count_active_users():
    """Count unique logged-in users via 'who'."""
    try:
        result = subprocess.run(["who"], capture_output=True, text=True)
        lines  = [l for l in result.stdout.strip().split("\n") if l.strip()]
        return len(lines)
    except Exception:
        return 0


def _count_open_ports():
    """Count listening TCP/UDP ports via psutil."""
    try:
        conns = psutil.net_connections()
        return sum(1 for c in conns if c.status == "LISTEN")
    except Exception:
        return 0


def _ensure_csv():
    """Create CSV with header if it doesn't exist."""
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    if not os.path.exists(CSV_PATH):
        with open(CSV_PATH, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "cpu_percent", "ram_percent",
                "failed_logins", "active_users", "open_ports", "hour_of_day"
            ])
        # Group-writable so dashboard user (in aegis group) can also read
        if os.name == "posix":
            try:
                os.chmod(CSV_PATH, 0o664)
            except OSError:
                pass
        print(f"[COLLECTOR] Created CSV at {CSV_PATH}", flush=True)
    else:
        # Fix permissions on existing file if needed
        if os.name == "posix":
            try:
                os.chmod(CSV_PATH, 0o664)
            except OSError:
                pass


# ─────────────────────────────────────────────────────────────────────────────
def collect_sample():
    """
    Collect one telemetry snapshot.
    Returns dict of feature values.
    """
    cpu          = psutil.cpu_percent(interval=1)
    ram          = psutil.virtual_memory().percent
    failed       = _count_recent_failed_logins()
    active_users = _count_active_users()
    open_ports   = _count_open_ports()
    hour         = datetime.now().hour
    ts           = datetime.now().isoformat()

    return {
        "timestamp":     ts,
        "cpu_percent":   cpu,
        "ram_percent":   ram,
        "failed_logins": failed,
        "active_users":  active_users,
        "open_ports":    open_ports,
        "hour_of_day":   hour,
    }


# ─────────────────────────────────────────────────────────────────────────────
def _collector_loop():
    """Background thread main loop."""
    global _running

    _ensure_csv()
    print("[COLLECTOR] Background collector started", flush=True)

    while _running:
        try:
            sample = collect_sample()

            # Feed ML detector rolling window
            ml_detector.add_sample(
                sample["cpu_percent"],
                sample["ram_percent"],
                sample["failed_logins"],
                sample["active_users"],
                sample["open_ports"],
                sample["hour_of_day"],
            )

            # Append to CSV (protected by trainer lock)
            with trainer._lock:
                with open(CSV_PATH, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        sample["timestamp"],
                        sample["cpu_percent"],
                        sample["ram_percent"],
                        sample["failed_logins"],
                        sample["active_users"],
                        sample["open_ports"],
                        sample["hour_of_day"],
                    ])

            print(
                f"[COLLECTOR] cpu={sample['cpu_percent']:.1f}% "
                f"ram={sample['ram_percent']:.1f}% "
                f"fails={sample['failed_logins']} "
                f"users={sample['active_users']} "
                f"ports={sample['open_ports']} "
                f"hour={sample['hour_of_day']}",
                flush=True
            )

        except Exception as e:
            print(f"[COLLECTOR] Error: {e}", flush=True)

        time.sleep(COLLECT_INTERVAL)


# ─────────────────────────────────────────────────────────────────────────────
def start():
    """Start the background collector thread. Call once from daemon.py."""
    global _running
    _running = True
    t = threading.Thread(target=_collector_loop, name="collector", daemon=True)
    t.start()
    print("[COLLECTOR] Thread launched", flush=True)


def stop():
    """Signal the collector loop to exit."""
    global _running
    _running = False

