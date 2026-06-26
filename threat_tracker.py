#!/usr/bin/env python3
"""
Project Aegis - threat_tracker.py
Layer 3 slow attack detection.
Tracks low-and-slow probes, persistent attackers, distributed attacks,
repeat offenders, and new port appearances.
"""

import os
import csv
import time
import threading
import subprocess
from datetime import datetime
from collections import defaultdict

import config

# ── State ─────────────────────────────────────────────────────────────────────

_lock = threading.Lock()

# IP -> list of unix timestamps (all failed logins, no expiry — we manage windows manually)
_ip_timestamps = defaultdict(list)

# Distributed attack tracking: timestamp -> set of IPs that failed in last 10 min
_recent_ips = {}  # ip -> last_fail_timestamp

# Port baseline
_port_baseline = set()
_baseline_ready = False

# Already triggered flags to avoid duplicate alerts
_triggered_slow = set()       # IPs that already triggered SLOW_PROBE
_triggered_persistent = set() # IPs that already triggered PERSISTENT_PROBE
_distributed_triggered = False

# ── Constants ─────────────────────────────────────────────────────────────────

WINDOW_1HR  = 3600
WINDOW_24HR = 86400
WINDOW_10MIN = 600
SLOW_PROBE_THRESHOLD = 3
PERSISTENT_PROBE_THRESHOLD = 10
DISTRIBUTED_IP_THRESHOLD = 10
DISTRIBUTED_FAILS_MAX = 2   # IPs with 1-2 fails count toward distributed

# ── Record a failed login ─────────────────────────────────────────────────────

def record_fail(ip):
    """Call this every time a failed login is seen for an IP."""
    now = time.time()
    with _lock:
        _ip_timestamps[ip].append(now)
        _recent_ips[ip] = now

# ── Slow probe check ──────────────────────────────────────────────────────────

def check_slow_probe(ip):
    """
    Returns (label, count) if this IP qualifies for SLOW_PROBE or
    PERSISTENT_PROBE, else (None, 0).
    Only triggers once per IP per label.
    """
    now = time.time()
    with _lock:
        timestamps = _ip_timestamps[ip]
        count_1hr  = sum(1 for t in timestamps if now - t <= WINDOW_1HR)
        count_24hr = sum(1 for t in timestamps if now - t <= WINDOW_24HR)

        if count_24hr >= PERSISTENT_PROBE_THRESHOLD and ip not in _triggered_persistent:
            _triggered_persistent.add(ip)
            return "PERSISTENT_PROBE", count_24hr

        if count_1hr >= SLOW_PROBE_THRESHOLD and ip not in _triggered_slow:
            _triggered_slow.add(ip)
            return "SLOW_PROBE", count_1hr

    return None, 0

# ── Distributed attack check ──────────────────────────────────────────────────

def check_distributed_attack():
    """
    Returns (True, ip_count) if 10+ different IPs each have 1-2 fails
    in the last 10 minutes. Triggers only once.
    """
    global _distributed_triggered
    if _distributed_triggered:
        return False, 0

    now = time.time()
    with _lock:
        qualifying_ips = []
        for ip, last_ts in _recent_ips.items():
            if now - last_ts > WINDOW_10MIN:
                continue
            count = sum(1 for t in _ip_timestamps[ip] if now - t <= WINDOW_10MIN)
            if 1 <= count <= DISTRIBUTED_FAILS_MAX:
                qualifying_ips.append(ip)

        if len(qualifying_ips) >= DISTRIBUTED_IP_THRESHOLD:
            _distributed_triggered = True
            return True, len(qualifying_ips)

    return False, 0

# ── Repeat offender check ─────────────────────────────────────────────────────

def check_repeat_offender(ip):
    """
    Returns (True, previous_count) if IP appears in incidents.csv history.
    """
    csv_path = getattr(config, "CSV_REPORT_PATH", "reports/incidents.csv")
    if not os.path.exists(csv_path):
        return False, 0
    try:
        count = 0
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("attacker_ip") == ip:
                    count += 1
        return count > 0, count
    except Exception:
        return False, 0

# ── Port baseline + new port detection ────────────────────────────────────────

def _get_open_ports():
    """Return set of currently open port strings from ss."""
    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=10
        )
        ports = set()
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                port = addr.split(":")[-1]
                if port.isdigit():
                    ports.add(port)
        return ports
    except Exception:
        return set()

def initialize_port_baseline():
    """Call once at startup to record baseline open ports."""
    global _port_baseline, _baseline_ready
    with _lock:
        _port_baseline = _get_open_ports()
        _baseline_ready = True
    print(f"[THREAT TRACKER] Port baseline set: {_port_baseline}")

def check_new_ports():
    """
    Returns (True, new_ports_set) if any ports appeared since baseline.
    Returns (False, set()) otherwise.
    """
    if not _baseline_ready:
        return False, set()
    current = _get_open_ports()
    with _lock:
        new_ports = current - _port_baseline
    if new_ports:
        return True, new_ports
    return False, set()

# ── Full Layer 3 check for a given IP ────────────────────────────────────────

def evaluate(ip):
    """
    Run all Layer 3 checks for a given IP after a failed login.
    Returns a list of dicts, each with keys: label, extra_context
    One dict per triggered detection. Empty list = nothing triggered.
    """
    results = []

    # Slow / persistent probe
    label, count = check_slow_probe(ip)
    if label:
        is_repeat, repeat_count = check_repeat_offender(ip)
        results.append({
            "label": label,
            "extra_context": {
                "detection_label": label,
                "fail_count_in_window": count,
                "repeat_offender": is_repeat,
                "previous_incident_count": repeat_count
            }
        })

    # Distributed attack (global check)
    is_distributed, ip_count = check_distributed_attack()
    if is_distributed:
        results.append({
            "label": "DISTRIBUTED_ATTACK",
            "extra_context": {
                "detection_label": "DISTRIBUTED_ATTACK",
                "unique_ips_in_window": ip_count,
                "window_minutes": WINDOW_10MIN // 60
            }
        })

    return results
