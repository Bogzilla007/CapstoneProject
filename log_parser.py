#!/usr/bin/env python3
"""
Project Aegis - log_parser.py
Deep auth.log parsing and threat classification.
Extracts usernames, detects privilege escalation, breach, unusual hours,
and timing patterns from raw auth.log lines.
"""

import re
import time
import statistics
from datetime import datetime

import config

# ── Regex patterns ────────────────────────────────────────────────────────────

# Failed SSH login — covers both valid and invalid users
RE_FAILED = re.compile(
    r"Failed password for(?: invalid user)? (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# Successful SSH login
RE_SUCCESS = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# sudo failure
RE_SUDO_FAIL = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure;.*?(?:ruser=(\S+)|user=(\S+))|"
    r"sudo:\s*(\S+)\s*:\s*(?:\d+ incorrect password attempts?|auth failure|authentication failure)"
)

# sudo success (privilege use)
RE_SUDO_OK = re.compile(
    r"sudo:.*USER=(\S+).*COMMAND=(.+)"
)

# Invalid user (separate pattern for clarity)
RE_INVALID_USER = re.compile(
    r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# ── Parse a single line ───────────────────────────────────────────────────────

def parse_line(line):
    """
    Parse a single auth.log line.
    Returns a dict with keys: event_type, username, ip, raw, timestamp
    event_type is one of: FAILED_LOGIN, SUCCESSFUL_LOGIN, SUDO_FAIL,
                          SUDO_OK, INVALID_USER, UNKNOWN
    """
    result = {
        "event_type": "UNKNOWN",
        "username": None,
        "ip": None,
        "raw": line.strip(),
        "timestamp": time.time()
    }

    m = RE_FAILED.search(line)
    if m:
        result["event_type"] = "FAILED_LOGIN"
        result["username"] = m.group(1).lower()
        result["ip"] = m.group(2)
        return result

    m = RE_INVALID_USER.search(line)
    if m:
        result["event_type"] = "FAILED_LOGIN"
        result["username"] = m.group(1).lower()
        result["ip"] = m.group(2)
        return result

    m = RE_SUCCESS.search(line)
    if m:
        result["event_type"] = "SUCCESSFUL_LOGIN"
        result["username"] = m.group(1).lower()
        result["ip"] = m.group(2)
        return result

    m = RE_SUDO_FAIL.search(line)
    if m:
        result["event_type"] = "SUDO_FAIL"
        matched_user = next((g for g in m.groups() if g), None)
        result["username"] = matched_user.lower() if matched_user else "unknown"
        return result

    m = RE_SUDO_OK.search(line)
    if m:
        result["event_type"] = "SUDO_OK"
        result["username"] = m.group(1).lower()
        result["command"] = m.group(2).strip()
        return result

    return result

# ── Timing pattern analysis ───────────────────────────────────────────────────

def analyze_timing(timestamps):
    """
    Given a list of unix timestamps, determine if the pattern is:
    AUTOMATED  — regular intervals (low std dev), likely a tool
    HUMAN      — irregular intervals, likely manual
    INSUFFICIENT — not enough data points
    Returns (pattern_label, avg_interval, std_dev)
    """
    if len(timestamps) < 3:
        return "INSUFFICIENT_DATA", 0, 0

    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    avg = statistics.mean(intervals)
    std = statistics.stdev(intervals) if len(intervals) > 1 else 0

    # If std dev is less than 20% of mean, it is highly regular = automated tool
    if avg > 0 and (std / avg) < 0.20:
        label = "AUTOMATED_TOOL"
    else:
        label = "HUMAN_OPERATOR"

    return label, round(avg, 2), round(std, 2)

# ── Unusual hour detection ────────────────────────────────────────────────────

def is_unusual_hour(active_hours=None):
    """
    Returns True if current hour is outside configured active hours.
    active_hours: tuple (start_hour, end_hour) in 24h format, e.g. (8, 20)
    Defaults to config.ACTIVE_HOURS if set, otherwise (7, 22).
    """
    if active_hours is None:
        active_hours = getattr(config, "ACTIVE_HOURS", (7, 22))
    current_hour = datetime.now().hour
    start, end = active_hours
    return not (start <= current_hour < end)

# ── High-value username detection ─────────────────────────────────────────────

PRIVILEGED_USERS = {"root", "admin", "administrator", "sudo", "wheel", "kali"}

def is_privileged_user(username):
    if username is None:
        return False
    return username.lower() in PRIVILEGED_USERS

# ── Threat classifier ─────────────────────────────────────────────────────────

def classify_threat(ip, parsed_events, failed_timestamps):
    """
    Given a list of parsed events and failed login timestamps for an IP,
    return a dict of threat intelligence to merge into forensics.

    Keys returned:
      detected_usernames   — set of usernames tried
      privileged_targets   — subset of detected_usernames that are privileged
      timing_pattern       — AUTOMATED_TOOL / HUMAN_OPERATOR / INSUFFICIENT_DATA
      avg_interval         — average seconds between attempts
      std_dev_interval     — std dev of intervals
      unusual_hour         — True/False
      current_hour         — int
      threat_labels        — list of extra labels beyond base detection
      sudo_failures        — count of sudo failures seen
    """
    usernames = set()
    sudo_failures = 0
    successful_logins = []

    for ev in parsed_events:
        if ev.get("username"):
            usernames.add(ev["username"])
        if ev["event_type"] == "SUDO_FAIL":
            sudo_failures += 1
        if ev["event_type"] == "SUCCESSFUL_LOGIN" and ev.get("ip") == ip:
            successful_logins.append(ev)

    privileged_targets = {u for u in usernames if is_privileged_user(u)}
    timing_pattern, avg_interval, std_dev = analyze_timing(failed_timestamps)
    unusual = is_unusual_hour()
    current_hour = datetime.now().hour

    threat_labels = []

    if sudo_failures > 0:
        threat_labels.append("PRIV_ESC_ATTEMPT")

    if successful_logins:
        threat_labels.append("BREACH_SUSPECTED")

    if unusual:
        threat_labels.append("UNUSUAL_HOUR")

    if privileged_targets:
        threat_labels.append("PRIVILEGED_USER_TARGETED")

    if timing_pattern == "AUTOMATED_TOOL":
        threat_labels.append("AUTOMATED_ATTACK")

    return {
        "detected_usernames": list(usernames),
        "privileged_targets": list(privileged_targets),
        "timing_pattern": timing_pattern,
        "avg_interval_seconds": avg_interval,
        "std_dev_interval": std_dev,
        "unusual_hour": unusual,
        "current_hour": current_hour,
        "threat_labels": threat_labels,
        "sudo_failures": sudo_failures,
        "successful_logins_after_fails": len(successful_logins)
    }
