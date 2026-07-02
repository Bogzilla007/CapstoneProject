"""
resilience.py — Project Aegis (Session 15)
Self-defense layer: watches Aegis's own enforcement mechanisms.

Thread 6 (spawns 2 sub-threads):
1. ufw_integrity_check() — every 60s. Verifies every currently-active
   (non-expired) IP from mitigation.get_active_blocks() still has a
   live ufw rule. If missing, re-applies it directly and alerts.
2. log_tamper_check()    — every 30s. Watches /var/log/auth.log size +
   inode. Size shrinking or inode changing fires a LOG_TAMPER verdict
   through mitigation.handle_verdict() (same master entrypoint used
   by the rest of the pipeline).

Must be run inside a process started with sudo (same as daemon.py),
since both ufw status checks and re-adding ufw rules require root.
"""

import os
import subprocess
import threading
import time
from datetime import datetime

import config
import mitigation

AUTH_LOG_PATH = config.AUTH_LOG_PATH

_tamper_state_lock = threading.Lock()
_last_log_size = None
_last_log_inode = None


def _log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[resilience] [{timestamp}] {msg}")


# UFW Integrity Check

def _ip_has_ufw_rule(ip):
    """Checks if ufw currently has a deny rule for this IP."""
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status"],
            capture_output=True, text=True, timeout=10
        )
        return ip in result.stdout
    except Exception as e:
        _log(f"ufw status check failed: {e}")
        return True


def _force_readd_ufw_rule(ip):
    """
    Directly re-applies the ufw deny rule for an IP that mitigation's
    blocklist says is still actively blocked but ufw has lost it
    (rules flushed, ufw reset, reboot without persistence, tampering).
    Bypasses block_ip()'s already-blocked guard since that guard is
    exactly wrong here.
    """
    if config.DRY_RUN:
        _log(f"[DRY_RUN] Would re-add ufw deny rule for {ip}")
        return True
    try:
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            _log(f"Re-added ufw deny rule for {ip}")
            return True
        _log(f"ufw re-add failed for {ip}: {result.stderr}")
        return False
    except Exception as e:
        _log(f"ufw re-add error for {ip}: {e}")
        return False


def ufw_integrity_check_once():
    """Single pass - checks all active blocked IPs against live ufw rules."""
    if config.DRY_RUN:
        return

    active = mitigation.get_active_blocks()
    if not active:
        return

    for ip, data in active.items():
        if _ip_has_ufw_rule(ip):
            continue

        severity = data.get("severity", "HIGH")
        _log(f"INTEGRITY VIOLATION: {ip} missing from ufw rules. Re-adding (severity={severity}).")
        success = _force_readd_ufw_rule(ip)

        verdict = {
            "severity": severity,
            "action": "BLOCK" if success else "MONITOR",
            "summary": (
                f"UFW rule for {ip} was found missing during routine integrity "
                f"check and has been re-applied." if success else
                f"UFW rule for {ip} was found missing and re-application FAILED. "
                f"Manual intervention required."
            ),
        }
        forensics = {
            "detection_label": "UFW_INTEGRITY_VIOLATION",
            "failed_attempts": "N/A",
            "geo": {},
            "threat_labels": ["UFW_INTEGRITY_VIOLATION"],
        }
        mitigation.handle_verdict(ip, verdict, forensics)


def ufw_integrity_loop(stop_event=None, interval=60):
    _log("ufw_integrity_check thread started")
    while True:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            ufw_integrity_check_once()
        except Exception as e:
            _log(f"Unhandled error in integrity check: {e}")
        time.sleep(interval)


# Log Tamper Check

def _get_log_size_and_inode(path):
    try:
        stat = os.stat(path)
        return stat.st_size, stat.st_ino
    except FileNotFoundError:
        return None, None
    except PermissionError:
        return None, None


def _fire_tamper_verdict(severity, summary):
    """
    Routes a LOG_TAMPER event through mitigation.handle_verdict(), the
    same master entrypoint the rest of the pipeline uses. action is
    always MONITOR since there is no attacker IP to block.
    """
    verdict = {
        "severity": severity,
        "action": "MONITOR",
        "summary": summary,
    }
    forensics = {
        "detection_label": "LOG_TAMPER",
        "failed_attempts": "N/A",
        "geo": {},
        "threat_labels": ["LOG_TAMPER"],
    }
    mitigation.handle_verdict("N/A (log file)", verdict, forensics)


def log_tamper_check_once():
    global _last_log_size, _last_log_inode

    current_size, current_inode = _get_log_size_and_inode(AUTH_LOG_PATH)

    if current_size is None:
        _log("TAMPER: auth.log missing or inaccessible")
        _fire_tamper_verdict(
            "CRITICAL",
            f"{AUTH_LOG_PATH} is missing or inaccessible. This may indicate log deletion."
        )
        return

    with _tamper_state_lock:
        if _last_log_size is None:
            _last_log_size = current_size
            _last_log_inode = current_inode
            return

        size_shrank = current_size < _last_log_size
        inode_changed = current_inode != _last_log_inode

        if size_shrank:
            _log(f"TAMPER: log size shrank ({_last_log_size} -> {current_size})")
            _fire_tamper_verdict(
                "CRITICAL",
                f"{AUTH_LOG_PATH} size decreased from {_last_log_size} to "
                f"{current_size} bytes. Possible log truncation or deletion."
            )
        elif inode_changed:
            _log(f"TAMPER WARNING: log inode changed ({_last_log_inode} -> {current_inode})")
            _fire_tamper_verdict(
                "HIGH",
                f"{AUTH_LOG_PATH} inode changed from {_last_log_inode} to "
                f"{current_inode}. Could be logrotate, or could be file replacement."
            )

        _last_log_size = current_size
        _last_log_inode = current_inode


def log_tamper_loop(stop_event=None, interval=30):
    _log("log_tamper_check thread started")
    while True:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            log_tamper_check_once()
        except Exception as e:
            _log(f"Unhandled error in tamper check: {e}")
        time.sleep(interval)


# Entry point for daemon.py

def start_resilience_threads(stop_event=None):
    """
    Launches both resilience checks as background daemon threads.
    This is Thread 6 conceptually, spawning 2 sub-threads internally.
    """
    t_ufw = threading.Thread(
        target=ufw_integrity_loop, args=(stop_event, 60),
        daemon=True, name="UFW-Integrity"
    )
    t_tamper = threading.Thread(
        target=log_tamper_loop, args=(stop_event, 30),
        daemon=True, name="Log-Tamper"
    )
    t_ufw.start()
    t_tamper.start()
    _log("Resilience threads launched (UFW-Integrity, Log-Tamper)")
    return t_ufw, t_tamper


if __name__ == "__main__":
    _log("Running resilience.py standalone for testing (Ctrl+C to stop). Run with sudo.")
    stop_event = threading.Event()
    start_resilience_threads(stop_event)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        _log("Stopped.")
