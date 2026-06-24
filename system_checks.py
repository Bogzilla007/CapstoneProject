#!/usr/bin/env python3
"""
Project Aegis - System Security Checks
Handles open ports, active users, and running services enumeration.
"""

import subprocess
import psutil
from datetime import datetime


# ─── Open Ports ────────────────────────────────────────────────────────────────

def get_open_ports():
    """
    Returns list of open listening ports with process info.
    Uses ss command (modern replacement for netstat).
    """
    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")
        ports = []
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                local_address = parts[3]
                port = local_address.split(":")[-1]
                process = parts[6] if len(parts) > 6 else "unknown"
                # Clean up process string like users:(("sshd",pid=1065,fd=3))
                if "(" in process:
                    try:
                        process = process.split('"')[1]
                    except IndexError:
                        pass
                ports.append({
                    "port": port,
                    "address": local_address,
                    "process": process,
                    "state": parts[0]
                })
        return ports
    except Exception as e:
        return [{"error": str(e)}]


# ─── Active Users ──────────────────────────────────────────────────────────────

def get_active_users():
    """
    Returns list of currently logged in users.
    Uses who command.
    """
    try:
        result = subprocess.run(
            ["who"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")
        users = []
        for line in lines:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                users.append({
                    "user": parts[0],
                    "terminal": parts[1],
                    "date": parts[2],
                    "time": parts[3],
                    "source": parts[4] if len(parts) > 4 else "local"
                })
        return users
    except Exception as e:
        return [{"error": str(e)}]


# ─── Running Services ──────────────────────────────────────────────────────────

def get_running_services():
    """
    Returns list of active running systemd services.
    """
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service",
             "--state=running", "--no-pager", "--no-legend"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")
        services = []
        for line in lines:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                services.append({
                    "name": parts[0].replace(".service", ""),
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": " ".join(parts[4:]) if len(parts) > 4 else ""
                })
        return services
    except Exception as e:
        return [{"error": str(e)}]


# ─── Full System Snapshot ──────────────────────────────────────────────────────

def get_full_system_snapshot():
    """
    Master function — runs all checks and returns
    a single structured dict with everything.
    """
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": get_open_ports(),
        "active_users": get_active_users(),
        "running_services": get_running_services()
    }


# ─── Standalone Test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    print("[*] Running system security checks...\n")
    snapshot = get_full_system_snapshot()

    print(f"Timestamp: {snapshot['timestamp']}\n")

    print("=" * 50)
    print("OPEN PORTS")
    print("=" * 50)
    for p in snapshot["open_ports"]:
        print(f"  Port {p.get('port','?'):6} | {p.get('address','?'):25} | {p.get('process','?')}")

    print("\n" + "=" * 50)
    print("ACTIVE USERS")
    print("=" * 50)
    if snapshot["active_users"]:
        for u in snapshot["active_users"]:
            print(f"  {u.get('user','?'):10} | {u.get('terminal','?'):8} | {u.get('date','?')} {u.get('time','?')} | {u.get('source','?')}")
    else:
        print("  No active users detected.")

    print("\n" + "=" * 50)
    print("RUNNING SERVICES")
    print("=" * 50)
    for s in snapshot["running_services"]:
        print(f"  {s.get('name','?'):30} | {s.get('description','?')}")
