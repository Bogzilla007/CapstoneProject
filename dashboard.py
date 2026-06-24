#!/usr/bin/env python3
"""
Project Aegis - Streamlit C2 Dashboard
"""

import streamlit as st
import pandas as pd
import psutil
import time
import os
from datetime import datetime
import config
from system_checks import get_full_system_snapshot

st.set_page_config(
    page_title="Project Aegis — C2 Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    h1, h2, h3 { color: #58a6ff; }
    .header-bar {
        background: linear-gradient(90deg, #161b22, #1f2937);
        border-bottom: 2px solid #58a6ff;
        padding: 10px 20px;
        border-radius: 8px;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="header-bar">
    <h1 style="margin:0; color:#58a6ff;">🛡️ PROJECT AEGIS — Command & Control Dashboard</h1>
    <p style="margin:0; color:#8b949e;">Autonomous EDR & AI Investigator</p>
</div>
""", unsafe_allow_html=True)

def get_telemetry():
    uptime_seconds = time.time() - psutil.boot_time()
    hours = int(uptime_seconds // 3600)
    minutes = int((uptime_seconds % 3600) // 60)
    return {
        "cpu": psutil.cpu_percent(interval=1),
        "ram": psutil.virtual_memory().percent,
        "ram_used": round(psutil.virtual_memory().used / (1024**3), 2),
        "ram_total": round(psutil.virtual_memory().total / (1024**3), 2),
        "uptime": f"{hours}h {minutes}m",
        "hostname": os.uname().nodename
    }

def load_incidents():
    if not os.path.exists(config.CSV_REPORT_PATH):
        return pd.DataFrame()
    try:
        return pd.read_csv(config.CSV_REPORT_PATH)
    except Exception:
        return pd.DataFrame()

def load_blocklist():
    blocklist_path = "reports/blocklist.txt"
    if not os.path.exists(blocklist_path):
        return []
    with open(blocklist_path, "r") as f:
        lines = [l.strip() for l in f if l.strip()]
    entries = []
    for line in lines:
        parts = line.split(",", 3)
        if len(parts) >= 3:
            entries.append({
                "ip": parts[0],
                "severity": parts[1],
                "timestamp": parts[2],
                "reason": parts[3] if len(parts) > 3 else ""
            })
    return entries

def severity_color(severity):
    colors = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8800",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#44ff44",
        "PENDING":  "#8b949e"
    }
    return colors.get(str(severity).upper(), "#8b949e")

# ── Telemetry ──
st.subheader("📊 Live System Telemetry")
tel = get_telemetry()
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("🖥️ Hostname", tel["hostname"])
with col2:
    st.metric("⚡ CPU Usage", f"{tel['cpu']}%")
with col3:
    st.metric("🧠 RAM Usage", f"{tel['ram']}%")
with col4:
    st.metric("💾 RAM Used", f"{tel['ram_used']} / {tel['ram_total']} GB")
with col5:
    st.metric("⏱️ Uptime", tel["uptime"])

# ── Charts ──
st.subheader("📈 Resource Utilization")
if "cpu_history" not in st.session_state:
    st.session_state.cpu_history = []
    st.session_state.ram_history = []
    st.session_state.time_history = []

st.session_state.cpu_history.append(tel["cpu"])
st.session_state.ram_history.append(tel["ram"])
st.session_state.time_history.append(datetime.now().strftime("%H:%M:%S"))
st.session_state.cpu_history = st.session_state.cpu_history[-30:]
st.session_state.ram_history = st.session_state.ram_history[-30:]
st.session_state.time_history = st.session_state.time_history[-30:]

chart_data = pd.DataFrame({
    "CPU %": st.session_state.cpu_history,
    "RAM %": st.session_state.ram_history
}, index=st.session_state.time_history)
st.line_chart(chart_data, color=["#58a6ff", "#ff6b6b"])

# ── System Security Checks ──
st.subheader("🔍 Live System Security Checks")
snapshot = get_full_system_snapshot()

st.markdown("---")

# Open Ports
with st.expander("🔌 Open Ports", expanded=True):
    ports_data = []
    for p in snapshot["open_ports"]:
        if "error" not in p:
            ports_data.append({
                "Port": p.get("port", "?"),
                "Address": p.get("address", "?"),
                "Process": p.get("process", "unknown"),
                "State": p.get("state", "?")
            })
    if ports_data:
        st.dataframe(
            pd.DataFrame(ports_data),
            width="stretch",
            hide_index=True
        )
    else:
        st.info("No open ports detected.")

# Active Users
with st.expander("👤 Active Users", expanded=True):
    users_data = []
    for u in snapshot["active_users"]:
        if "error" not in u:
            users_data.append({
                "User": u.get("user", "?"),
                "Terminal": u.get("terminal", "?"),
                "Date": u.get("date", "?"),
                "Time": u.get("time", "?"),
                "Source": u.get("source", "local")
            })
    if users_data:
        st.dataframe(
            pd.DataFrame(users_data),
            width="stretch",
            hide_index=True
        )
    else:
        st.info("No active users detected.")

# Running Services
with st.expander("⚙️ Running Services", expanded=True):
    services_data = []
    for s in snapshot["running_services"]:
        if "error" not in s:
            services_data.append({
                "Service": s.get("name", "?"),
                "Status": s.get("sub", "?"),
                "Description": s.get("description", "")
            })
    if services_data:
        st.dataframe(
            pd.DataFrame(services_data),
            width="stretch",
            hide_index=True
        )
    else:
        st.info("No running services found.")

st.markdown("---")

# ── Incident Summary ──
st.subheader("🚨 Incident Summary")
df = load_incidents()

if df.empty:
    st.info("No incidents detected yet. Daemon is watching...")
else:
    total = len(df)
    critical = len(df[df["severity"] == "CRITICAL"]) if "severity" in df.columns else 0
    blocked = len(df[df["action"] == "BLOCK"]) if "action" in df.columns else 0
    unique_ips = df["attacker_ip"].nunique() if "attacker_ip" in df.columns else 0

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("📋 Total Incidents", total)
    with c2:
        st.metric("🚨 Critical", critical)
    with c3:
        st.metric("🔒 IPs Blocked", blocked)
    with c4:
        st.metric("🌐 Unique Attackers", unique_ips)

# ── Threat Feed ──
st.subheader("🔴 Live Threat Feed")
if df.empty:
    st.info("No threats detected yet.")
else:
    display_df = df.sort_values("timestamp", ascending=False) if "timestamp" in df.columns else df
    for _, row in display_df.iterrows():
        severity = str(row.get("severity", "UNKNOWN")).upper()
        color = severity_color(severity)
        action = row.get("action", "N/A")
        ip = row.get("attacker_ip", "N/A")
        country = row.get("country", "Unknown")
        isp = row.get("isp", "Unknown")
        attempts = row.get("failed_attempts", "?")
        summary = row.get("summary", "No summary available.")
        timestamp = row.get("timestamp", "N/A")
        st.markdown(f"""
        <div style="background:#161b22; border-left: 4px solid {color};
                    border-radius:6px; padding:12px; margin-bottom:10px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:{color}; font-size:16px; font-weight:bold;">
                    ⚠️ {severity} — {action}
                </span>
                <span style="color:#8b949e; font-size:12px;">{timestamp}</span>
            </div>
            <div style="margin-top:8px; color:#c9d1d9;">
                🌐 <b>IP:</b> {ip} &nbsp;|&nbsp;
                🏳️ <b>Country:</b> {country} &nbsp;|&nbsp;
                🏢 <b>ISP:</b> {isp} &nbsp;|&nbsp;
                ❌ <b>Attempts:</b> {attempts}
            </div>
            <div style="margin-top:8px; color:#8b949e; font-size:13px;">
                📋 {summary}
            </div>
        </div>
        """, unsafe_allow_html=True)

# ── Kill Chain ──
st.subheader("🔒 Kill Chain — Blocked IPs")
blocklist = load_blocklist()
if not blocklist:
    st.info("No IPs blocked yet.")
else:
    for entry in reversed(blocklist):
        color = severity_color(entry["severity"])
        st.markdown(f"""
        <div style="background:#161b22; border-left: 4px solid {color};
                    border-radius:6px; padding:10px; margin-bottom:8px;">
            <span style="color:{color}; font-weight:bold;">🚫 {entry['ip']}</span>
            &nbsp;|&nbsp;
            <span style="color:#8b949e;">{entry['severity']}</span>
            &nbsp;|&nbsp;
            <span style="color:#8b949e;">{entry['timestamp']}</span>
            &nbsp;|&nbsp;
            <span style="color:#8b949e;">{entry['reason']}</span>
        </div>
        """, unsafe_allow_html=True)

# ── Export ──
st.subheader("📥 Export Reports")
col_a, col_b = st.columns(2)
with col_a:
    if os.path.exists(config.CSV_REPORT_PATH):
        with open(config.CSV_REPORT_PATH, "rb") as f:
            st.download_button(
                label="⬇️ Download CSV Report",
                data=f,
                file_name="aegis_incidents.csv",
                mime="text/csv"
            )
    else:
        st.button("⬇️ Download CSV Report", disabled=True)
with col_b:
    if os.path.exists(config.TEXT_REPORT_PATH):
        with open(config.TEXT_REPORT_PATH, "rb") as f:
            st.download_button(
                label="⬇️ Download Text Report",
                data=f,
                file_name="aegis_incidents.txt",
                mime="text/plain"
            )
    else:
        st.button("⬇️ Download Text Report", disabled=True)

# ── Footer ──
st.markdown("---")
st.caption(f"🔄 Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Auto-refreshes every 10 seconds")
time.sleep(10)
st.rerun()
