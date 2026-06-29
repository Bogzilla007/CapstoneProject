#!/usr/bin/env python3
"""
Project Aegis — SOC Dashboard (Session 17)
Five-tab Streamlit C2 interface.
Tabs: Overview | Incidents | ML Status | Timeline | Block Manager
"""

import streamlit as st
import pandas as pd
import psutil
import plotly.graph_objects as go
import time
import os
import json
import subprocess
from datetime import datetime
import config
from system_checks import get_full_system_snapshot

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Project Aegis — SOC Dashboard",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── Global CSS ────────────────────────────────────────────────────────────────
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
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: bold;
        margin-right: 4px;
    }
    .stTabs [data-baseweb="tab"] { color: #8b949e; }
    .stTabs [aria-selected="true"] { color: #58a6ff !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="header-bar">
    <h1 style="margin:0; color:#58a6ff;">PROJECT AEGIS &mdash; SOC Dashboard</h1>
    <p style="margin:0; color:#8b949e;">
        Autonomous EDR &nbsp;&middot;&nbsp; AI Investigator &nbsp;&middot;&nbsp; Multi-Layer Detection
    </p>
</div>
""", unsafe_allow_html=True)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR       = os.path.expanduser("~/project-aegis")
METRICS_CSV    = os.path.join(BASE_DIR, "ml_data", "system_metrics.csv")
SCORES_CSV     = os.path.join(BASE_DIR, "ml_data", "anomaly_scores.csv")
META_JSON      = os.path.join(BASE_DIR, "ml_data", "model", "metadata.json")
BLOCKLIST_PATH = os.path.join(BASE_DIR, "reports", "blocklist.txt")

# ── Helper functions ──────────────────────────────────────────────────────────
def severity_color(sev):
    return {
        "CRITICAL": "#ff4444", "HIGH": "#ff8800",
        "MEDIUM":   "#ffcc00", "LOW":  "#44ff44",
    }.get(str(sev).upper(), "#8b949e")

def severity_emoji(sev):
    return {
        "CRITICAL": "CRIT", "HIGH": "HIGH",
        "MEDIUM":   "MED",  "LOW":  "LOW",
    }.get(str(sev).upper(), "???")

def detection_badge_html(label):
    cfg = {
        "BRUTE_FORCE":        ("#ff4444", "BRUTE FORCE"),
        "ML_ANOMALY":         ("#a371f7", "ML ANOMALY"),
        "SLOW_PROBE":         ("#ff8800", "SLOW PROBE"),
        "PERSISTENT_PROBE":   ("#ff6600", "PERSISTENT"),
        "DISTRIBUTED_ATTACK": ("#ff0000", "DISTRIBUTED"),
        "PRIV_ESC":           ("#ff4444", "PRIV ESC"),
        "BREACH_SUSPECTED":   ("#ff0000", "BREACH"),
        "UNUSUAL_LOGIN":      ("#ffcc00", "UNUSUAL LOGIN"),
        "NEW_PORT_DETECTED":  ("#58a6ff", "NEW PORT"),
        "LOG_TAMPER":         ("#ff4444", "LOG TAMPER"),
        "UFW_TAMPER":         ("#ff4444", "UFW TAMPER"),
    }
    color, text = cfg.get(str(label).upper(), ("#8b949e", str(label)))
    return (
        '<span class="badge" style="background:' + color + '22;color:' + color
        + ';border:1px solid ' + color + ';">' + text + '</span>'
    )

def get_telemetry():
    uptime  = time.time() - psutil.boot_time()
    return {
        "cpu":       psutil.cpu_percent(interval=1),
        "ram":       psutil.virtual_memory().percent,
        "ram_used":  round(psutil.virtual_memory().used  / (1024**3), 2),
        "ram_total": round(psutil.virtual_memory().total / (1024**3), 2),
        "uptime":    f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m",
        "hostname":  os.uname().nodename,
    }

def load_incidents():
    csv_path = os.path.join(BASE_DIR, 'reports', 'incidents.csv')
    if not os.path.exists(csv_path):
        return pd.DataFrame()
    try:
        df = pd.read_csv(csv_path)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df
    except Exception:
        return pd.DataFrame()

def load_ml_metadata():
    if not os.path.exists(META_JSON):
        return {}
    try:
        with open(META_JSON) as f:
            return json.load(f)
    except Exception:
        return {}

def load_system_metrics(n=60):
    if not os.path.exists(METRICS_CSV):
        return pd.DataFrame()
    try:
        df = pd.read_csv(METRICS_CSV)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df.tail(n)
    except Exception:
        return pd.DataFrame()

def load_anomaly_scores(n=60):
    if not os.path.exists(SCORES_CSV):
        return pd.DataFrame()
    try:
        df = pd.read_csv(SCORES_CSV)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df.tail(n)
    except Exception:
        return pd.DataFrame()

def load_blocklist():
    if not os.path.exists(BLOCKLIST_PATH):
        return []
    entries = []
    try:
        with open(BLOCKLIST_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",", 4)
                ip       = parts[0] if len(parts) > 0 else "?"
                sev      = parts[1] if len(parts) > 1 else "?"
                ts       = parts[2] if len(parts) > 2 else "?"
                if len(parts) == 5:
                    expiry  = parts[3]
                    summary = parts[4]
                else:
                    expiry  = "DRY_RUN" if sev == "DRY_RUN" else "0"
                    summary = parts[3] if len(parts) > 3 else ""
                entries.append({"ip": ip, "severity": sev,
                                "timestamp": ts, "expiry": expiry, "summary": summary})
    except Exception:
        pass
    return entries

def expiry_display(expiry, severity):
    if severity == "DRY_RUN" or expiry in ("DRY_RUN", ""):
        return "DRY RUN"
    try:
        exp = float(expiry)
        if exp == 0:
            return "PERMANENT"
        remaining = exp - time.time()
        if remaining <= 0:
            return "EXPIRED"
        return f"{int(remaining // 3600)}h {int((remaining % 3600) // 60)}m left"
    except Exception:
        return str(expiry)

def plotly_dark_layout(height=350):
    return dict(
        paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
        font=dict(color="#c9d1d9"),
        xaxis=dict(gridcolor="#21262d"),
        yaxis=dict(gridcolor="#21262d"),
        height=height,
        margin=dict(l=40, r=20, t=20, b=40),
        showlegend=True,
        legend=dict(bgcolor="#161b22"),
    )

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Overview",
    "Incidents",
    "ML Status",
    "Timeline",
    "Block Manager",
])

# ════════════════════════════════════════════════════════════════════════════════
# TAB 1 — OVERVIEW
# ════════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("Live System Telemetry")
    tel = get_telemetry()
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1: st.metric("Hostname",  tel["hostname"])
    with c2: st.metric("CPU",       f"{tel['cpu']}%")
    with c3: st.metric("RAM",       f"{tel['ram']}%")
    with c4: st.metric("RAM Used",  f"{tel['ram_used']} / {tel['ram_total']} GB")
    with c5: st.metric("Uptime",    tel["uptime"])

    st.subheader("Resource Utilization (live)")
    if "cpu_history" not in st.session_state:
        st.session_state.cpu_history  = []
        st.session_state.ram_history  = []
        st.session_state.time_history = []
    st.session_state.cpu_history.append(tel["cpu"])
    st.session_state.ram_history.append(tel["ram"])
    st.session_state.time_history.append(datetime.now().strftime("%H:%M:%S"))
    st.session_state.cpu_history  = st.session_state.cpu_history[-30:]
    st.session_state.ram_history  = st.session_state.ram_history[-30:]
    st.session_state.time_history = st.session_state.time_history[-30:]
    chart_df = pd.DataFrame(
        {"CPU %": st.session_state.cpu_history, "RAM %": st.session_state.ram_history},
        index=st.session_state.time_history,
    )
    st.line_chart(chart_df, color=["#58a6ff", "#ff6b6b"])

    st.subheader("Live System Security Checks")
    snapshot = get_full_system_snapshot()

    with st.expander("Open Ports", expanded=True):
        ports = [
            {"Port": p.get("port","?"), "Address": p.get("address","?"),
             "Process": p.get("process","unknown"), "State": p.get("state","?")}
            for p in snapshot["open_ports"] if "error" not in p
        ]
        if ports:
            st.dataframe(pd.DataFrame(ports), hide_index=True)
        else:
            st.info("No open ports.")

    with st.expander("Active Users", expanded=True):
        users = [
            {"User": u.get("user","?"), "Terminal": u.get("terminal","?"),
             "Date": u.get("date","?"), "Time": u.get("time","?"), "Source": u.get("source","local")}
            for u in snapshot["active_users"] if "error" not in u
        ]
        if users:
            st.dataframe(pd.DataFrame(users), hide_index=True)
        else:
            st.info("No active users.")

    with st.expander("Running Services", expanded=True):
        svcs = [
            {"Service": s.get("name","?"), "Status": s.get("sub","?"), "Description": s.get("description","")}
            for s in snapshot["running_services"] if "error" not in s
        ]
        if svcs:
            st.dataframe(pd.DataFrame(svcs), hide_index=True)
        else:
            st.info("No services found.")

    st.markdown("---")
    st.subheader("Export Reports")
    ca, cb = st.columns(2)
    with ca:
        if os.path.exists(config.CSV_REPORT_PATH):
            with open(config.CSV_REPORT_PATH, "rb") as fh:
                st.download_button("Download CSV Report", fh, "aegis_incidents.csv", "text/csv")
        else:
            st.button("Download CSV Report", disabled=True)
    with cb:
        if os.path.exists(config.TEXT_REPORT_PATH):
            with open(config.TEXT_REPORT_PATH, "rb") as fh:
                st.download_button("Download Text Report", fh, "aegis_incidents.txt", "text/plain")
        else:
            st.button("Download Text Report", disabled=True)

# ════════════════════════════════════════════════════════════════════════════════
# TAB 2 — INCIDENTS
# ════════════════════════════════════════════════════════════════════════════════
with tab2:
    df = load_incidents()

    if df.empty:
        st.info("No incidents detected yet. Daemon is watching...")
    else:
        total      = len(df)
        critical   = int((df["severity"] == "CRITICAL").sum()) if "severity"    in df.columns else 0
        blocked    = int((df["action"]   == "BLOCK").sum())    if "action"      in df.columns else 0
        unique_ips = df["attacker_ip"].nunique()                if "attacker_ip" in df.columns else 0

        c1, c2, c3, c4 = st.columns(4)
        with c1: st.metric("Total Incidents", total)
        with c2: st.metric("Critical",        critical)
        with c3: st.metric("IPs Blocked",     blocked)
        with c4: st.metric("Unique Attackers", unique_ips)

        st.markdown("---")
        st.subheader("Incident Feed")
        display_df = df.sort_values("timestamp", ascending=False) if "timestamp" in df.columns else df

        for _, row in display_df.iterrows():
            sev    = str(row.get("severity", "UNKNOWN")).upper()
            color  = severity_color(sev)
            action = str(row.get("action", "N/A"))
            ip     = str(row.get("attacker_ip", "N/A"))
            ts_raw = row.get("timestamp", "N/A")
            ts     = ts_raw.strftime("%Y-%m-%d %H:%M:%S") if hasattr(ts_raw, "strftime") else str(ts_raw)
            country  = str(row.get("country",         "Unknown"))
            isp      = str(row.get("isp",             "Unknown"))
            attempts = str(row.get("failed_attempts", "?"))
            summary  = str(row.get("summary",         "No summary."))
            det_lbl  = str(row.get("detection_label", "BRUTE_FORCE"))

            # Build badge row
            badges = detection_badge_html(det_lbl)

            abuse_raw = row.get("abuse_score", None)
            if abuse_raw is not None and str(abuse_raw) not in ("", "nan", "0"):
                try:
                    a  = int(float(abuse_raw))
                    ac = "#ff4444" if a >= 80 else "#ff8800" if a >= 50 else "#ffcc00"
                    badges += (
                        '<span class="badge" style="background:' + ac + '22;color:' + ac
                        + ';border:1px solid ' + ac + ';">ABUSE ' + str(a) + '%</span>'
                    )
                except Exception:
                    pass

            if str(row.get("repeat_offender", "")).lower() in ("true", "1"):
                badges += '<span class="badge" style="background:#ff444422;color:#ff4444;border:1px solid #ff4444;">REPEAT</span>'

            timing = str(row.get("timing_pattern", ""))
            if timing not in ("", "nan", "INSUFFICIENT_DATA", "None"):
                tc = "#ff4444" if "AUTOMATED" in timing else "#58a6ff"
                badges += (
                    '<span class="badge" style="background:' + tc + '22;color:' + tc
                    + ';border:1px solid ' + tc + ';">' + timing + '</span>'
                )

            # Extra detail lines
            extra = ""
            usernames = str(row.get("usernames", ""))
            if usernames not in ("", "nan", "None"):
                names = usernames.replace("|", ", ")
                extra += ("<div style='margin-top:4px;color:#8b949e;font-size:12px;'>"
                          "Targeted users: <span style='color:#c9d1d9;'>" + names + "</span></div>")

            anom = str(row.get("anomaly_score", ""))
            if anom not in ("", "nan", "None"):
                try:
                    extra += ("<div style='margin-top:4px;color:#8b949e;font-size:12px;'>"
                              "Anomaly score: <span style='color:#a371f7;'>"
                              + f"{float(anom):.6f}" + "</span></div>")
                except Exception:
                    pass

            with st.expander(f"[{sev}]  {ip}  —  {ts}", expanded=False):
                st.markdown(
                    "<div style='padding:6px;'>"
                    "<div style='margin-bottom:8px;'>" + badges + "</div>"
                    "<div style='color:#c9d1d9;margin-bottom:4px;'>"
                    "IP: <b>" + ip + "</b> &nbsp;|&nbsp; "
                    "Country: " + country + " &nbsp;|&nbsp; "
                    "ISP: " + isp + " &nbsp;|&nbsp; "
                    "Attempts: " + attempts + " &nbsp;|&nbsp; "
                    "Action: <span style='color:" + color + ";'>" + action + "</span>"
                    "</div>"
                    + extra +
                    "<div style='margin-top:8px;color:#8b949e;font-size:13px;"
                    "border-top:1px solid #21262d;padding-top:6px;'>"
                    + summary + "</div></div>",
                    unsafe_allow_html=True,
                )

# ════════════════════════════════════════════════════════════════════════════════
# TAB 3 — ML STATUS
# ════════════════════════════════════════════════════════════════════════════════
with tab3:
    meta       = load_ml_metadata()
    scores_df  = load_anomaly_scores(60)
    metrics_df = load_system_metrics(60)

    st.subheader("Model Status")

    if not meta:
        st.warning("No model metadata found. Train the model first.")
    else:
        threshold     = meta.get("threshold", "N/A")
        trained_at    = meta.get("trained_at", "N/A")
        seq_len       = meta.get("sequence_length", meta.get("timesteps", "N/A"))
        epochs        = meta.get("epochs_trained", "N/A")
        val_loss      = meta.get("final_val_loss", "N/A")
        retrain_count = meta.get("retrain_count", 0)
        clean_rows    = meta.get("clean_rows", "N/A")

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            thr_display = f"{float(threshold):.6f}" if isinstance(threshold, (int, float)) else str(threshold)
            st.metric("Anomaly Threshold", thr_display)
        with m2:
            st.metric("Last Trained", str(trained_at)[:16] if trained_at != "N/A" else "N/A")
        with m3:
            st.metric("Retrain Cycles", retrain_count)
        with m4:
            st.metric("Clean Training Rows", clean_rows)

        m5, m6, m7 = st.columns(3)
        with m5: st.metric("Sequence Length", seq_len)
        with m6: st.metric("Epochs Trained",  epochs)
        with m7:
            vl_display = f"{float(val_loss):.6f}" if isinstance(val_loss, (int, float)) else str(val_loss)
            st.metric("Final Val Loss", vl_display)

        feats = meta.get("features", [])
        if feats:
            st.markdown("**Features:** " + "  ·  ".join(f"`{f}`" for f in feats))

    st.markdown("---")
    st.subheader("Live Anomaly Score Graph")

    if not scores_df.empty and "score" in scores_df.columns:
        threshold_val = float(meta.get("threshold", 0.072743)) if meta else 0.072743
        anomaly_mask  = scores_df.get("is_anomaly", pd.Series([False] * len(scores_df)))

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=scores_df["timestamp"],
            y=scores_df["score"],
            mode="lines+markers",
            name="Anomaly Score",
            line=dict(color="#a371f7", width=2),
            marker=dict(
                size=5,
                color=["#ff4444" if v else "#a371f7" for v in anomaly_mask],
            ),
        ))
        fig.add_hline(
            y=threshold_val,
            line_dash="dash",
            line_color="#ff4444",
            annotation_text=f"Threshold {threshold_val:.4f}",
            annotation_position="top right",
        )
        layout = plotly_dark_layout(350)
        layout["xaxis"]["title"] = "Time"
        layout["yaxis"]["title"] = "MAE Score"
        fig.update_layout(**layout)
        st.plotly_chart(fig, use_container_width=True)

        n_anomalies = int(anomaly_mask.sum()) if hasattr(anomaly_mask, "sum") else 0
        if n_anomalies > 0:
            st.warning(f"{n_anomalies} anomalous readings in last 60 samples")
        else:
            st.success("All recent readings within normal range")
    else:
        st.info("Anomaly score history not yet available. Start the daemon to begin collecting scores.")

    if not metrics_df.empty and "cpu_percent" in metrics_df.columns:
        st.markdown("---")
        st.subheader("System Telemetry History (last 60 samples)")
        fig2 = go.Figure()
        fig2.add_trace(go.Scatter(
            x=metrics_df["timestamp"], y=metrics_df["cpu_percent"],
            mode="lines", name="CPU %", line=dict(color="#58a6ff"),
        ))
        fig2.add_trace(go.Scatter(
            x=metrics_df["timestamp"], y=metrics_df["ram_percent"],
            mode="lines", name="RAM %", line=dict(color="#ff6b6b"),
        ))
        layout2 = plotly_dark_layout(280)
        layout2["yaxis"]["range"] = [0, 100]
        fig2.update_layout(**layout2)
        st.plotly_chart(fig2, use_container_width=True)

# ════════════════════════════════════════════════════════════════════════════════
# TAB 4 — TIMELINE
# ════════════════════════════════════════════════════════════════════════════════
with tab4:
    df = load_incidents()

    if df.empty or "timestamp" not in df.columns:
        st.info("No incident data yet for timeline analysis.")
    else:
        df_ts = df.dropna(subset=["timestamp"]).copy()
        df_ts["hour"] = df_ts["timestamp"].dt.hour
        df_ts["date"] = df_ts["timestamp"].dt.strftime("%Y-%m-%d")

        st.subheader("Attack Heatmap — Hour of Day vs Date")
        heat  = df_ts.groupby(["date", "hour"]).size().reset_index(name="count")
        if not heat.empty:
            pivot = heat.pivot(index="date", columns="hour", values="count").fillna(0)
            for h in range(24):
                if h not in pivot.columns:
                    pivot[h] = 0
            pivot = pivot[sorted(pivot.columns)]

            fig_heat = go.Figure(data=go.Heatmap(
                z=pivot.values,
                x=[f"{h:02d}:00" for h in pivot.columns],
                y=pivot.index.tolist(),
                colorscale=[[0, "#161b22"], [0.5, "#ff8800"], [1.0, "#ff4444"]],
                showscale=True,
                hoverongaps=False,
            ))
            layout_h = plotly_dark_layout(max(200, 60 * len(pivot) + 80))
            layout_h["xaxis"]["title"] = "Hour of Day"
            layout_h["yaxis"]["title"] = "Date"
            fig_heat.update_layout(**layout_h)
            st.plotly_chart(fig_heat, use_container_width=True)

        st.markdown("---")
        col_a, col_b = st.columns(2)

        with col_a:
            st.subheader("Top 5 Attacking IPs")
            if "attacker_ip" in df_ts.columns:
                top_ips = df_ts["attacker_ip"].value_counts().head(5).reset_index()
                top_ips.columns = ["IP Address", "Incidents"]
                st.dataframe(top_ips, hide_index=True, use_container_width=True)
            else:
                st.info("No IP data available.")

        with col_b:
            st.subheader("Top 5 Targeted Usernames")
            if "usernames" in df_ts.columns:
                all_users = []
                for val in df_ts["usernames"].dropna():
                    if str(val) not in ("", "nan"):
                        all_users.extend(str(val).split("|"))
                if all_users:
                    top_u = pd.Series(all_users).value_counts().head(5).reset_index()
                    top_u.columns = ["Username", "Times Targeted"]
                    st.dataframe(top_u, hide_index=True, use_container_width=True)
                else:
                    st.info("No username data yet (requires Session 13+ log parser).")
            else:
                st.info("No username column found. Run daemon to generate new incidents.")

        st.markdown("---")
        st.subheader("Severity Distribution")
        if "severity" in df.columns:
            sev_c = df["severity"].value_counts().reset_index()
            sev_c.columns = ["Severity", "Count"]
            clr_map = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44ff44"}
            fig_bar = go.Figure(data=[go.Bar(
                x=sev_c["Severity"],
                y=sev_c["Count"],
                marker_color=[clr_map.get(s, "#8b949e") for s in sev_c["Severity"]],
            )])
            layout_b = plotly_dark_layout(250)
            layout_b["showlegend"] = False
            fig_bar.update_layout(**layout_b)
            st.plotly_chart(fig_bar, use_container_width=True)

# ════════════════════════════════════════════════════════════════════════════════
# TAB 5 — BLOCK MANAGER
# ════════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("Active Block Manager")
    blocklist = load_blocklist()

    if config.DRY_RUN:
        st.warning(
            "DRY_RUN = True in config.py — IPs are logged but not actually blocked. "
            "Set DRY_RUN = False to enable real enforcement."
        )

    if not blocklist:
        st.info("No blocked IPs on record.")
    else:
        for entry in reversed(blocklist):
            ip      = entry["ip"]
            sev     = entry["severity"]
            ts      = entry["timestamp"]
            expiry  = entry["expiry"]
            summary = entry["summary"]
            color   = severity_color(sev) if sev != "DRY_RUN" else "#8b949e"
            exp_txt = expiry_display(expiry, sev)

            with st.expander(f"BLOCKED  {ip}    {sev}    {exp_txt}", expanded=False):
                st.markdown(
                    "<div style='color:#c9d1d9;padding:4px;'>"
                    "<b>Blocked at:</b> " + ts + "<br>"
                    "<b>Status:</b> <span style='color:" + color + ";'>" + exp_txt + "</span><br>"
                    "<b>Reason:</b> " + summary + "</div>",
                    unsafe_allow_html=True,
                )
                if config.DRY_RUN:
                    st.button(f"Unblock {ip} (disabled — DRY_RUN)", key=f"unblock_{ip}", disabled=True)
                else:
                    if st.button(f"Unblock {ip}", key=f"unblock_{ip}"):
                        try:
                            r = subprocess.run(
                                ["sudo", "ufw", "delete", "deny", "from", ip],
                                capture_output=True, text=True,
                            )
                            if r.returncode == 0:
                                st.success(f"{ip} unblocked successfully.")
                            else:
                                st.error(f"Failed: {r.stderr.strip()}")
                        except Exception as e:
                            st.error(f"Error: {e}")

    st.markdown("---")
    st.subheader("IP Whitelist")
    whitelist = getattr(config, "IP_WHITELIST", [])
    if whitelist:
        for wip in whitelist:
            st.markdown(f"- `{wip}`")
    else:
        st.info("No IPs whitelisted.")

# ── Footer + auto-refresh ─────────────────────────────────────────────────────
st.markdown("---")
st.caption(
    f"Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Auto-refreshes every 10 seconds"
)
time.sleep(10)
st.rerun()
