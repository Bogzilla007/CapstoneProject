#!/usr/bin/env python3
"""
Project Aegis desktop dashboard.

Native PySide6/Qt application. No Streamlit server and no browser required.
The daemon still runs separately as a systemd service; this app reads the
same CSV/model/blocklist files and refreshes every 10 seconds.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime

import pandas as pd
import psutil

import config
import runtime_paths
from system_checks import get_full_system_snapshot

try:
    from PySide6.QtCore import Qt, QTimer, QRectF
    from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QScrollArea,
        QSizePolicy,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:
    print("Project Aegis desktop dashboard requires PySide6.")
    print("Install it with: pip install PySide6 --break-system-packages")
    raise SystemExit(1) from exc


runtime_paths.ensure_runtime_dirs()

ACCENT = "#26f0a5"
ACCENT_2 = "#3aa7ff"
WARNING = "#f5b342"
DANGER = "#ff5570"
PANEL = "#101820"
PANEL_2 = "#15212b"
BG = "#07110d"
TEXT = "#d7f5e7"
MUTED = "#7f9b91"


def _read_csv(path, n=None):
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        df = pd.read_csv(path)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df.tail(n) if n else df
    except Exception:
        return pd.DataFrame()


def load_incidents():
    return _read_csv(runtime_paths.as_str(runtime_paths.INCIDENTS_CSV))


def load_metrics(n=90):
    return _read_csv(runtime_paths.as_str(runtime_paths.SYSTEM_METRICS_CSV), n=n)


def load_scores(n=90):
    return _read_csv(runtime_paths.as_str(runtime_paths.ANOMALY_SCORES_CSV), n=n)


def load_metadata():
    path = runtime_paths.as_str(runtime_paths.METADATA_PATH)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def load_blocklist():
    path = runtime_paths.as_str(runtime_paths.BLOCKLIST_PATH)
    if not os.path.exists(path):
        return []
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",", 4)
                rows.append({
                    "ip": parts[0] if len(parts) > 0 else "?",
                    "severity": parts[1] if len(parts) > 1 else "?",
                    "timestamp": parts[2] if len(parts) > 2 else "?",
                    "expiry": parts[3] if len(parts) > 3 else "0",
                    "summary": parts[4] if len(parts) > 4 else "",
                })
    except Exception:
        return []
    return rows


def severity_color(severity):
    return {
        "CRITICAL": DANGER,
        "HIGH": "#ff8a4c",
        "MEDIUM": WARNING,
        "LOW": ACCENT,
        "DRY_RUN": MUTED,
    }.get(str(severity).upper(), MUTED)


def expiry_text(expiry, severity):
    if severity == "DRY_RUN" or expiry in ("DRY_RUN", ""):
        return "DRY RUN"
    try:
        exp = float(expiry)
        if exp == 0:
            return "PERMANENT"
        remaining = exp - time.time()
        if remaining <= 0:
            return "EXPIRED"
        return f"{int(remaining // 3600)}h {int((remaining % 3600) // 60)}m"
    except Exception:
        return str(expiry)


class Card(QFrame):
    def __init__(self, title, value="--", subtitle="", color=ACCENT):
        super().__init__()
        self.setObjectName("Card")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(112)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(6)

        self.title = QLabel(title)
        self.title.setObjectName("CardTitle")
        self.value = QLabel(value)
        self.value.setObjectName("CardValue")
        self.value.setStyleSheet(f"color: {color};")
        self.subtitle = QLabel(subtitle)
        self.subtitle.setObjectName("Muted")
        self.subtitle.setWordWrap(True)

        layout.addWidget(self.title)
        layout.addWidget(self.value)
        layout.addWidget(self.subtitle)

    def set_data(self, value, subtitle=""):
        self.value.setText(str(value))
        self.subtitle.setText(str(subtitle))


class Sparkline(QFrame):
    def __init__(self, color=ACCENT, fill=False):
        super().__init__()
        self.values = []
        self.color = QColor(color)
        self.fill = fill
        self.setMinimumHeight(140)
        self.setObjectName("Chart")

    def set_values(self, values):
        self.values = [float(v) for v in values if pd.notna(v)]
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(14, 14, -14, -14)

        painter.setPen(QPen(QColor("#1f3a32"), 1))
        for i in range(1, 4):
            y = rect.top() + rect.height() * i / 4
            painter.drawLine(rect.left(), int(y), rect.right(), int(y))

        if len(self.values) < 2:
            painter.setPen(QColor(MUTED))
            painter.drawText(rect, Qt.AlignCenter, "Waiting for data")
            return

        mn, mx = min(self.values), max(self.values)
        if mx == mn:
            mx = mn + 1
        step = rect.width() / (len(self.values) - 1)
        path = QPainterPath()
        fill_path = QPainterPath()
        points = []
        for idx, value in enumerate(self.values):
            x = rect.left() + idx * step
            y = rect.bottom() - ((value - mn) / (mx - mn)) * rect.height()
            points.append((x, y))
            if idx == 0:
                path.moveTo(x, y)
                fill_path.moveTo(x, rect.bottom())
                fill_path.lineTo(x, y)
            else:
                path.lineTo(x, y)
                fill_path.lineTo(x, y)

        if self.fill:
            fill_path.lineTo(points[-1][0], rect.bottom())
            fill_path.closeSubpath()
            fill = QColor(self.color)
            fill.setAlpha(45)
            painter.fillPath(fill_path, fill)

        pen = QPen(self.color, 2)
        painter.setPen(pen)
        painter.drawPath(path)


class DataTable(QTableWidget):
    def __init__(self, columns):
        super().__init__(0, len(columns))
        self.columns = columns
        self.setHorizontalHeaderLabels(columns)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def set_rows(self, rows):
        self.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            for col_idx, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                item.setForeground(QColor(TEXT))
                self.setItem(row_idx, col_idx, item)


class Dashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Project Aegis")
        self.resize(1380, 860)

        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)
        main.setContentsMargins(18, 16, 18, 16)
        main.setSpacing(14)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Project Aegis")
        title.setObjectName("AppTitle")
        subtitle = QLabel("Autonomous security monitor | Native desktop console")
        subtitle.setObjectName("Muted")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        self.status = QLabel("Starting")
        self.status.setObjectName("StatusPill")
        header.addWidget(self.status)
        main.addLayout(header)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        main.addWidget(self.tabs)

        self._build_overview()
        self._build_incidents()
        self._build_ml()
        self._build_timeline()
        self._build_blocks()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(10_000)
        self.refresh()

    def _build_overview(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(14)

        grid = QGridLayout()
        self.host_card = Card("Host", "--", "System hostname", ACCENT_2)
        self.cpu_card = Card("CPU", "--", "Live utilization", ACCENT)
        self.ram_card = Card("RAM", "--", "Memory pressure", WARNING)
        self.incident_card = Card("Incidents", "--", "Total recorded", DANGER)
        self.block_card = Card("Blocks", "--", "Active blocklist rows", ACCENT)
        for idx, card in enumerate([self.host_card, self.cpu_card, self.ram_card, self.incident_card, self.block_card]):
            grid.addWidget(card, 0, idx)
        layout.addLayout(grid)

        chart_row = QHBoxLayout()
        self.cpu_chart = Sparkline(ACCENT_2, fill=True)
        self.ram_chart = Sparkline(WARNING, fill=True)
        chart_row.addWidget(self._panel("CPU History", self.cpu_chart), 1)
        chart_row.addWidget(self._panel("RAM History", self.ram_chart), 1)
        layout.addLayout(chart_row)

        checks = QHBoxLayout()
        self.ports_table = DataTable(["Port", "Address", "Process", "State"])
        self.users_table = DataTable(["User", "Terminal", "Source"])
        checks.addWidget(self._panel("Open Ports", self.ports_table), 2)
        checks.addWidget(self._panel("Active Users", self.users_table), 1)
        layout.addLayout(checks)
        self.tabs.addTab(page, "Overview")

    def _build_incidents(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.incident_table = DataTable(["Time", "Severity", "Action", "IP", "Detection", "Summary"])
        layout.addWidget(self.incident_table)
        self.tabs.addTab(page, "Incidents")

    def _build_ml(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        cards = QGridLayout()
        self.phase_card = Card("ML Phase", "--", "Detector status", ACCENT)
        self.threshold_card = Card("Threshold", "--", "Current anomaly limit", ACCENT_2)
        self.trained_card = Card("Last Trained", "--", "Model metadata", WARNING)
        self.clean_rows_card = Card("Clean Rows", "--", "Training rows", ACCENT)
        for idx, card in enumerate([self.phase_card, self.threshold_card, self.trained_card, self.clean_rows_card]):
            cards.addWidget(card, 0, idx)
        layout.addLayout(cards)
        self.score_chart = Sparkline("#b785ff", fill=True)
        layout.addWidget(self._panel("Anomaly Score", self.score_chart))
        self.meta_text = QTextEdit()
        self.meta_text.setReadOnly(True)
        self.meta_text.setMinimumHeight(150)
        layout.addWidget(self._panel("Model Metadata", self.meta_text))
        self.tabs.addTab(page, "ML Status")

    def _build_timeline(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        top = QHBoxLayout()
        self.top_ips_table = DataTable(["IP", "Incidents"])
        self.top_users_table = DataTable(["Username", "Attempts"])
        top.addWidget(self._panel("Top Attacking IPs", self.top_ips_table), 1)
        top.addWidget(self._panel("Top Targeted Users", self.top_users_table), 1)
        layout.addLayout(top)
        self.severity_table = DataTable(["Severity", "Count"])
        layout.addWidget(self._panel("Severity Distribution", self.severity_table))
        self.tabs.addTab(page, "Timeline")

    def _build_blocks(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.dry_run_label = QLabel("")
        self.dry_run_label.setObjectName("WarningText")
        layout.addWidget(self.dry_run_label)
        self.block_table = DataTable(["IP", "Severity", "Blocked At", "Expiry", "Reason"])
        layout.addWidget(self.block_table)
        self.whitelist_text = QTextEdit()
        self.whitelist_text.setReadOnly(True)
        self.whitelist_text.setMaximumHeight(120)
        layout.addWidget(self._panel("IP Whitelist", self.whitelist_text))
        self.tabs.addTab(page, "Block Manager")

    def _panel(self, title, widget):
        frame = QFrame()
        frame.setObjectName("Panel")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 14)
        label = QLabel(title)
        label.setObjectName("PanelTitle")
        layout.addWidget(label)
        layout.addWidget(widget)
        return frame

    def refresh(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status.setText(f"Live | {now}")
        incidents = load_incidents()
        metrics = load_metrics()
        scores = load_scores()
        blocks = load_blocklist()
        meta = load_metadata()

        self._refresh_overview(incidents, metrics, blocks)
        self._refresh_incidents(incidents)
        self._refresh_ml(scores, meta)
        self._refresh_timeline(incidents)
        self._refresh_blocks(blocks)

    def _refresh_overview(self, incidents, metrics, blocks):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        uptime = time.time() - psutil.boot_time()
        self.host_card.set_data(os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "localhost"), f"Uptime {int(uptime // 3600)}h {int((uptime % 3600) // 60)}m")
        self.cpu_card.set_data(f"{cpu:.1f}%", "Live sample")
        self.ram_card.set_data(f"{mem.percent:.1f}%", f"{mem.used / (1024 ** 3):.1f}/{mem.total / (1024 ** 3):.1f} GB")
        self.incident_card.set_data(len(incidents), "CSV incident rows")
        self.block_card.set_data(len(blocks), "Blocklist rows")

        if not metrics.empty:
            if "cpu_percent" in metrics:
                self.cpu_chart.set_values(metrics["cpu_percent"].tolist())
            if "ram_percent" in metrics:
                self.ram_chart.set_values(metrics["ram_percent"].tolist())

        try:
            snapshot = get_full_system_snapshot()
            ports = []
            for item in snapshot.get("open_ports", [])[:20]:
                if "error" in item:
                    continue
                ports.append([
                    item.get("port", "?"),
                    item.get("address", "?"),
                    item.get("process", "unknown"),
                    item.get("state", "?"),
                ])
            self.ports_table.set_rows(ports)

            users = []
            for item in snapshot.get("active_users", [])[:20]:
                if "error" in item:
                    continue
                users.append([item.get("user", "?"), item.get("terminal", "?"), item.get("source", "local")])
            self.users_table.set_rows(users)
        except Exception:
            self.ports_table.set_rows([])
            self.users_table.set_rows([])

    def _refresh_incidents(self, incidents):
        if incidents.empty:
            self.incident_table.set_rows([])
            return
        rows = []
        data = incidents.sort_values("timestamp", ascending=False) if "timestamp" in incidents else incidents
        for _, row in data.head(100).iterrows():
            ts = row.get("timestamp", "")
            if hasattr(ts, "strftime"):
                ts = ts.strftime("%Y-%m-%d %H:%M:%S")
            rows.append([
                ts,
                row.get("severity", "UNKNOWN"),
                row.get("action", "N/A"),
                row.get("attacker_ip", "N/A"),
                row.get("detection_label", "UNKNOWN"),
                str(row.get("summary", ""))[:140],
            ])
        self.incident_table.set_rows(rows)

    def _refresh_ml(self, scores, meta):
        threshold = meta.get("threshold", "N/A")
        threshold_text = f"{float(threshold):.6f}" if isinstance(threshold, (int, float)) else str(threshold)
        self.threshold_card.set_data(threshold_text, "95th percentile target")
        self.trained_card.set_data(str(meta.get("trained_at", "N/A"))[:19], "Last model save")
        self.clean_rows_card.set_data(meta.get("clean_rows", "N/A"), "Clean samples")
        phase = "DEFENDING" if os.path.exists(runtime_paths.as_str(runtime_paths.MODEL_PATH)) else "WARMING UP"
        self.phase_card.set_data(phase, "Desktop view estimate")
        if not scores.empty and "score" in scores:
            self.score_chart.set_values(scores["score"].tolist())
        self.meta_text.setPlainText(json.dumps(meta or {"status": "No metadata found"}, indent=2))

    def _refresh_timeline(self, incidents):
        if incidents.empty:
            self.top_ips_table.set_rows([])
            self.top_users_table.set_rows([])
            self.severity_table.set_rows([])
            return
        if "attacker_ip" in incidents:
            top_ips = incidents["attacker_ip"].value_counts().head(8)
            self.top_ips_table.set_rows([[ip, count] for ip, count in top_ips.items()])
        if "usernames" in incidents:
            names = []
            for value in incidents["usernames"].dropna():
                if str(value) not in ("", "nan", "None"):
                    names.extend(str(value).split("|"))
            top_users = pd.Series(names).value_counts().head(8) if names else pd.Series(dtype=int)
            self.top_users_table.set_rows([[name, count] for name, count in top_users.items()])
        if "severity" in incidents:
            severity = incidents["severity"].value_counts()
            self.severity_table.set_rows([[name, count] for name, count in severity.items()])

    def _refresh_blocks(self, blocks):
        if getattr(config, "DRY_RUN", True):
            self.dry_run_label.setText("DRY_RUN is enabled. Aegis will log block actions without changing UFW rules.")
        else:
            self.dry_run_label.setText("LIVE BLOCKING ENABLED. Confirm your admin IP is whitelisted.")

        rows = []
        for block in reversed(blocks[-100:]):
            rows.append([
                block["ip"],
                block["severity"],
                block["timestamp"],
                expiry_text(block["expiry"], block["severity"]),
                block["summary"],
            ])
        self.block_table.set_rows(rows)
        whitelist = getattr(config, "IP_WHITELIST", [])
        self.whitelist_text.setPlainText("\n".join(str(ip) for ip in whitelist) or "No whitelist entries configured.")


STYLE = f"""
QMainWindow, QWidget {{
    background: {BG};
    color: {TEXT};
    font-family: "Inter", "Segoe UI", "Noto Sans", sans-serif;
    font-size: 13px;
}}
QTabWidget::pane {{
    border: 1px solid #1d3a32;
    border-radius: 8px;
    background: #0a1511;
}}
QTabBar::tab {{
    background: #0d1714;
    color: {MUTED};
    padding: 10px 18px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 4px;
}}
QTabBar::tab:selected {{
    color: {ACCENT};
    background: {PANEL};
    border: 1px solid #1d5c48;
}}
QFrame#Card, QFrame#Panel, QFrame#Chart {{
    background: {PANEL};
    border: 1px solid #1a3b31;
    border-radius: 8px;
}}
QFrame#Card:hover, QFrame#Panel:hover {{
    border: 1px solid #2ee6a0;
}}
QLabel#AppTitle {{
    color: {TEXT};
    font-size: 28px;
    font-weight: 700;
}}
QLabel#CardTitle, QLabel#PanelTitle {{
    color: {MUTED};
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}}
QLabel#CardValue {{
    font-size: 30px;
    font-weight: 800;
}}
QLabel#Muted {{
    color: {MUTED};
}}
QLabel#StatusPill {{
    color: {ACCENT};
    background: #0e241d;
    border: 1px solid #1c6e52;
    border-radius: 12px;
    padding: 6px 12px;
}}
QLabel#WarningText {{
    color: {WARNING};
    padding: 8px;
}}
QTableWidget {{
    background: {PANEL_2};
    alternate-background-color: #101c24;
    color: {TEXT};
    border: 1px solid #1a3b31;
    border-radius: 6px;
    gridline-color: #20382f;
}}
QHeaderView::section {{
    background: #0e241d;
    color: {ACCENT};
    padding: 8px;
    border: 0;
    font-weight: 700;
}}
QTextEdit {{
    background: {PANEL_2};
    color: {TEXT};
    border: 1px solid #1a3b31;
    border-radius: 6px;
    padding: 8px;
}}
QScrollBar:vertical {{
    background: #08110e;
    width: 10px;
}}
QScrollBar::handle:vertical {{
    background: #1d5c48;
    border-radius: 5px;
}}
"""


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    window = Dashboard()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
