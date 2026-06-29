#!/usr/bin/env python3
"""
Project Aegis desktop dashboard.

Native PySide6/Qt SOC console. The security daemon still runs separately as a
systemd service; this app reads the shared reports, metrics, model metadata,
and blocklist files. No Streamlit server and no browser are used.
"""

from __future__ import annotations

import json
import math
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
    from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
    from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen, QRadialGradient
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QMainWindow,
        QScrollArea,
        QStackedWidget,
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

BG = "#040907"
PANEL = "#0b1512"
PANEL_ALT = "#101d1a"
LINE = "#1c4438"
LINE_HOT = "#26f0a5"
TEXT = "#e4fff3"
MUTED = "#7fa093"
GREEN = "#24f0a1"
CYAN = "#49c8ff"
AMBER = "#f4b24a"
RED = "#ff4d6d"
PURPLE = "#b785ff"


def _csv(path, n=None):
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        frame = pd.read_csv(path)
        if "timestamp" in frame.columns:
            frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
        return frame.tail(n) if n else frame
    except Exception:
        return pd.DataFrame()


def load_incidents():
    return _csv(runtime_paths.as_str(runtime_paths.INCIDENTS_CSV))


def load_metrics(n=120):
    return _csv(runtime_paths.as_str(runtime_paths.SYSTEM_METRICS_CSV), n)


def load_scores(n=120):
    return _csv(runtime_paths.as_str(runtime_paths.ANOMALY_SCORES_CSV), n)


def load_metadata():
    path = runtime_paths.as_str(runtime_paths.METADATA_PATH)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def load_blocklist():
    path = runtime_paths.as_str(runtime_paths.BLOCKLIST_PATH)
    if not os.path.exists(path):
        return []
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
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
        "CRITICAL": RED,
        "HIGH": "#ff8d56",
        "MEDIUM": AMBER,
        "LOW": GREEN,
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


def service_status():
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "aegis-daemon"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


class AnimatedBackdrop(QWidget):
    def __init__(self):
        super().__init__()
        self.phase = 0.0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(33)

    def tick(self):
        self.phase += 0.012
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect()
        painter.fillRect(rect, QColor(BG))

        grad = QRadialGradient(QPointF(rect.width() * 0.18, rect.height() * 0.15), rect.width() * 0.7)
        grad.setColorAt(0.0, QColor(10, 60, 42, 150))
        grad.setColorAt(0.45, QColor(5, 24, 18, 90))
        grad.setColorAt(1.0, QColor(4, 9, 7, 255))
        painter.fillRect(rect, grad)

        glow = QRadialGradient(QPointF(rect.width() * 0.72, rect.height() * 0.78), rect.width() * 0.45)
        glow.setColorAt(0.0, QColor(38, 240, 165, 60))
        glow.setColorAt(0.55, QColor(12, 70, 50, 38))
        glow.setColorAt(1.0, QColor(4, 9, 7, 0))
        painter.fillRect(rect, glow)

        grid_pen = QPen(QColor(24, 92, 70, 44), 1)
        painter.setPen(grid_pen)
        offset = int((self.phase * 28) % 28)
        for x in range(-offset, rect.width(), 28):
            painter.drawLine(x, 0, x + rect.height() // 2, rect.height())
        for y in range(offset, rect.height(), 28):
            painter.drawLine(0, y, rect.width(), y - rect.width() // 2)

        wave_pen = QPen(QColor(38, 240, 165, 85), 1)
        painter.setPen(wave_pen)
        base = rect.height() * 0.73
        for lane in range(3):
            path = QPainterPath()
            path.moveTo(0, base + lane * 28)
            for x in range(0, rect.width() + 12, 12):
                y = base + lane * 28 + math.sin(x * 0.018 + self.phase * 5 + lane) * (18 + lane * 5)
                path.lineTo(x, y)
            painter.drawPath(path)

        for i in range(34):
            x = (i * 97 + math.sin(self.phase * 1.7 + i) * 42) % max(rect.width(), 1)
            y = (i * 53 + math.cos(self.phase * 1.3 + i) * 36) % max(rect.height(), 1)
            alpha = 65 + int(55 * (math.sin(self.phase * 2 + i) + 1) / 2)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(38, 240, 165, alpha))
            painter.drawEllipse(QPointF(x, y), 1.8, 1.8)


class GlassPanel(QFrame):
    def __init__(self, title=None):
        super().__init__()
        self.setObjectName("GlassPanel")
        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(16, 14, 16, 16)
        self.outer.setSpacing(10)
        if title:
            label = QLabel(title)
            label.setObjectName("PanelTitle")
            self.outer.addWidget(label)


class StatCard(QFrame):
    def __init__(self, label, color=GREEN):
        super().__init__()
        self.setObjectName("StatCard")
        self.color = color
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 13, 16, 14)
        layout.setSpacing(6)
        self.label = QLabel(label)
        self.label.setObjectName("TinyLabel")
        self.value = QLabel("--")
        self.value.setObjectName("StatValue")
        self.value.setStyleSheet(f"color: {color};")
        self.sub = QLabel("")
        self.sub.setObjectName("Muted")
        self.sub.setWordWrap(True)
        layout.addWidget(self.label)
        layout.addWidget(self.value)
        layout.addWidget(self.sub)

    def set_data(self, value, sub=""):
        self.value.setText(str(value))
        self.sub.setText(str(sub))


class MetricRing(QWidget):
    def __init__(self, label, color=GREEN):
        super().__init__()
        self.value = 0.0
        self.label = label
        self.color = QColor(color)
        self.setMinimumSize(132, 132)

    def set_value(self, value):
        self.value = max(0.0, min(100.0, float(value)))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(18, 12, self.width() - 36, self.height() - 36)
        painter.setPen(QPen(QColor(31, 72, 58), 10, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 90 * 16, -360 * 16)
        painter.setPen(QPen(self.color, 10, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 90 * 16, int(-360 * 16 * (self.value / 100)))
        painter.setPen(QColor(TEXT))
        painter.setFont(QFont("Segoe UI", 20, QFont.Bold))
        painter.drawText(rect, Qt.AlignCenter, f"{self.value:.0f}")
        painter.setPen(QColor(MUTED))
        painter.setFont(QFont("Segoe UI", 8, QFont.Bold))
        painter.drawText(QRectF(0, self.height() - 28, self.width(), 18), Qt.AlignCenter, self.label.upper())


class Sparkline(QFrame):
    def __init__(self, color=GREEN, fill=True, bar=False):
        super().__init__()
        self.values = []
        self.color = QColor(color)
        self.fill = fill
        self.bar = bar
        self.setObjectName("Chart")
        self.setMinimumHeight(130)

    def set_values(self, values):
        self.values = [float(v) for v in values if pd.notna(v)]
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(12, 12, -12, -14)
        painter.setPen(QPen(QColor(25, 64, 50, 80), 1))
        for i in range(1, 4):
            y = rect.top() + rect.height() * i / 4
            painter.drawLine(rect.left(), int(y), rect.right(), int(y))

        if len(self.values) < 2:
            painter.setPen(QColor(MUTED))
            painter.drawText(rect, Qt.AlignCenter, "Awaiting telemetry")
            return

        mn, mx = min(self.values), max(self.values)
        if mn == mx:
            mx = mn + 1
        count = len(self.values)

        if self.bar:
            width = max(2, rect.width() / count - 2)
            for idx, value in enumerate(self.values):
                height = ((value - mn) / (mx - mn)) * rect.height()
                x = rect.left() + idx * (rect.width() / count)
                y = rect.bottom() - height
                c = QColor(self.color)
                c.setAlpha(70 + int(120 * idx / max(count, 1)))
                painter.setBrush(c)
                painter.setPen(Qt.NoPen)
                painter.drawRoundedRect(QRectF(x, y, width, height), 2, 2)
            return

        step = rect.width() / (count - 1)
        path = QPainterPath()
        fill = QPainterPath()
        for idx, value in enumerate(self.values):
            x = rect.left() + idx * step
            y = rect.bottom() - ((value - mn) / (mx - mn)) * rect.height()
            if idx == 0:
                path.moveTo(x, y)
                fill.moveTo(x, rect.bottom())
                fill.lineTo(x, y)
            else:
                path.lineTo(x, y)
                fill.lineTo(x, y)
        if self.fill:
            fill.lineTo(rect.right(), rect.bottom())
            fill.closeSubpath()
            c = QColor(self.color)
            c.setAlpha(38)
            painter.fillPath(fill, c)
        painter.setPen(QPen(self.color, 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(path)


class DataTable(QTableWidget):
    def __init__(self, columns):
        super().__init__(0, len(columns))
        self.setHorizontalHeaderLabels(columns)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def set_rows(self, rows):
        self.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                item.setForeground(QColor(TEXT))
                self.setItem(r, c, item)


class NavButton(QLabel):
    def __init__(self, text, index, callback):
        super().__init__(text)
        self.index = index
        self.callback = callback
        self.setObjectName("NavButton")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(40)

    def mousePressEvent(self, event):
        self.callback(self.index)

    def set_active(self, active):
        self.setProperty("active", active)
        self.style().unpolish(self)
        self.style().polish(self)


class IncidentCard(QFrame):
    def __init__(self, row):
        super().__init__()
        self.setObjectName("IncidentCard")
        severity = str(row.get("severity", "UNKNOWN")).upper()
        color = severity_color(severity)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        top = QHBoxLayout()
        badge = QLabel(severity)
        badge.setObjectName("Badge")
        badge.setStyleSheet(f"color: {color}; border-color: {color}; background: rgba(38, 240, 165, 0.06);")
        ip = QLabel(str(row.get("attacker_ip", "N/A")))
        ip.setObjectName("IncidentIP")
        top.addWidget(badge)
        top.addWidget(ip)
        top.addStretch()
        ts = row.get("timestamp", "")
        if hasattr(ts, "strftime"):
            ts = ts.strftime("%H:%M:%S")
        time_label = QLabel(str(ts))
        time_label.setObjectName("Muted")
        top.addWidget(time_label)
        layout.addLayout(top)

        det = QLabel(f"{row.get('detection_label', 'UNKNOWN')}  |  {row.get('action', 'N/A')}")
        det.setObjectName("TinyLabel")
        layout.addWidget(det)
        summary = QLabel(str(row.get("summary", "No summary"))[:220])
        summary.setWordWrap(True)
        summary.setObjectName("IncidentSummary")
        layout.addWidget(summary)


class Dashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Project Aegis")
        self.resize(1480, 920)
        self.backdrop = AnimatedBackdrop()
        self.setCentralWidget(self.backdrop)

        shell = QHBoxLayout(self.backdrop)
        shell.setContentsMargins(18, 18, 18, 18)
        shell.setSpacing(16)

        self.nav = GlassPanel()
        self.nav.setObjectName("NavRail")
        self.nav.setFixedWidth(220)
        brand = QLabel("AEGIS")
        brand.setObjectName("Brand")
        self.nav.outer.addWidget(brand)
        sub = QLabel("Autonomous Defense Console")
        sub.setObjectName("Muted")
        self.nav.outer.addWidget(sub)

        self.nav_buttons = []
        for idx, text in enumerate(["Overview", "Incidents", "ML Status", "Timeline", "Blocks"]):
            button = NavButton(text, idx, self.set_page)
            self.nav_buttons.append(button)
            self.nav.outer.addWidget(button)
        self.nav.outer.addStretch()
        self.daemon_pill = QLabel("Daemon: unknown")
        self.daemon_pill.setObjectName("DaemonPill")
        self.nav.outer.addWidget(self.daemon_pill)
        shell.addWidget(self.nav)

        content = QVBoxLayout()
        content.setSpacing(14)
        shell.addLayout(content, 1)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Security & Drift Management")
        title.setObjectName("AppTitle")
        subtitle = QLabel("Live host telemetry, incident intelligence, model state, and response controls")
        subtitle.setObjectName("Muted")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        self.clock = QLabel("--")
        self.clock.setObjectName("StatusPill")
        header.addWidget(self.clock)
        content.addLayout(header)

        self.stack = QStackedWidget()
        content.addWidget(self.stack, 1)
        self._build_overview()
        self._build_incidents()
        self._build_ml()
        self._build_timeline()
        self._build_blocks()
        self.set_page(0)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(10_000)
        self.refresh()

    def set_page(self, index):
        self.stack.setCurrentIndex(index)
        for button in self.nav_buttons:
            button.set_active(button.index == index)

    def _panel(self, title, widget):
        panel = GlassPanel(title)
        panel.outer.addWidget(widget)
        return panel

    def _build_overview(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(14)

        row = QHBoxLayout()
        self.host_card = StatCard("Host Identity", CYAN)
        self.incident_card = StatCard("Incidents", RED)
        self.block_card = StatCard("Block Records", GREEN)
        self.model_card = StatCard("Model State", PURPLE)
        for card in [self.host_card, self.incident_card, self.block_card, self.model_card]:
            row.addWidget(card)
        layout.addLayout(row)

        mid = QHBoxLayout()
        ring_panel = GlassPanel("System Pressure")
        ring_row = QHBoxLayout()
        self.cpu_ring = MetricRing("CPU", GREEN)
        self.ram_ring = MetricRing("RAM", CYAN)
        ring_row.addWidget(self.cpu_ring)
        ring_row.addWidget(self.ram_ring)
        ring_panel.outer.addLayout(ring_row)
        mid.addWidget(ring_panel, 1)

        self.cpu_chart = Sparkline(GREEN, fill=True)
        self.ram_chart = Sparkline(CYAN, fill=True)
        chart_grid = QVBoxLayout()
        chart_grid.addWidget(self._panel("CPU Telemetry", self.cpu_chart))
        chart_grid.addWidget(self._panel("RAM Telemetry", self.ram_chart))
        mid.addLayout(chart_grid, 2)
        layout.addLayout(mid)

        bottom = QHBoxLayout()
        self.ports_table = DataTable(["Port", "Address", "Process", "State"])
        self.users_table = DataTable(["User", "Terminal", "Source"])
        bottom.addWidget(self._panel("Open Ports", self.ports_table), 2)
        bottom.addWidget(self._panel("Active Users", self.users_table), 1)
        layout.addLayout(bottom, 1)
        self.stack.addWidget(page)

    def _build_incidents(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(12)
        header = QHBoxLayout()
        self.incident_feed_title = QLabel("Incident Feed")
        self.incident_feed_title.setObjectName("SectionTitle")
        header.addWidget(self.incident_feed_title)
        header.addStretch()
        layout.addLayout(header)
        self.incident_scroll = QScrollArea()
        self.incident_scroll.setWidgetResizable(True)
        self.incident_scroll.setObjectName("TransparentScroll")
        self.incident_container = QWidget()
        self.incident_list = QVBoxLayout(self.incident_container)
        self.incident_list.setSpacing(10)
        self.incident_list.setContentsMargins(2, 2, 8, 2)
        self.incident_scroll.setWidget(self.incident_container)
        layout.addWidget(self.incident_scroll)
        self.stack.addWidget(page)

    def _build_ml(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        cards = QHBoxLayout()
        self.phase_card = StatCard("ML Phase", GREEN)
        self.threshold_card = StatCard("Threshold", CYAN)
        self.trained_card = StatCard("Last Trained", AMBER)
        self.clean_rows_card = StatCard("Clean Rows", PURPLE)
        for card in [self.phase_card, self.threshold_card, self.trained_card, self.clean_rows_card]:
            cards.addWidget(card)
        layout.addLayout(cards)
        self.score_chart = Sparkline(PURPLE, fill=True)
        layout.addWidget(self._panel("Anomaly Score Stream", self.score_chart), 1)
        self.meta_text = QTextEdit()
        self.meta_text.setReadOnly(True)
        layout.addWidget(self._panel("Model Metadata", self.meta_text), 1)
        self.stack.addWidget(page)

    def _build_timeline(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        self.top_ips_table = DataTable(["IP", "Incidents"])
        self.top_users_table = DataTable(["Username", "Attempts"])
        row.addWidget(self._panel("Top Attacking IPs", self.top_ips_table), 1)
        row.addWidget(self._panel("Top Targeted Users", self.top_users_table), 1)
        layout.addLayout(row)
        self.severity_table = DataTable(["Severity", "Count"])
        self.severity_chart = Sparkline(AMBER, fill=False, bar=True)
        lower = QHBoxLayout()
        lower.addWidget(self._panel("Severity Distribution", self.severity_table), 1)
        lower.addWidget(self._panel("Incident Volume", self.severity_chart), 1)
        layout.addLayout(lower, 1)
        self.stack.addWidget(page)

    def _build_blocks(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.dry_run_label = QLabel("")
        self.dry_run_label.setObjectName("WarningText")
        layout.addWidget(self.dry_run_label)
        self.block_table = DataTable(["IP", "Severity", "Blocked At", "Expiry", "Reason"])
        layout.addWidget(self._panel("Block Manager", self.block_table), 1)
        self.whitelist_text = QTextEdit()
        self.whitelist_text.setReadOnly(True)
        self.whitelist_text.setMaximumHeight(140)
        layout.addWidget(self._panel("IP Whitelist", self.whitelist_text))
        self.stack.addWidget(page)

    def refresh(self):
        self.clock.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        incidents = load_incidents()
        metrics = load_metrics()
        scores = load_scores()
        blocks = load_blocklist()
        meta = load_metadata()
        self._refresh_overview(incidents, metrics, blocks, meta)
        self._refresh_incidents(incidents)
        self._refresh_ml(scores, meta)
        self._refresh_timeline(incidents)
        self._refresh_blocks(blocks)

    def _refresh_overview(self, incidents, metrics, blocks, meta):
        status = service_status()
        self.daemon_pill.setText(f"Daemon: {status}")
        self.daemon_pill.setProperty("state", "good" if status == "active" else "bad")
        self.daemon_pill.style().unpolish(self.daemon_pill)
        self.daemon_pill.style().polish(self.daemon_pill)

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        uptime = time.time() - psutil.boot_time()
        host = os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "localhost")
        self.host_card.set_data(host, f"Uptime {int(uptime // 3600)}h {int((uptime % 3600) // 60)}m")
        self.incident_card.set_data(len(incidents), "Recorded detections")
        self.block_card.set_data(len(blocks), "Blocklist rows")
        self.model_card.set_data("Ready" if meta else "Warmup", "Metadata present" if meta else "No model metadata")
        self.cpu_ring.set_value(cpu)
        self.ram_ring.set_value(mem.percent)

        if not metrics.empty:
            if "cpu_percent" in metrics:
                self.cpu_chart.set_values(metrics["cpu_percent"].tolist())
            if "ram_percent" in metrics:
                self.ram_chart.set_values(metrics["ram_percent"].tolist())

        try:
            snapshot = get_full_system_snapshot()
            ports = []
            for item in snapshot.get("open_ports", [])[:24]:
                if "error" not in item:
                    ports.append([item.get("port", "?"), item.get("address", "?"), item.get("process", "unknown"), item.get("state", "?")])
            self.ports_table.set_rows(ports)
            users = []
            for item in snapshot.get("active_users", [])[:24]:
                if "error" not in item:
                    users.append([item.get("user", "?"), item.get("terminal", "?"), item.get("source", "local")])
            self.users_table.set_rows(users)
        except Exception:
            self.ports_table.set_rows([])
            self.users_table.set_rows([])

    def _refresh_incidents(self, incidents):
        while self.incident_list.count():
            item = self.incident_list.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        if incidents.empty:
            empty = QLabel("No incidents recorded yet. The daemon is watching.")
            empty.setObjectName("EmptyState")
            self.incident_list.addWidget(empty)
            self.incident_list.addStretch()
            return
        data = incidents.sort_values("timestamp", ascending=False) if "timestamp" in incidents else incidents
        for _, row in data.head(30).iterrows():
            self.incident_list.addWidget(IncidentCard(row))
        self.incident_list.addStretch()

    def _refresh_ml(self, scores, meta):
        threshold = meta.get("threshold", "N/A")
        threshold_text = f"{float(threshold):.6f}" if isinstance(threshold, (int, float)) else str(threshold)
        phase = "DEFENDING" if os.path.exists(runtime_paths.as_str(runtime_paths.MODEL_PATH)) else "WARMING UP"
        self.phase_card.set_data(phase, "Model file state")
        self.threshold_card.set_data(threshold_text, "Current anomaly limit")
        self.trained_card.set_data(str(meta.get("trained_at", "N/A"))[:19], "Last artifact write")
        self.clean_rows_card.set_data(meta.get("clean_rows", "N/A"), "Rows used for model")
        if not scores.empty and "score" in scores:
            self.score_chart.set_values(scores["score"].tolist())
        self.meta_text.setPlainText(json.dumps(meta or {"status": "No metadata found"}, indent=2))

    def _refresh_timeline(self, incidents):
        if incidents.empty:
            self.top_ips_table.set_rows([])
            self.top_users_table.set_rows([])
            self.severity_table.set_rows([])
            self.severity_chart.set_values([])
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
            self.severity_chart.set_values(severity.tolist())

    def _refresh_blocks(self, blocks):
        if getattr(config, "DRY_RUN", True):
            self.dry_run_label.setText("DRY_RUN enabled. Aegis logs enforcement decisions without changing UFW rules.")
        else:
            self.dry_run_label.setText("LIVE BLOCKING ENABLED. Confirm your admin IP is whitelisted.")
        rows = []
        for block in reversed(blocks[-100:]):
            rows.append([block["ip"], block["severity"], block["timestamp"], expiry_text(block["expiry"], block["severity"]), block["summary"]])
        self.block_table.set_rows(rows)
        whitelist = getattr(config, "IP_WHITELIST", [])
        self.whitelist_text.setPlainText("\n".join(str(ip) for ip in whitelist) or "No whitelist entries configured.")


STYLE = f"""
QMainWindow, QWidget {{
    color: {TEXT};
    font-family: "Inter", "Segoe UI", "Noto Sans", sans-serif;
    font-size: 13px;
    letter-spacing: 0px;
}}
QFrame#GlassPanel, QFrame#StatCard, QFrame#IncidentCard, QFrame#Chart {{
    background: rgba(10, 22, 18, 205);
    border: 1px solid rgba(58, 255, 181, 60);
    border-radius: 8px;
}}
QFrame#NavRail {{
    background: rgba(4, 12, 10, 215);
    border: 1px solid rgba(58, 255, 181, 70);
    border-radius: 8px;
}}
QFrame#StatCard:hover, QFrame#GlassPanel:hover, QFrame#IncidentCard:hover {{
    border: 1px solid rgba(58, 255, 181, 150);
    background: rgba(13, 30, 24, 220);
}}
QLabel#Brand {{
    color: {GREEN};
    font-size: 28px;
    font-weight: 900;
}}
QLabel#AppTitle {{
    color: {TEXT};
    font-size: 30px;
    font-weight: 850;
}}
QLabel#SectionTitle {{
    color: {TEXT};
    font-size: 19px;
    font-weight: 800;
}}
QLabel#TinyLabel, QLabel#PanelTitle {{
    color: {MUTED};
    font-size: 11px;
    font-weight: 800;
    text-transform: uppercase;
}}
QLabel#StatValue {{
    font-size: 30px;
    font-weight: 900;
}}
QLabel#Muted {{
    color: {MUTED};
}}
QLabel#StatusPill, QLabel#DaemonPill {{
    color: {GREEN};
    background: rgba(14, 45, 34, 190);
    border: 1px solid rgba(38, 240, 165, 95);
    border-radius: 8px;
    padding: 8px 12px;
}}
QLabel#DaemonPill[state="bad"] {{
    color: {RED};
    border-color: rgba(255, 77, 109, 140);
}}
QLabel#NavButton {{
    color: {MUTED};
    padding: 10px 12px;
    border-radius: 8px;
}}
QLabel#NavButton[active="true"] {{
    color: {GREEN};
    background: rgba(38, 240, 165, 34);
    border: 1px solid rgba(38, 240, 165, 90);
}}
QLabel#Badge {{
    border: 1px solid;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 10px;
    font-weight: 900;
}}
QLabel#IncidentIP {{
    color: {TEXT};
    font-size: 18px;
    font-weight: 850;
}}
QLabel#IncidentSummary {{
    color: #c9e8dc;
    line-height: 140%;
}}
QLabel#EmptyState {{
    color: {MUTED};
    padding: 18px;
}}
QLabel#WarningText {{
    color: {AMBER};
    background: rgba(244, 178, 74, 24);
    border: 1px solid rgba(244, 178, 74, 80);
    border-radius: 8px;
    padding: 10px 12px;
}}
QTableWidget {{
    background: rgba(8, 18, 15, 180);
    alternate-background-color: rgba(16, 33, 28, 170);
    color: {TEXT};
    border: 1px solid rgba(58, 255, 181, 45);
    border-radius: 8px;
    gridline-color: rgba(58, 255, 181, 30);
}}
QHeaderView::section {{
    background: rgba(14, 36, 29, 230);
    color: {GREEN};
    padding: 8px;
    border: 0;
    font-weight: 800;
}}
QTextEdit {{
    background: rgba(8, 18, 15, 190);
    color: {TEXT};
    border: 1px solid rgba(58, 255, 181, 45);
    border-radius: 8px;
    padding: 10px;
}}
QScrollArea#TransparentScroll {{
    background: transparent;
    border: 0;
}}
QScrollBar:vertical {{
    background: rgba(5, 12, 10, 180);
    width: 10px;
}}
QScrollBar::handle:vertical {{
    background: rgba(38, 240, 165, 110);
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
