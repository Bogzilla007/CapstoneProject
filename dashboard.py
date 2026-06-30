#!/usr/bin/env python3
"""
Project Aegis desktop dashboard.

Native PySide6/Qt SOC console. The security daemon still runs separately as a
systemd service; this app reads the shared reports, metrics, model metadata,
and blocklist files. No Streamlit server and no browser are used.
"""

from __future__ import annotations

import importlib
import ipaddress
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

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
        QCheckBox,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QScrollArea,
        QSizePolicy,
        QSpinBox,
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


CONFIG_PATH = Path(config.__file__).resolve()


def _is_real_secret(value):
    value = str(value or "")
    return bool(value) and not value.startswith("your_")


def _serialize_config_value(value):
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (list, dict)):
        return repr(value)
    return repr(value)


def _split_whitelist(text):
    values = []
    for chunk in str(text).replace(",", "\n").splitlines():
        value = chunk.strip()
        if value:
            values.append(value)
    return values


def _validate_whitelist(values):
    invalid = []
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            invalid.append(value)
    return invalid


def _config_snapshot():
    base_dir = getattr(config, "BASE_DIR", os.path.dirname(os.path.abspath(__file__)))
    return {
        "BASE_DIR": base_dir,
        "GROQ_API_KEY": getattr(config, "GROQ_API_KEY", ""),
        "GROQ_MODEL": getattr(config, "GROQ_MODEL", "openai/gpt-oss-120b"),
        "AUTH_LOG_PATH": getattr(config, "AUTH_LOG_PATH", "/var/log/auth.log"),
        "FAILED_LOGIN_THRESHOLD": int(getattr(config, "FAILED_LOGIN_THRESHOLD", 5)),
        "TIME_WINDOW_SECONDS": int(getattr(config, "TIME_WINDOW_SECONDS", 120)),
        "TELEMETRY_INTERVAL": int(getattr(config, "TELEMETRY_INTERVAL", 30)),
        "CSV_REPORT_PATH": getattr(config, "CSV_REPORT_PATH", os.path.join(base_dir, "reports", "incidents.csv")),
        "TEXT_REPORT_PATH": getattr(config, "TEXT_REPORT_PATH", os.path.join(base_dir, "reports", "incidents.txt")),
        "DISCORD_WEBHOOK_URL": getattr(config, "DISCORD_WEBHOOK_URL", ""),
        "ABUSEIPDB_API_KEY": getattr(config, "ABUSEIPDB_API_KEY", ""),
        "DRY_RUN": bool(getattr(config, "DRY_RUN", True)),
        "IP_WHITELIST": list(getattr(config, "IP_WHITELIST", [])),
        "BLOCK_EXPIRY": dict(getattr(config, "BLOCK_EXPIRY", {})),
        "DISCORD_ESCALATION": dict(getattr(config, "DISCORD_ESCALATION", {})),
        "ML_INFERENCE_INTERVAL": int(getattr(config, "ML_INFERENCE_INTERVAL", 10)),
        "ML_ANOMALY_COOLDOWN_SECONDS": int(getattr(config, "ML_ANOMALY_COOLDOWN_SECONDS", 300)),
        "ML_ANOMALY_CONSECUTIVE_REQUIRED": int(getattr(config, "ML_ANOMALY_CONSECUTIVE_REQUIRED", 3)),
        "ML_DRIFT_RATIO_GUARD": int(getattr(config, "ML_DRIFT_RATIO_GUARD", 25)),
    }


def _write_config_file(data):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CONFIG_PATH.exists():
        backup = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + f".{datetime.now().strftime('%Y%m%d%H%M%S')}.bak")
        shutil.copy2(CONFIG_PATH, backup)

    keys = [
        "BASE_DIR", "GROQ_API_KEY", "GROQ_MODEL", "AUTH_LOG_PATH",
        "FAILED_LOGIN_THRESHOLD", "TIME_WINDOW_SECONDS", "TELEMETRY_INTERVAL",
        "CSV_REPORT_PATH", "TEXT_REPORT_PATH", "DISCORD_WEBHOOK_URL",
        "ABUSEIPDB_API_KEY", "DRY_RUN", "IP_WHITELIST", "BLOCK_EXPIRY",
        "DISCORD_ESCALATION", "ML_INFERENCE_INTERVAL", "ML_ANOMALY_COOLDOWN_SECONDS",
        "ML_ANOMALY_CONSECUTIVE_REQUIRED", "ML_DRIFT_RATIO_GUARD",
    ]
    lines = [
        "# Project Aegis - Local Configuration",
        "# Managed by the dashboard settings tab. Keep this file private.",
        "",
    ]
    lines.extend(f"{key} = {_serialize_config_value(data[key])}" for key in keys)

    fd, tmp_path = tempfile.mkstemp(prefix="config.", suffix=".py", dir=str(CONFIG_PATH.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.replace(tmp_path, CONFIG_PATH)
        if os.name == "posix":
            os.chmod(CONFIG_PATH, 0o600)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

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
        self.setMinimumHeight(118)
        self.setMaximumHeight(138)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_data(self, value, sub=""):
        self.value.setText(str(value))
        self.sub.setText(str(sub))


class MetricRing(QWidget):
    def __init__(self, label, color=GREEN):
        super().__init__()
        self.value = 0.0
        self.label = label
        self.color = QColor(color)
        self.setFixedSize(132, 132)

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
    def __init__(self, color=GREEN, fill=True, bar=False, height=132):
        super().__init__()
        self.values = []
        self.color = QColor(color)
        self.fill = fill
        self.bar = bar
        self.setObjectName("Chart")
        self.setMinimumHeight(height)
        self.setMaximumHeight(height + 34)

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



class TopologyMap(QWidget):
    def __init__(self):
        super().__init__()
        self.phase = 0.0
        self.setMinimumHeight(296)
        self.setMaximumHeight(340)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(60)

    def _tick(self):
        self.phase += 0.035
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(18, 18, -18, -18)
        painter.setPen(QPen(QColor(32, 80, 64, 70), 1))
        for x in range(rect.left(), rect.right(), 34):
            painter.drawLine(x, rect.top(), x, rect.bottom())
        for y in range(rect.top(), rect.bottom(), 34):
            painter.drawLine(rect.left(), y, rect.right(), y)

        nodes = [
            (0.08, 0.34, "auth.log", CYAN),
            (0.28, 0.20, "Rule", GREEN),
            (0.28, 0.62, "ML", PURPLE),
            (0.52, 0.40, "Intel", AMBER),
            (0.74, 0.26, "UFW", RED),
            (0.86, 0.62, "Reports", GREEN),
        ]
        points = []
        for nx, ny, label, color in nodes:
            points.append((QPointF(rect.left() + nx * rect.width(), rect.top() + ny * rect.height()), label, QColor(color)))
        edges = [(0, 1), (0, 2), (1, 3), (2, 3), (3, 4), (3, 5)]
        for a, b in edges:
            pa, _, _ = points[a]
            pb, _, _ = points[b]
            painter.setPen(QPen(QColor(38, 240, 165, 80), 1.4))
            path = QPainterPath(pa)
            midx = (pa.x() + pb.x()) / 2
            path.cubicTo(QPointF(midx, pa.y()), QPointF(midx, pb.y()), pb)
            painter.drawPath(path)
            t = (math.sin(self.phase + a + b) + 1) / 2
            pulse = QPointF(pa.x() + (pb.x() - pa.x()) * t, pa.y() + (pb.y() - pa.y()) * t)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(38, 240, 165, 165))
            painter.drawEllipse(pulse, 3.2, 3.2)
        for point, label, color in points:
            glow = QColor(color)
            glow.setAlpha(55)
            painter.setPen(Qt.NoPen)
            painter.setBrush(glow)
            painter.drawEllipse(point, 17, 17)
            painter.setBrush(color)
            painter.drawEllipse(point, 7, 7)
            painter.setPen(QColor(TEXT))
            painter.setFont(QFont("Segoe UI", 8, QFont.Bold))
            painter.drawText(QRectF(point.x() - 42, point.y() + 13, 84, 20), Qt.AlignCenter, label)


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
        self.setMinimumHeight(112)
        self.setMaximumHeight(142)


class Dashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Project Aegis")
        self.resize(1480, 920)
        self.backdrop = AnimatedBackdrop()
        self.setCentralWidget(self.backdrop)

        shell = QHBoxLayout(self.backdrop)
        shell.setContentsMargins(22, 20, 22, 20)
        shell.setSpacing(18)

        self.nav = GlassPanel()
        self.nav.setObjectName("NavRail")
        self.nav.setFixedWidth(236)
        brand = QLabel("AEGIS")
        brand.setObjectName("Brand")
        self.nav.outer.addWidget(brand)
        sub = QLabel("Autonomous Defense Console")
        sub.setObjectName("Muted")
        self.nav.outer.addWidget(sub)

        self.nav_buttons = []
        for idx, text in enumerate(["Overview", "Incidents", "ML Status", "Timeline", "Blocks", "Settings"]):
            button = NavButton(text, idx, self.set_page)
            self.nav_buttons.append(button)
            self.nav.outer.addWidget(button)
        self.nav.outer.addStretch()
        self.daemon_pill = QLabel("Daemon: unknown")
        self.daemon_pill.setObjectName("DaemonPill")
        self.nav.outer.addWidget(self.daemon_pill)
        shell.addWidget(self.nav)

        self.content_frame = QWidget()
        self.content_frame.setObjectName("ContentFrame")
        self.content_frame.setMaximumWidth(1360)
        self.content_frame.setMinimumWidth(920)
        self.content_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        content = QVBoxLayout(self.content_frame)
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(14)
        shell.addWidget(self.content_frame, 1)
        shell.addStretch(1)

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
        self.stack.setObjectName("MainStack")
        content.addWidget(self.stack, 1)
        self._build_overview()
        self._build_incidents()
        self._build_ml()
        self._build_timeline()
        self._build_blocks()
        self._build_settings()
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
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        row = QGridLayout()
        row.setHorizontalSpacing(14)
        row.setVerticalSpacing(14)
        self.host_card = StatCard("Host Identity", CYAN)
        self.incident_card = StatCard("Incidents", RED)
        self.block_card = StatCard("Block Records", GREEN)
        self.model_card = StatCard("Model State", PURPLE)
        cards = [self.host_card, self.incident_card, self.block_card, self.model_card]
        for col, card in enumerate(cards):
            row.addWidget(card, 0, col)
            row.setColumnStretch(col, 1)
        layout.addLayout(row)

        mid = QGridLayout()
        mid.setHorizontalSpacing(14)
        mid.setVerticalSpacing(14)
        ring_panel = GlassPanel("System Pressure")
        ring_panel.setMaximumWidth(360)
        ring_row = QHBoxLayout()
        ring_row.setContentsMargins(0, 8, 0, 4)
        ring_row.setSpacing(18)
        ring_row.addStretch()
        self.cpu_ring = MetricRing("CPU", GREEN)
        self.ram_ring = MetricRing("RAM", CYAN)
        ring_row.addWidget(self.cpu_ring)
        ring_row.addWidget(self.ram_ring)
        ring_row.addStretch()
        ring_panel.outer.addLayout(ring_row)
        mid.addWidget(ring_panel, 0, 0, 2, 1)

        self.cpu_chart = Sparkline(GREEN, fill=True, height=148)
        self.ram_chart = Sparkline(CYAN, fill=True, height=148)
        mid.addWidget(self._panel("CPU Telemetry", self.cpu_chart), 0, 1)
        mid.addWidget(self._panel("RAM Telemetry", self.ram_chart), 1, 1)
        mid.setColumnStretch(0, 0)
        mid.setColumnStretch(1, 1)
        layout.addLayout(mid)

        bottom = QGridLayout()
        bottom.setHorizontalSpacing(14)
        bottom.setVerticalSpacing(14)
        self.ports_table = DataTable(["Port", "Address", "Process", "State"])
        self.users_table = DataTable(["User", "Terminal", "Source"])
        self.ports_table.setMinimumHeight(250)
        self.users_table.setMinimumHeight(250)
        bottom.addWidget(self._panel("Open Ports", self.ports_table), 0, 0)
        bottom.addWidget(self._panel("Active Users", self.users_table), 0, 1)
        bottom.setColumnStretch(0, 2)
        bottom.setColumnStretch(1, 1)
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
        self.ml_explain = QLabel("Scores are raw ML readings. Incidents are saved only after sustained anomaly, cooldown, and drift-guard checks pass.")
        self.ml_explain.setObjectName("Muted")
        self.ml_explain.setWordWrap(True)
        layout.addWidget(self.ml_explain)
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
        self.severity_chart = Sparkline(AMBER, fill=False, bar=True, height=210)
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

    def _settings_row(self, layout, label_text, widget, row, hint=None):
        label = QLabel(label_text)
        label.setObjectName("TinyLabel")
        layout.addWidget(label, row, 0)
        layout.addWidget(widget, row, 1)
        if hint:
            note = QLabel(hint)
            note.setObjectName("Muted")
            note.setWordWrap(True)
            layout.addWidget(note, row, 2)

    def _line_input(self, value="", secret=False, placeholder=""):
        field = QLineEdit()
        field.setText(str(value or ""))
        field.setPlaceholderText(placeholder)
        if secret:
            field.setEchoMode(QLineEdit.Password)
        return field

    def _spin_input(self, value, minimum=1, maximum=86400):
        field = QSpinBox()
        field.setRange(minimum, maximum)
        field.setValue(int(value))
        return field

    def _build_settings(self):
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(12)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setObjectName("TransparentScroll")
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(14)

        config_banner = QLabel(f"Config file: {CONFIG_PATH}")
        config_banner.setObjectName("WarningText")
        config_banner.setWordWrap(True)
        layout.addWidget(config_banner)

        general = GlassPanel("Runtime Controls")
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        self.setting_base_dir = self._line_input(getattr(config, "BASE_DIR", ""))
        self.setting_auth_log = self._line_input(getattr(config, "AUTH_LOG_PATH", "/var/log/auth.log"))
        self.setting_dry_run = QCheckBox("Dry-run mode")
        self.setting_dry_run.setChecked(bool(getattr(config, "DRY_RUN", True)))
        self.setting_whitelist = QTextEdit()
        self.setting_whitelist.setPlainText("\n".join(str(ip) for ip in getattr(config, "IP_WHITELIST", [])))
        self.setting_whitelist.setMaximumHeight(112)
        self._settings_row(grid, "Base directory", self.setting_base_dir, 0, "Reports and ML artifacts live here.")
        self._settings_row(grid, "Auth log path", self.setting_auth_log, 1, "Usually /var/log/auth.log on Debian/Kali.")
        self._settings_row(grid, "Firewall mode", self.setting_dry_run, 2, "Keep dry-run on until your admin IP is whitelisted.")
        self._settings_row(grid, "IP whitelist", self.setting_whitelist, 3, "One IP per line. Required before live blocking.")
        general.outer.addLayout(grid)
        layout.addWidget(general)

        detection = GlassPanel("Detection Thresholds")
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        self.setting_failed_threshold = self._spin_input(getattr(config, "FAILED_LOGIN_THRESHOLD", 5), 1, 1000)
        self.setting_time_window = self._spin_input(getattr(config, "TIME_WINDOW_SECONDS", 120), 10, 86400)
        self.setting_telemetry = self._spin_input(getattr(config, "TELEMETRY_INTERVAL", 30), 1, 3600)
        self.setting_ml_interval = self._spin_input(getattr(config, "ML_INFERENCE_INTERVAL", 10), 1, 3600)
        self.setting_ml_cooldown = self._spin_input(getattr(config, "ML_ANOMALY_COOLDOWN_SECONDS", 300), 0, 86400)
        self.setting_ml_required = self._spin_input(getattr(config, "ML_ANOMALY_CONSECUTIVE_REQUIRED", 3), 1, 100)
        self.setting_ml_drift = self._spin_input(getattr(config, "ML_DRIFT_RATIO_GUARD", 25), 1, 10000)
        self._settings_row(grid, "Failed login threshold", self.setting_failed_threshold, 0)
        self._settings_row(grid, "Time window seconds", self.setting_time_window, 1)
        self._settings_row(grid, "Telemetry interval", self.setting_telemetry, 2)
        self._settings_row(grid, "ML inference interval", self.setting_ml_interval, 3)
        self._settings_row(grid, "ML anomaly cooldown", self.setting_ml_cooldown, 4)
        self._settings_row(grid, "Consecutive ML anomalies", self.setting_ml_required, 5)
        self._settings_row(grid, "ML drift ratio guard", self.setting_ml_drift, 6)
        detection.outer.addLayout(grid)
        layout.addWidget(detection)

        integrations = GlassPanel("Integrations")
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        self.setting_groq_model = self._line_input(getattr(config, "GROQ_MODEL", "openai/gpt-oss-120b"))
        self.setting_groq_key = self._line_input(secret=True, placeholder="Leave blank to keep current Groq key")
        self.setting_discord_webhook = self._line_input(secret=True, placeholder="Leave blank to keep current Discord webhook")
        self.setting_abuse_key = self._line_input(secret=True, placeholder="Leave blank to keep current AbuseIPDB key")
        self.secret_status = QLabel(self._secret_status_text())
        self.secret_status.setObjectName("Muted")
        self.secret_status.setWordWrap(True)
        self._settings_row(grid, "Groq model", self.setting_groq_model, 0)
        self._settings_row(grid, "Groq API key", self.setting_groq_key, 1, "Existing secret is never displayed.")
        self._settings_row(grid, "Discord webhook", self.setting_discord_webhook, 2, "Paste a replacement only when rotating it.")
        self._settings_row(grid, "AbuseIPDB key", self.setting_abuse_key, 3, "Blank means keep the saved value.")
        grid.addWidget(self.secret_status, 4, 1, 1, 2)
        integrations.outer.addLayout(grid)
        layout.addWidget(integrations)

        reports = GlassPanel("Report Paths")
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        self.setting_csv_path = self._line_input(getattr(config, "CSV_REPORT_PATH", ""))
        self.setting_text_path = self._line_input(getattr(config, "TEXT_REPORT_PATH", ""))
        self._settings_row(grid, "CSV report path", self.setting_csv_path, 0)
        self._settings_row(grid, "Text report path", self.setting_text_path, 1)
        reports.outer.addLayout(grid)
        layout.addWidget(reports)

        actions = QHBoxLayout()
        self.settings_status = QLabel("")
        self.settings_status.setObjectName("Muted")
        self.save_settings_button = QPushButton("Save Settings")
        self.save_settings_button.clicked.connect(self._save_settings)
        self.reload_settings_button = QPushButton("Reload From Disk")
        self.reload_settings_button.clicked.connect(self._reload_settings_page)
        actions.addWidget(self.settings_status, 1)
        actions.addWidget(self.reload_settings_button)
        actions.addWidget(self.save_settings_button)
        layout.addLayout(actions)
        layout.addStretch()

        scroll.setWidget(container)
        page_layout.addWidget(scroll)
        self.stack.addWidget(page)

    def _secret_status_text(self):
        return " | ".join(
            f"{label}: {'configured' if _is_real_secret(getattr(config, field, '')) else 'not set'}"
            for label, field in [
                ("Groq", "GROQ_API_KEY"),
                ("Discord", "DISCORD_WEBHOOK_URL"),
                ("AbuseIPDB", "ABUSEIPDB_API_KEY"),
            ]
        )

    def _reload_settings_page(self):
        importlib.reload(config)
        importlib.reload(runtime_paths)
        self.setting_base_dir.setText(str(getattr(config, "BASE_DIR", "")))
        self.setting_auth_log.setText(str(getattr(config, "AUTH_LOG_PATH", "/var/log/auth.log")))
        self.setting_dry_run.setChecked(bool(getattr(config, "DRY_RUN", True)))
        self.setting_whitelist.setPlainText("\n".join(str(ip) for ip in getattr(config, "IP_WHITELIST", [])))
        self.setting_failed_threshold.setValue(int(getattr(config, "FAILED_LOGIN_THRESHOLD", 5)))
        self.setting_time_window.setValue(int(getattr(config, "TIME_WINDOW_SECONDS", 120)))
        self.setting_telemetry.setValue(int(getattr(config, "TELEMETRY_INTERVAL", 30)))
        self.setting_ml_interval.setValue(int(getattr(config, "ML_INFERENCE_INTERVAL", 10)))
        self.setting_ml_cooldown.setValue(int(getattr(config, "ML_ANOMALY_COOLDOWN_SECONDS", 300)))
        self.setting_ml_required.setValue(int(getattr(config, "ML_ANOMALY_CONSECUTIVE_REQUIRED", 3)))
        self.setting_ml_drift.setValue(int(getattr(config, "ML_DRIFT_RATIO_GUARD", 25)))
        self.setting_groq_model.setText(str(getattr(config, "GROQ_MODEL", "openai/gpt-oss-120b")))
        self.setting_groq_key.clear()
        self.setting_discord_webhook.clear()
        self.setting_abuse_key.clear()
        self.secret_status.setText(self._secret_status_text())
        self.setting_csv_path.setText(str(getattr(config, "CSV_REPORT_PATH", "")))
        self.setting_text_path.setText(str(getattr(config, "TEXT_REPORT_PATH", "")))
        self.settings_status.setText("Settings reloaded from disk.")

    def _collect_settings(self):
        whitelist = _split_whitelist(self.setting_whitelist.toPlainText())
        invalid_ips = _validate_whitelist(whitelist)
        if invalid_ips:
            raise ValueError(f"Invalid whitelist IP entries: {', '.join(invalid_ips)}")
        if not self.setting_dry_run.isChecked() and not whitelist:
            raise ValueError("Live blocking requires at least one admin IP in the whitelist.")
        data = _config_snapshot()
        data.update({
            "BASE_DIR": self.setting_base_dir.text().strip(),
            "AUTH_LOG_PATH": self.setting_auth_log.text().strip(),
            "FAILED_LOGIN_THRESHOLD": self.setting_failed_threshold.value(),
            "TIME_WINDOW_SECONDS": self.setting_time_window.value(),
            "TELEMETRY_INTERVAL": self.setting_telemetry.value(),
            "CSV_REPORT_PATH": self.setting_csv_path.text().strip(),
            "TEXT_REPORT_PATH": self.setting_text_path.text().strip(),
            "DRY_RUN": self.setting_dry_run.isChecked(),
            "IP_WHITELIST": whitelist,
            "GROQ_MODEL": self.setting_groq_model.text().strip() or "openai/gpt-oss-120b",
            "ML_INFERENCE_INTERVAL": self.setting_ml_interval.value(),
            "ML_ANOMALY_COOLDOWN_SECONDS": self.setting_ml_cooldown.value(),
            "ML_ANOMALY_CONSECUTIVE_REQUIRED": self.setting_ml_required.value(),
            "ML_DRIFT_RATIO_GUARD": self.setting_ml_drift.value(),
        })
        for field, widget in [
            ("GROQ_API_KEY", self.setting_groq_key),
            ("DISCORD_WEBHOOK_URL", self.setting_discord_webhook),
            ("ABUSEIPDB_API_KEY", self.setting_abuse_key),
        ]:
            value = widget.text().strip()
            if value:
                if value.startswith("your_"):
                    raise ValueError(f"{field} looks like a placeholder. Leave it blank to keep the current secret.")
                data[field] = value
        return data

    def _save_settings(self):
        try:
            data = self._collect_settings()
            _write_config_file(data)
            importlib.reload(config)
            importlib.reload(runtime_paths)
            runtime_paths.ensure_runtime_dirs()
            self._reload_settings_page()
            self.settings_status.setText("Settings saved. Restart aegis-daemon for daemon-only changes.")
            QMessageBox.information(self, "Settings Saved", "Settings were saved. Secrets were not echoed back to the UI. Restart aegis-daemon for daemon-only changes.")
            self.refresh()
        except PermissionError as exc:
            self.settings_status.setText("Permission denied while saving config.")
            QMessageBox.critical(self, "Save Failed", f"Permission denied writing {CONFIG_PATH}:\n{exc}")
        except Exception as exc:
            self.settings_status.setText("Settings not saved.")
            QMessageBox.warning(self, "Save Failed", str(exc))

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
        score_count = len(scores) if not scores.empty else 0
        anomaly_count = 0
        latest_score = "N/A"
        if not scores.empty and "score" in scores:
            numeric_scores = pd.to_numeric(scores["score"], errors="coerce").dropna()
            self.score_chart.set_values(numeric_scores.tolist())
            latest = numeric_scores.tail(1)
            if not latest.empty:
                latest_score = f"{float(latest.iloc[0]):.6f}"
            if "is_anomaly" in scores:
                anomaly_count = int(scores["is_anomaly"].astype(str).str.lower().isin(["true", "1"]).sum())
        self.ml_explain.setText(
            f"Raw ML samples shown: {score_count} | anomalous samples: {anomaly_count} | latest score: {latest_score}. "
            "Scores are not the same as incidents; the daemon saves an incident only after sustained anomaly, cooldown, and drift-guard checks pass."
        )
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
QLineEdit, QSpinBox, QTextEdit {{
    background: rgba(8, 18, 15, 190);
    color: #e4fff3;
    border: 1px solid rgba(58, 255, 181, 45);
    border-radius: 8px;
    padding: 8px 10px;
    selection-background-color: rgba(38, 240, 165, 90);
}}
QLineEdit:focus, QSpinBox:focus, QTextEdit:focus {{
    border: 1px solid rgba(38, 240, 165, 155);
}}
QCheckBox {{
    color: #e4fff3;
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 5px;
    border: 1px solid rgba(58, 255, 181, 95);
    background: rgba(8, 18, 15, 210);
}}
QCheckBox::indicator:checked {{
    background: #24f0a1;
    border-color: #24f0a1;
}}
QPushButton {{
    color: #e4fff3;
    background: rgba(14, 45, 34, 210);
    border: 1px solid rgba(38, 240, 165, 105);
    border-radius: 8px;
    padding: 9px 14px;
    font-weight: 800;
}}
QPushButton:hover {{
    background: rgba(24, 72, 54, 225);
    border-color: rgba(38, 240, 165, 180);
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
