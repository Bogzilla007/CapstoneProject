# Project Aegis - Configuration Template
# Copy this to config.py and fill in your values

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Groq API
GROQ_API_KEY = "your_groq_api_key_here"
GROQ_MODEL = "openai/gpt-oss-120b"

# Detection Settings
AUTH_LOG_PATH = "/var/log/auth.log"
FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 120

# Telemetry
TELEMETRY_INTERVAL = 30

# ML anomaly incident gating
# Scores are always logged to ml_data/anomaly_scores.csv, but an incident is
# only opened after sustained anomalies and cooldown checks pass.
ML_INFERENCE_INTERVAL = 10
ML_ANOMALY_COOLDOWN_SECONDS = 300
ML_ANOMALY_CONSECUTIVE_REQUIRED = 3
ML_DRIFT_RATIO_GUARD = 25

# Reports
CSV_REPORT_PATH = os.path.join(BASE_DIR, "reports", "incidents.csv")
TEXT_REPORT_PATH = os.path.join(BASE_DIR, "reports", "incidents.txt")

# Discord / threat intelligence
DISCORD_WEBHOOK_URL = "your_discord_webhook_url_here"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key_here"

# Dry Run Mode (True = no actual blocking)
DRY_RUN = True

# Safety controls
IP_WHITELIST = ["127.0.0.1", "::1"]
BLOCK_EXPIRY = {
    "LOW": 3600,
    "MEDIUM": 6 * 3600,
    "HIGH": 24 * 3600,
    "CRITICAL": 0,
}

# Discord escalation by severity
DISCORD_ESCALATION = {
    "LOW": "LOG_ONLY",
    "MEDIUM": "MESSAGE",
    "HIGH": "HERE",
    "CRITICAL": "HERE_FORENSICS",
}
