# Project Aegis - Configuration Template
# Copy this to config.py and fill in your values

# Groq API
GROQ_API_KEY = "your_groq_api_key_here"
GROQ_MODEL = "openai/gpt-oss-120b"

# Detection Settings
AUTH_LOG_PATH = "/var/log/auth.log"
FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 120

# Telemetry
TELEMETRY_INTERVAL = 30

# Reports
CSV_REPORT_PATH = "reports/incidents.csv"
TEXT_REPORT_PATH = "reports/incidents.txt"

# Discord
DISCORD_WEBHOOK_URL = "your_discord_webhook_url_here"

# Dry Run Mode (True = no actual blocking)
DRY_RUN = True
