# Project Aegis — Architecture Overview

## System Overview
Project Aegis is an autonomous Endpoint Detection & Response (EDR) system
built in Python. It continuously monitors a Linux system for security threats,
investigates attackers using AI, and actively defends the system.

## Architecture Diagram
[200~┌─────────────────────────────────────────────────────────────┐

│                     PROJECT AEGIS                           │

│                                                             │

│  ┌─────────────┐     ┌──────────────┐    ┌──────────────┐  │

│  │  /var/log/  │────▶│   daemon.py  │───▶│system_checks │  │

│  │  auth.log   │     │  (Core Loop) │    │  open ports  │  │

│  └─────────────┘     └──────┬───────┘    │  active users│  │

│                             │            │  services    │  │

│  ┌─────────────┐            │            └──────────────┘  │

│  │   psutil    │────▶ telemetry                            │

│  │  CPU/RAM    │      polling                              │

│  └─────────────┘            │                             │

│                             ▼                             │

│                    ┌────────────────┐                     │

│                    │  SENTINEL      │                     │

│                    │  TRIGGER       │                     │

│                    │  5+ failures   │                     │

│                    │  in 60s window │                     │

│                    └───────┬────────┘                     │

│                            │                             │

│              ┌─────────────┼─────────────┐               │

│              ▼             ▼             ▼               │

│        ┌──────────┐ ┌──────────┐ ┌──────────┐           │

│        │  whois   │ │ip-api.com│ │  ps aux  │           │

│        │  lookup  │ │  GeoIP   │ │ snapshot │           │

│        └────┬─────┘ └────┬─────┘ └────┬─────┘           │

│             └────────────┼────────────┘                  │

│                          ▼                               │

│                 ┌─────────────────┐                      │

│                 │  llm_analyst.py │                      │

│                 │  Groq API       │                      │

│                 │  llama3-70b     │                      │

│                 │  JSON Verdict   │                      │

│                 └────────┬────────┘                      │

│                          │                               │

│              ┌───────────┼───────────┐                   │

│              ▼           ▼           ▼                   │

│        ┌──────────┐ ┌─────────┐ ┌────────┐              │

│        │mitigation│ │ reports │ │Discord │              │

│        │ufw block │ │CSV+Text │ │webhook │              │

│        └──────────┘ └─────────┘ └────────┘              │

│                                                          │

│  ┌────────────────────────────────────────────────────┐  │

│  │              dashboard.py (Streamlit)              │  │

│  │  Telemetry │ Threat Feed │ Kill Chain │ Export     │  │

│  └────────────────────────────────────────────────────┘  │

└─────────────────────────────────────────────────────────┘~
## Component Breakdown

### daemon.py — Core Engine
The main background process. Runs as a systemd service, starts on boot.
Tails auth.log in real time, tracks failed logins per IP within a sliding
time window, triggers the Sentinel pipeline when threshold is breached.

### system_checks.py — Security Enumerator
Runs periodic checks on open ports (ss), active users (who), and running
services (systemctl). Results fed into forensics reports and dashboard.

### llm_analyst.py — AI Brain
Packages forensics data into a structured prompt and sends to Groq API.
Forces JSON output with severity classification and executive summary.
Includes fallback parser for malformed responses.

### mitigation.py — Active Defense
Executes ufw firewall rules to block attacker IPs. Maintains a blocklist log.
Fires Discord webhook with rich embed alert. Supports dry-run mode.

### dashboard.py — C2 Interface
Streamlit web app. Shows live telemetry, resource graphs, open ports,
active users, running services, threat feed, kill chain, and report exports.
Auto-refreshes every 10 seconds.

### config.py — Configuration
Central config file. API keys, thresholds, paths, dry-run toggle.
Never committed to version control (.gitignored).

## Data Flow
1. auth.log gets a new failed SSH line
2. daemon.py extracts attacker IP
3. Failure count tracked in sliding time window
4. Threshold breached → Sentinel triggered
5. whois + GeoIP + process snapshot gathered
6. Forensics packaged → sent to Groq
7. Groq returns JSON verdict + summary
8. If BLOCK → ufw rule added
9. Discord webhook fired
10. CSV + Text reports updated
11. Dashboard reflects new incident on next refresh

## Security Considerations
- API keys stored in config.py, gitignored
- Dry-run mode prevents accidental self-blocking
- Groq responses validated with fallback parser
- Service runs as root only for ufw/log access
