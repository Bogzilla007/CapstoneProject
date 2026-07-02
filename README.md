# Project Aegis

Project Aegis is a native desktop security monitoring app for Kali Linux and other Debian-based Linux systems. The security monitor runs continuously in the background as a systemd daemon, while the SOC console opens as a real desktop window built with PySide6/Qt.

It watches SSH authentication logs, collects system telemetry, detects brute-force and behavioral anomalies, enriches incidents with threat intelligence, applies mitigation decisions, and displays live status in a dark desktop dashboard.

## App Shape

Project Aegis is no longer a Streamlit web dashboard.

- `aegis-daemon` runs the continuous security monitor in the background.
- `dashboard.py` opens a native PySide6 desktop window.
- `install_systemd.sh` installs only the daemon service.
- `install_desktop_app.sh` adds Project Aegis to the Kali app menu.

The daemon should run as root because it reads `/var/log/auth.log` and controls UFW. The desktop dashboard runs as your normal logged-in user and reads the generated reports, metrics, model metadata, and blocklist.

## Why PySide6 Instead Of Tkinter

Tkinter is fine for small utility windows, but it is not ideal for the kind of polished dark SOC dashboard shown in your reference image. PySide6/Qt is a better fit because it supports richer layouts, better tables, custom painted charts, native desktop integration, cleaner styling, and a more professional app feel.

## Main Features

- Native desktop SOC dashboard
- Continuous `/var/log/auth.log` monitoring
- SSH brute-force detection
- Slow and persistent probe detection
- Distributed attack detection
- New open-port detection
- LSTM-based ML anomaly scoring
- Background model retraining on clean telemetry
- AbuseIPDB IP reputation lookups
- Groq LLM incident analysis and verdict generation
- UFW blocking with whitelist and dry-run safety
- Auto-expiring LOW/MEDIUM blocks
- Discord alerting with severity-based escalation
- CSV and TXT incident reports
- systemd startup service for boot-time monitoring

## Repository Map

| File | Purpose |
|---|---|
| `daemon.py` | Main continuous monitoring process and incident pipeline |
| `dashboard.py` | Native PySide6 desktop SOC dashboard |
| `collector.py` | Runtime telemetry collector |
| `trainer.py` | Background ML retraining engine |
| `ml_detector.py` | LSTM anomaly inference |
| `mitigation.py` | UFW blocking, unblock logic, and Discord alerts |
| `resilience.py` | UFW integrity and auth log tamper monitoring |
| `log_parser.py` | Auth log parsing, username extraction, timing analysis |
| `threat_tracker.py` | Slow probe, persistent probe, distributed attack, and port tracking |
| `threat_intel.py` | AbuseIPDB lookups and severity escalation |
| `llm_analyst.py` | Groq prompt builder and fallback classifier |
| `system_checks.py` | Open ports, active users, and service snapshots |
| `runtime_paths.py` | Shared runtime paths for reports, ML data, and models |
| `config.example.py` | Safe configuration template |
| `config.py` | Local secrets/config file, gitignored |
| `requirements.txt` | Python dependency list |
| `install_systemd.sh` | Installs the daemon service |
| `install_desktop_app.sh` | Installs the desktop launcher |
| `aegis-daemon.service` | systemd template for daemon |
| `aegis-dashboard.desktop` | Desktop launcher template |
| `start_aegis.sh` | Direct daemon launcher |

## Prerequisites

- Kali Linux or another Debian-based Linux system
- Python 3.13+
- Internet access
- Groq API key from `console.groq.com`
- Discord webhook URL
- AbuseIPDB API key from `abuseipdb.com`
- SSH server enabled so `/var/log/auth.log` receives SSH auth events
- UFW installed for firewall mitigation

### Quick Start On Kali

Clone the repository:

```bash
git clone https://github.com/Bogzilla007/CapstoneProject.git
cd CapstoneProject
```

There are two ways to install Project Aegis: as a `.deb` package (recommended) or manually.

---

### Option A: Install As A Debian Package (Recommended)

Install build tools and build the package:

```bash
sudo apt update
sudo apt install dpkg-dev rsync -y
bash build_deb.sh
```

Install the generated package:

```bash
sudo apt install ./dist/project-aegis_0.2.2_all.deb
```

The package installs the app under `/opt/project-aegis`, configuration under `/etc/project-aegis/config.py`, runtime data under `/var/lib/project-aegis`, launchers under `/usr/bin`, and the `aegis-daemon` systemd service. See `PACKAGING.md` for the full package workflow.

You still need to install the Python dependencies and system services. Continue from the **Install Dependencies** section below.

---

### Option B: Manual Install (No Package)

If you prefer not to use the `.deb` package, you can run Project Aegis directly from the cloned repository. Continue from the **Install Dependencies** section below, then use the manual install scripts for the daemon and desktop app.

---

## Install Dependencies

Install required Linux packages:

```bash
sudo apt update
sudo apt install rsyslog ufw ssh sshpass python3-pyside6.qtwidgets -y
```

Install Python dependencies for your user and root. The daemon usually runs as root because it reads system logs and controls UFW:

```bash
pip install -r requirements.txt --break-system-packages
sudo pip install -r requirements.txt --break-system-packages
```

If TensorFlow fails because `/tmp` is too small:

```bash
mkdir -p ~/tmp_pip
sudo TMPDIR=~/tmp_pip pip install tensorflow --break-system-packages
```

Enable required system services:

```bash
sudo systemctl enable ssh rsyslog
sudo systemctl start ssh rsyslog
sudo ufw enable
```

## Configure

Create local config:

```bash
cp config.example.py config.py
nano config.py
```

Fill in the required values:

```python
GROQ_API_KEY = "gsk_..."
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/..."
ABUSEIPDB_API_KEY = "..."
DRY_RUN = True
IP_WHITELIST = ["127.0.0.1", "::1", "YOUR_ADMIN_IP"]
```

`config.py` is gitignored. Do not commit API keys.

If you installed via the `.deb` package, edit the config at `/etc/project-aegis/config.py` instead.

## Train The Initial ML Model

Project Aegis can still defend with rule-based detection while the ML model warms up, but ML anomaly detection needs baseline telemetry.

Collect baseline behavior:

```bash
sudo python3 data_collector.py
```

Let it run for at least 30 to 35 minutes, then stop it with `Ctrl+C`.

Train the model:

```bash
sudo python3 train_model.py
```

The trained artifacts are stored in:

```text
ml_data/model/aegis_model.keras
ml_data/model/scaler.pkl
ml_data/model/metadata.json
```

After the daemon starts, `trainer.py` can continue retraining in the background as clean telemetry accumulates.

## Install The Background Monitor

Install the daemon as a boot-time systemd service:

```bash
sudo bash install_systemd.sh
```

Check status:

```bash
sudo systemctl status aegis-daemon
```

Watch daemon logs:

```bash
sudo journalctl -u aegis-daemon -f
```

Restart the daemon:

```bash
sudo systemctl restart aegis-daemon
```

## Install The Desktop App

Install the Project Aegis launcher into your Kali app menu:

```bash
bash install_desktop_app.sh
```

Then open `Project Aegis` from the app menu.

You can also launch it directly:

```bash
python3 dashboard.py
```

This opens a native desktop window. No Streamlit server and no browser are used.

## Updating

To update Project Aegis to a new version:

```bash
cd CapstoneProject
git pull
```

If you installed via the `.deb` package, rebuild and reinstall:

```bash
bash build_deb.sh
sudo apt install ./dist/project-aegis_0.2.2_all.deb
```

Then restart the daemon to pick up changes:

```bash
sudo systemctl restart aegis-daemon
```

The dashboard will pick up changes the next time it is launched.

## Desktop Dashboard Tabs

| Tab | Purpose |
|---|---|
| Overview | Live CPU/RAM gauges, host status, open ports, active users, incident/block totals |
| Incidents | Recent incident feed with severity badges, dismiss individual incidents or clear all |
| ML Status | Model metadata, phase estimate, threshold, clean rows, anomaly score chart |
| Timeline | Top attacking IPs, targeted usernames, and severity distribution |
| Block Manager | Blocklist, expiry status, dry-run warning, whitelist view |
| Settings | Edit daemon configuration, API keys, thresholds, and whitelist from the GUI |

## Test The System

Run a simulated SSH brute-force attempt in a second terminal:

```bash
for i in {1..10}; do
    sshpass -p wrongpass ssh -o StrictHostKeyChecking=no fakeuser@127.0.0.1 2>/dev/null
    sleep 2
done
```

Expected daemon behavior:

```text
[~] Failed login from 127.0.0.1 (user: fakeuser) - 1/5 in window
[L3] SLOW_PROBE detected for 127.0.0.1
[!] SENTINEL TRIGGERED - Gathering forensics on 127.0.0.1
[~] Failed login from 127.0.0.1 (user: fakeuser) - 5/5 in window
[+] Verdict: HIGH - BLOCK
[+] Discord alert sent (HERE).
```

If `DRY_RUN = True`, Aegis logs what it would block without changing firewall rules.

## Go Live

Keep dry-run enabled while testing:

```python
DRY_RUN = True
```

Before real blocking, make sure your current/admin IP is in `IP_WHITELIST`:

```python
IP_WHITELIST = ["127.0.0.1", "::1", "YOUR_ADMIN_IP"]
```

Then enable real blocking:

```python
DRY_RUN = False
```

Restart the daemon:

```bash
sudo systemctl restart aegis-daemon
```

## Architecture Overview

Project Aegis detects attacks across several layers and routes every incident through one pipeline:

```text
/var/log/auth.log      -> Layer 1 Rule Engine       -> BRUTE_FORCE
psutil + auth.log      -> Layer 2 LSTM Autoencoder  -> ML_ANOMALY
auth.log slow patterns -> Layer 3 Threat Tracker    -> SLOW/PERSISTENT/DISTRIBUTED
open port baseline     -> Layer 3 Port Watcher      -> NEW_PORT_DETECTED
self-defense checks    -> Resilience Layer          -> UFW/LOG_TAMPER alerts

All detections -> forensics -> AbuseIPDB -> Groq LLM -> verdict -> UFW/Discord/reports/dashboard
```

## Thread Architecture

| Thread | Name | Tick | Role |
|---|---|---|---|
| 1 | Rule-Engine | 0.5s | Tails auth.log and detects brute force attempts |
| 2 | Collector | 10s | Samples six system features, feeds ML, writes `system_metrics.csv` |
| 3 | ML-Inference | 10s | Runs LSTM anomaly scoring and fires `ML_ANOMALY` |
| 4 | Trainer | 60min or 200 rows | Retrains model with data guard and hot reloads it |
| 5 | Port-Watcher | 60s | Diffs open ports against baseline |
| 6 | Resilience | 60s and 30s | Checks UFW integrity and auth log tampering |

## Intelligence Pipeline

1. Any detection layer triggers an incident.
2. `gather_forensics()` collects telemetry, process snapshots, open ports, active users, running services, whois, and GeoIP.
3. `threat_intel.py` checks AbuseIPDB when the target is a public IP.
4. `llm_analyst.py` sends enriched forensics to Groq and receives `{severity, action, summary}`.
5. Fallback classifier produces a verdict if Groq is unavailable.
6. AbuseIPDB reputation can escalate severity.
7. `mitigation.py` checks whitelist and dry-run mode.
8. UFW block is applied if verdict action is `BLOCK` and dry-run is off.
9. Discord alert is sent based on severity.
10. CSV/TXT reports are saved and shown in the desktop dashboard.

## ML Pipeline

`collector.py` samples every 10 seconds:

- `cpu_percent`
- `ram_percent`
- `failed_logins`
- `active_users`
- `open_ports`
- `hour_of_day`

It writes to:

```text
ml_data/system_metrics.csv
```

`ml_detector.py` keeps a rolling 20-timestep window and runs the LSTM autoencoder. The reconstruction error becomes the anomaly score. Scores are written to:

```text
ml_data/anomaly_scores.csv
```

`trainer.py` retrains every 60 minutes or after 200 new rows, using a data guard:

- Filter rows already scored as anomalous
- Filter rows within 5 minutes of incidents
- Abort if fewer than 100 clean rows survive

Model artifacts are atomically swapped so the daemon does not load half-written files.

## Detection Labels

| Label | Layer | Trigger |
|---|---|---|
| `BRUTE_FORCE` | 1 | 5+ failed logins from one IP in 120 seconds |
| `ML_ANOMALY` | 2 | LSTM reconstruction error exceeds threshold |
| `SLOW_PROBE` | 3 | 3+ failures from one IP in 1 hour |
| `PERSISTENT_PROBE` | 3 | 10+ failures from one IP in 24 hours |
| `DISTRIBUTED_ATTACK` | 3 | Many low-volume IPs inside the same time window |
| `NEW_PORT_DETECTED` | 3 | New listening port compared to baseline |
| `PRIV_ESC_ATTEMPT` | Parser | sudo/auth privilege escalation signal |
| `BREACH_SUSPECTED` | Parser | Successful login after failed attempts |
| `UNUSUAL_HOUR` | Parser | Login outside expected activity hours |
| `LOG_TAMPER` | Resilience | Auth log missing, shrunk, or replaced |
| `UFW_INTEGRITY_VIOLATION` | Resilience | Expected UFW rule is missing |

## Runtime Data Files

| File | Contents |
|---|---|
| `reports/incidents.csv` | Structured incident log for dashboard |
| `reports/incidents.txt` | Human-readable full incident reports |
| `reports/blocklist.txt` | Blocked IPs, severity, timestamp, expiry, reason |
| `ml_data/system_metrics.csv` | Runtime telemetry samples |
| `ml_data/normal_behavior.csv` | Baseline training data |
| `ml_data/anomaly_scores.csv` | ML anomaly score history |
| `ml_data/model/aegis_model.keras` | Trained LSTM autoencoder |
| `ml_data/model/scaler.pkl` | Feature scaler |
| `ml_data/model/metadata.json` | Threshold, training timestamp, feature metadata |

## Security Notes

- `config.py` is gitignored and should contain all secrets.
- `DRY_RUN = True` is the safest testing mode.
- Always whitelist your admin IP before enabling real blocking.
- LOW and MEDIUM blocks auto-expire by default.
- HIGH and CRITICAL blocks are permanent unless manually removed.
- UFW integrity checks can re-add missing firewall rules.
- Log tamper checks can alert if `/var/log/auth.log` shrinks, disappears, or changes inode.
- Groq fallback classification keeps incident handling alive if the API fails.
- ML retraining filters anomalous and incident-adjacent data to avoid poisoning the baseline.

## Troubleshooting

| Issue | Fix |
|---|---|
| `No module named PySide6` | `pip install PySide6 --break-system-packages` |
| Desktop app does not open from menu | Run `bash install_desktop_app.sh`, then try `python3 dashboard.py` for terminal errors |
| `No module named tensorflow` | `sudo TMPDIR=~/tmp_pip pip install tensorflow --break-system-packages` |
| `No module named sklearn` | `sudo pip install scikit-learn joblib --break-system-packages` |
| `No module named groq` | `sudo pip install groq --break-system-packages` |
| `auth.log missing` | `sudo apt install rsyslog -y && sudo systemctl start rsyslog` |
| `ufw not found` | `sudo apt install ufw -y` |
| Daemon not detecting SSH events | Confirm `ssh` and `rsyslog` are running and `/var/log/auth.log` is updating |
| Model not loading | Run `sudo python3 data_collector.py`, then `sudo python3 train_model.py` |
| Permission errors in cache files | Remove stale root-owned cache: `sudo rm -rf __pycache__` |
| pip download fails due to disk space | Use `TMPDIR=~/tmp_pip` workaround shown above |
| AbuseIPDB 429 error | Free tier rate limit hit; wait or reduce lookup frequency |

## Current App Shape

Project Aegis is now a continuous Kali/Linux monitoring daemon plus a native PySide6 desktop dashboard. There is no Streamlit server and no browser dashboard path.
