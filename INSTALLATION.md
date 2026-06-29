# Project Aegis — Installation Guide

## Prerequisites
- Kali Linux (or any Debian-based Linux), physical or VMware
- Python 3.13+
- Internet access
- Groq API key (free at console.groq.com)
- Discord server with webhook configured
- AbuseIPDB account (free at abuseipdb.com — needed for IP reputation lookups)

---

## Step 1 — Clone the Repository
```bash
git clone https://github.com/Bogzilla007/CapstoneProject.git
cd CapstoneProject
```

---

## Step 2 — Install Python Dependencies

Install for both regular user AND root (daemon runs as sudo):
```bash
pip install groq requests psutil streamlit plotly pandas --break-system-packages
sudo pip install groq requests psutil streamlit plotly pandas --break-system-packages
```

Install TensorFlow (large download ~600MB — use TMPDIR workaround if /tmp is small):
```bash
mkdir -p ~/tmp_pip
sudo TMPDIR=~/tmp_pip pip install tensorflow --break-system-packages
```

Install scikit-learn for BOTH user and root:
```bash
pip install scikit-learn joblib --break-system-packages
sudo pip install scikit-learn joblib --break-system-packages
```

Install sshpass for attack simulation testing:
```bash
sudo apt install sshpass -y
```

---

## Step 3 — Configure the Project
```bash
cp config.example.py config.py
```

Edit config.py and fill in all required values:
```python
GROQ_API_KEY        = "gsk_..."           # from console.groq.com
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/..."
ABUSEIPDB_API_KEY   = "..."               # from abuseipdb.com/account/api
DRY_RUN             = True                # set False only after whitelist configured

# Add your own IP to prevent accidental self-blocking
IP_WHITELIST = ["127.0.0.1", "::1", "YOUR_IP_HERE"]
```

> Never commit config.py to git — it is gitignored by default.

---

## Step 4 — Enable Required System Services

SSH server (needed for auth.log to populate):
```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

rsyslog (provides /var/log/auth.log):
```bash
sudo apt install rsyslog -y
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

UFW firewall:
```bash
sudo apt install ufw -y
sudo ufw enable
```

---

## Step 5 — Train the Initial ML Model

Before running the daemon, collect baseline data and train the LSTM model:
```bash
# Collect ~200 rows of normal behaviour (takes ~35 minutes at 10s intervals)
sudo python3 collector.py

# Or train immediately on any existing data:
sudo python3 trainer.py
```

The model is saved to ml_data/model/aegis_model.keras.
Once trained, the daemon will auto-retrain in the background continuously.

---

## Step 6 — Run the Daemon

### Option A — Direct (recommended for testing, shows live output):
```bash
cd ~/project-aegis
sudo python3 daemon.py
```

### Option B — As a systemd service (runs on boot, background):
```bash
sudo cp aegis.service /etc/systemd/system/aegis.service
sudo systemctl daemon-reload
sudo systemctl enable aegis
sudo systemctl start aegis

# Check status:
sudo systemctl status aegis
sudo journalctl -u aegis -f
```

---

## Step 7 — Launch the Dashboard

Always launch from the project directory:
```bash
cd ~/project-aegis
streamlit run dashboard.py
```

Open browser at: http://localhost:8501

The dashboard auto-refreshes every 10 seconds. Five tabs:
- Overview — live telemetry, CPU/RAM, open ports, active users
- Incidents — incident cards with detection badges, AI summaries
- ML Status — model phase, anomaly score graph, threshold line
- Timeline — attack heatmap, top attacking IPs, top targeted usernames
- Block Manager — blocked IPs, expiry times, manual unblock

---

## Step 8 — Test the System

Fire a simulated brute force attack in a second terminal:
```bash
# Triggers SLOW_PROBE at 3, BRUTE_FORCE at 5, PERSISTENT_PROBE at 10
for i in {1..10}; do
    sshpass -p wrongpass ssh -o StrictHostKeyChecking=no fakeuser@127.0.0.1 2>/dev/null
    sleep 2
done
```

Expected output in daemon terminal:
[~] Failed login from 127.0.0.1 (user: fakeuser) - 1/5 in window

[~] Failed login from 127.0.0.1 (user: fakeuser) - 3/5 in window

[L3] SLOW_PROBE detected for 127.0.0.1

[!] SENTINEL TRIGGERED - Gathering forensics on 127.0.0.1

[~] Failed login from 127.0.0.1 (user: fakeuser) - 5/5 in window

[!] SENTINEL TRIGGERED - Gathering forensics on 127.0.0.1

[L3] PERSISTENT_PROBE detected for 127.0.0.1

[+] Verdict: HIGH — BLOCK

[+] Discord alert sent (HERE).

---

## Step 9 — Go Live (disable DRY_RUN)

> Only do this after confirming your IP is in IP_WHITELIST.

In config.py:
```python
DRY_RUN = False
```

Restart the daemon. Real ufw rules will now be applied for BLOCK verdicts.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `No module named tensorflow` | `sudo TMPDIR=~/tmp_pip pip install tensorflow --break-system-packages` |
| `No module named sklearn` | `sudo pip install scikit-learn --break-system-packages` (must be sudo) |
| `No module named groq` | `sudo pip install groq --break-system-packages` |
| `auth.log missing` | `sudo apt install rsyslog -y && sudo systemctl start rsyslog` |
| `ufw not found` | `sudo apt install ufw -y` |
| TF CUDA warnings | Normal — CPU-only install, ignore all CUDA/GPU warnings |
| TF oneDNN warnings | Normal — ignore |
| Dashboard shows no incidents | Launch streamlit from `cd ~/project-aegis` directory |
| Model not loading | Run `sudo python3 trainer.py` to generate initial model |
| __pycache__ permission errors | `sudo rm -rf __pycache__` then retry |
| pip download fails (no space) | `mkdir -p ~/tmp_pip && sudo TMPDIR=~/tmp_pip pip install ...` |
| AbuseIPDB 429 error | Free tier rate limit hit — cache TTL handles this automatically |

---

## Architecture Reference
See ARCHITECTURE.md for full system design, thread map, detection labels,
intelligence pipeline, and file descriptions.
