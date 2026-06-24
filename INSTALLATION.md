# Project Aegis — Installation Guide

## Prerequisites
- Kali Linux (or any Debian-based Linux)
- Python 3.13+
- Internet access
- Groq API key (free at console.groq.com)
- Discord server with webhook access

## Step 1 — Clone the Repository
```bash
git clone https://github.com/Bogzilla007/CapstoneProject.git
cd CapstoneProject
```

## Step 2 — Install Dependencies
```bash
sudo pip3 install groq requests psutil streamlit --break-system-packages
```

## Step 3 — Configure the Project
```bash
cp config.example.py config.py
nano config.py
```
Fill in:
- `GROQ_API_KEY` — your Groq API key
- `DISCORD_WEBHOOK_URL` — your Discord webhook URL
- Adjust thresholds if needed

## Step 4 — Enable SSH Server
```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

## Step 5 — Enable Firewall
```bash
sudo apt install ufw -y
sudo ufw enable
```

## Step 6 — Install rsyslog (for auth.log)
```bash
sudo apt install rsyslog -y
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

## Step 7 — Install Aegis as a System Service
```bash
sudo cp aegis.service /etc/systemd/system/aegis.service
sudo systemctl daemon-reload
sudo systemctl enable aegis
sudo systemctl start aegis
```

## Step 8 — Verify Daemon is Running
```bash
sudo systemctl status aegis
sudo tail -f reports/aegis.log
```

## Step 9 — Launch the Dashboard
```bash
python3 -m streamlit run dashboard.py --server.port 8501
```
Open browser at: http://localhost:8501

## Step 10 — Test the System
```bash
# Generate fake failed SSH logins
for i in {1..6}; do sshpass -p "wrong" ssh -o StrictHostKeyChecking=no fakeuser@127.0.0.1 2>/dev/null; done
```
Watch the dashboard update and check Discord for alerts.

## Dry Run Mode
By default `DRY_RUN = True` in config.py — the system logs what it would do without
actually blocking IPs. Set to `False` for live blocking during demo.

## Troubleshooting
| Issue | Fix |
|---|---|
| groq not found | `sudo pip3 install groq --break-system-packages` |
| auth.log missing | `sudo apt install rsyslog -y` |
| ufw not found | `sudo apt install ufw -y` |
| Dashboard blank | Check reports/ folder exists |
| Service not starting | `sudo journalctl -u aegis -n 20` |
