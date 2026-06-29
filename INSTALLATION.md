# Project Aegis Installation Guide

Project Aegis now installs as a native Kali/Linux app:

- `aegis-daemon` runs continuously in the background through systemd.
- `dashboard.py` opens a PySide6/Qt desktop window.
- No Streamlit server is used.
- No browser dashboard is used.

## Prerequisites

- Kali Linux or another Debian-based Linux system
- Python 3.13+
- Internet access
- Groq API key
- Discord webhook
- AbuseIPDB API key
- SSH service enabled
- UFW firewall enabled

## Clone The Repository

```bash
git clone https://github.com/Bogzilla007/CapstoneProject.git
cd CapstoneProject
```

## Install System Packages

```bash
sudo apt update
sudo apt install rsyslog ufw ssh sshpass python3-pyside6.qtwidgets -y
```

## Install Python Dependencies

Install for your user and root:

```bash
pip install -r requirements.txt --break-system-packages
sudo pip install -r requirements.txt --break-system-packages
```

If TensorFlow fails because `/tmp` is small:

```bash
mkdir -p ~/tmp_pip
sudo TMPDIR=~/tmp_pip pip install tensorflow --break-system-packages
```

## Configure Aegis

```bash
cp config.example.py config.py
nano config.py
```

Set:

```python
GROQ_API_KEY = "gsk_..."
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/..."
ABUSEIPDB_API_KEY = "..."
DRY_RUN = True
IP_WHITELIST = ["127.0.0.1", "::1", "YOUR_ADMIN_IP"]
```

Do not commit `config.py`; it is gitignored.

## Enable Required Services

```bash
sudo systemctl enable ssh rsyslog
sudo systemctl start ssh rsyslog
sudo ufw enable
```

## Train The Initial ML Model

Collect baseline behavior:

```bash
sudo python3 data_collector.py
```

Let it run for at least 30 to 35 minutes, then stop it with `Ctrl+C`.

Train:

```bash
sudo python3 train_model.py
```

Artifacts are saved to:

```text
ml_data/model/aegis_model.keras
ml_data/model/scaler.pkl
ml_data/model/metadata.json
```

## Install Background Monitor

```bash
sudo bash install_systemd.sh
```

Check:

```bash
sudo systemctl status aegis-daemon
sudo journalctl -u aegis-daemon -f
```

## Install Desktop App Launcher

Run as your normal desktop user, not sudo:

```bash
bash install_desktop_app.sh
```

Then open `Project Aegis` from the Kali app menu.

You can also launch directly:

```bash
python3 dashboard.py
```

This opens a native desktop window.

## Test The System

```bash
for i in {1..10}; do
    sshpass -p wrongpass ssh -o StrictHostKeyChecking=no fakeuser@127.0.0.1 2>/dev/null
    sleep 2
done
```

Watch daemon logs:

```bash
sudo journalctl -u aegis-daemon -f
```

## Go Live

Keep this while testing:

```python
DRY_RUN = True
```

Only after confirming your admin IP is in `IP_WHITELIST`, set:

```python
DRY_RUN = False
```

Restart:

```bash
sudo systemctl restart aegis-daemon
```

## Troubleshooting

| Issue | Fix |
|---|---|
| `No module named PySide6` | `pip install PySide6 --break-system-packages` |
| Desktop app does not open | Run `python3 dashboard.py` in a terminal to see the error |
| `No module named tensorflow` | `sudo TMPDIR=~/tmp_pip pip install tensorflow --break-system-packages` |
| `No module named sklearn` | `sudo pip install scikit-learn joblib --break-system-packages` |
| `No module named groq` | `sudo pip install groq --break-system-packages` |
| `auth.log missing` | `sudo apt install rsyslog -y && sudo systemctl start rsyslog` |
| `ufw not found` | `sudo apt install ufw -y` |
| Daemon not detecting SSH events | Confirm `ssh`, `rsyslog`, and `/var/log/auth.log` are working |
| Model not loading | Run `sudo python3 data_collector.py`, then `sudo python3 train_model.py` |
| pip download fails | Use the `TMPDIR=~/tmp_pip` workaround above |
