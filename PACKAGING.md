# Debian Package Build

Project Aegis can be packaged as a Debian package for Kali, Debian, Ubuntu,
and related distributions.

## Build On Linux

Install build tools:

```bash
sudo apt update
sudo apt install dpkg-dev rsync -y
```

Build the package from the repository root:

```bash
bash build_deb.sh
```

The package is written to:

```text
dist/project-aegis_0.2.3_all.deb
```

You can override version and architecture:

```bash
VERSION=1.0.0 ARCH=amd64 bash build_deb.sh
```

## Install

```bash
sudo apt install ./dist/project-aegis_0.2.3_all.deb
```

The package installs:

| Path | Purpose |
|---|---|
| `/opt/project-aegis` | Application files |
| `/etc/project-aegis/config.py` | Editable system configuration |
| `/var/lib/project-aegis` | Reports, telemetry, and ML artifacts |
| `/usr/bin/aegis-daemon` | Daemon launcher |
| `/usr/bin/aegis-dashboard` | Desktop dashboard launcher |
| `/usr/bin/aegis-collect-baseline` | Baseline telemetry collector |
| `/usr/bin/aegis-train-model` | ML training command |
| `/etc/systemd/system/aegis-daemon.service` | systemd service |
| `/usr/share/applications/project-aegis.desktop` | Desktop menu launcher |

## Runtime Dependencies

The Debian package installs the operating-system dependencies it can declare
portably. Python packages still need to be installed into the target system:

```bash
sudo python3 -m pip install -r /usr/share/doc/project-aegis/requirements.txt --break-system-packages
```

This is kept explicit because packages such as `groq`, `tensorflow`, and
`PySide6` vary by Debian/Kali release and should not be downloaded silently
during `dpkg` installation.

## Configure And Start

Edit secrets and safety settings:

```bash
sudo nano /etc/project-aegis/config.py
```

Keep `DRY_RUN = True` while testing. Then enable the daemon:

```bash
sudo systemctl enable --now aegis-daemon
sudo journalctl -u aegis-daemon -f
```

Open the dashboard:

```bash
aegis-dashboard
```

Collect baseline telemetry and train the model:

```bash
sudo aegis-collect-baseline
sudo aegis-train-model
```
