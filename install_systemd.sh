#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_SERVICE="/etc/systemd/system/aegis-daemon.service"

if [ "${EUID}" -ne 0 ]; then
  echo "Run with sudo: sudo bash install_systemd.sh"
  exit 1
fi

if [ ! -f "${PROJECT_DIR}/config.py" ]; then
  cp "${PROJECT_DIR}/config.example.py" "${PROJECT_DIR}/config.py"
  echo "Created config.py. Edit API keys and whitelist before disabling DRY_RUN."
fi

mkdir -p "${PROJECT_DIR}/reports" "${PROJECT_DIR}/ml_data/model"

sed "s#__PROJECT_DIR__#${PROJECT_DIR}#g" "${PROJECT_DIR}/aegis-daemon.service" > "${DAEMON_SERVICE}"

systemctl daemon-reload
systemctl enable aegis-daemon.service
systemctl restart aegis-daemon.service

echo "Aegis daemon service installed and started."
echo "Daemon:    systemctl status aegis-daemon"
echo "Logs:      journalctl -u aegis-daemon -f"
echo "Desktop UI: python3 ${PROJECT_DIR}/dashboard.py"
