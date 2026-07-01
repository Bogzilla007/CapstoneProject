#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="${HOME}/.local/share/applications"
DESKTOP_FILE="${DESKTOP_DIR}/project-aegis.desktop"

mkdir -p "${DESKTOP_DIR}"
sed "s#__PROJECT_DIR__#${PROJECT_DIR}#g" "${PROJECT_DIR}/aegis-dashboard.desktop" > "${DESKTOP_FILE}"
chmod +x "${DESKTOP_FILE}"

echo "Project Aegis desktop launcher installed."
echo "Open it from your app menu, or run:"
echo "python3 ${PROJECT_DIR}/dashboard.py"
