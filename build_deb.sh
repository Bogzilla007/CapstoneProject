#!/usr/bin/env bash
set -euo pipefail

PACKAGE_NAME="project-aegis"
VERSION="${VERSION:-0.1.0}"
ARCH="${ARCH:-all}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
BUILD_DIR="${DIST_DIR}/deb"
PKG_DIR="${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}"
APP_DIR="${PKG_DIR}/opt/project-aegis"

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required tool: $1" >&2
    exit 1
  fi
}

require_tool dpkg-deb
require_tool rsync

case "${PKG_DIR}" in
  "${ROOT_DIR}"/dist/deb/*) ;;
  *)
    echo "Refusing to build outside ${ROOT_DIR}/dist/deb" >&2
    exit 1
    ;;
esac

rm -rf "${PKG_DIR}"
mkdir -p \
  "${APP_DIR}" \
  "${PKG_DIR}/DEBIAN" \
  "${PKG_DIR}/etc/project-aegis" \
  "${PKG_DIR}/etc/systemd/system" \
  "${PKG_DIR}/usr/bin" \
  "${PKG_DIR}/usr/share/applications" \
  "${PKG_DIR}/usr/share/doc/project-aegis" \
  "${PKG_DIR}/var/lib/project-aegis/ml_data/model" \
  "${PKG_DIR}/var/lib/project-aegis/reports"

rsync -a \
  --exclude ".git/" \
  --exclude "__pycache__/" \
  --exclude "*.pyc" \
  --exclude ".env" \
  --exclude "config.py" \
  --exclude "reports/" \
  --exclude "dist/" \
  --exclude "packaging/" \
  "${ROOT_DIR}/" "${APP_DIR}/"

if [ -d "${ROOT_DIR}/ml_data" ]; then
  rsync -a "${ROOT_DIR}/ml_data/" "${PKG_DIR}/var/lib/project-aegis/ml_data/"
fi

ln -s /etc/project-aegis/config.py "${APP_DIR}/config.py"
install -m 0644 "${ROOT_DIR}/packaging/config.py" "${PKG_DIR}/etc/project-aegis/config.py"
install -m 0644 "${ROOT_DIR}/packaging/project-aegis.service" "${PKG_DIR}/etc/systemd/system/aegis-daemon.service"
install -m 0644 "${ROOT_DIR}/packaging/project-aegis.desktop" "${PKG_DIR}/usr/share/applications/project-aegis.desktop"
install -m 0755 "${ROOT_DIR}/packaging/wrappers/aegis-daemon" "${PKG_DIR}/usr/bin/aegis-daemon"
install -m 0755 "${ROOT_DIR}/packaging/wrappers/aegis-dashboard" "${PKG_DIR}/usr/bin/aegis-dashboard"
install -m 0755 "${ROOT_DIR}/packaging/wrappers/aegis-collect-baseline" "${PKG_DIR}/usr/bin/aegis-collect-baseline"
install -m 0755 "${ROOT_DIR}/packaging/wrappers/aegis-train-model" "${PKG_DIR}/usr/bin/aegis-train-model"
install -m 0644 "${ROOT_DIR}/README.md" "${PKG_DIR}/usr/share/doc/project-aegis/README.md"
install -m 0644 "${ROOT_DIR}/INSTALLATION.md" "${PKG_DIR}/usr/share/doc/project-aegis/INSTALLATION.md"
install -m 0644 "${ROOT_DIR}/PACKAGING.md" "${PKG_DIR}/usr/share/doc/project-aegis/PACKAGING.md"
install -m 0644 "${ROOT_DIR}/requirements.txt" "${PKG_DIR}/usr/share/doc/project-aegis/requirements.txt"

sed \
  -e "s/@VERSION@/${VERSION}/g" \
  -e "s/@ARCH@/${ARCH}/g" \
  "${ROOT_DIR}/packaging/debian/control" > "${PKG_DIR}/DEBIAN/control"
install -m 0644 "${ROOT_DIR}/packaging/debian/conffiles" "${PKG_DIR}/DEBIAN/conffiles"
install -m 0755 "${ROOT_DIR}/packaging/debian/postinst" "${PKG_DIR}/DEBIAN/postinst"
install -m 0755 "${ROOT_DIR}/packaging/debian/prerm" "${PKG_DIR}/DEBIAN/prerm"
install -m 0755 "${ROOT_DIR}/packaging/debian/postrm" "${PKG_DIR}/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "${PKG_DIR}" "${DIST_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
echo "Built ${DIST_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
