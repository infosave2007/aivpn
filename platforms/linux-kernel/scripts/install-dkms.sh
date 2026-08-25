#!/usr/bin/env bash
# Install aivpn.ko via DKMS. Run as root.
set -euo pipefail

MODNAME="aivpn"
VERSION="${1:-$(cat "$(dirname "$0")/../VERSION" 2>/dev/null || echo "0.1.0")}"
SRC_DIR="$(realpath "$(dirname "$0")/..")"
DEST="/usr/src/${MODNAME}-${VERSION}"

if ! command -v dkms &>/dev/null; then
    echo "ERROR: dkms not found. Install dkms package first." >&2
    exit 1
fi

echo "[aivpn] Installing DKMS source to ${DEST}..."
mkdir -p "${DEST}"
cp -r "${SRC_DIR}/src"      "${DEST}/"
cp -r "${SRC_DIR}/include"  "${DEST}/"
cp    "${SRC_DIR}/Makefile"  "${DEST}/"
cp    "${SRC_DIR}/Kbuild"    "${DEST}/"
sed "s/@VERSION@/${VERSION}/g" "${SRC_DIR}/dkms.conf" > "${DEST}/dkms.conf"

echo "[aivpn] dkms add..."
dkms add    -m "${MODNAME}" -v "${VERSION}"

echo "[aivpn] dkms build..."
dkms build  -m "${MODNAME}" -v "${VERSION}"

echo "[aivpn] dkms install..."
dkms install -m "${MODNAME}" -v "${VERSION}"

echo "[aivpn] Loading module..."
modprobe "${MODNAME}"

echo "[aivpn] Done. /dev/aivpn should now exist."
