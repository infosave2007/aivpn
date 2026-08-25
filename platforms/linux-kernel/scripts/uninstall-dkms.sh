#!/usr/bin/env bash
# Remove aivpn.ko DKMS registration and unload the module. Run as root.
set -euo pipefail

MODNAME="aivpn"
VERSION="${1:-$(dkms status -m aivpn 2>/dev/null | awk -F'[,/]' 'NR==1{print $2}' | tr -d ' ')}"

if [[ -z "${VERSION}" ]]; then
    echo "ERROR: cannot determine installed version. Pass version as argument." >&2
    exit 1
fi

echo "[aivpn] Unloading module..."
modprobe -r "${MODNAME}" 2>/dev/null || true

echo "[aivpn] dkms remove..."
dkms remove -m "${MODNAME}" -v "${VERSION}" --all

echo "[aivpn] Removing source tree..."
rm -rf "/usr/src/${MODNAME}-${VERSION}"

echo "[aivpn] Done."
