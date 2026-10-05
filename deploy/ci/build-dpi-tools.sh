#!/usr/bin/env bash
# Собирает зафиксированную версию независимого классификатора для CI.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NDPI_REVISION="375f99ef9fb4999d778b57bbeece171b3fa9fba6"
NDPI_DIR="${AIVPN_NDPI_DIR:-$REPO/target/dpi-tools/ndpi}"
if [ ! -d "$NDPI_DIR/.git" ]; then
    mkdir -p "$NDPI_DIR"
    git -C "$NDPI_DIR" init -q
    git -C "$NDPI_DIR" remote add origin https://github.com/ntop/nDPI.git
fi
if [ "$(git -C "$NDPI_DIR" rev-parse HEAD 2>/dev/null || true)" != "$NDPI_REVISION" ]; then
    git -C "$NDPI_DIR" fetch --depth 1 origin "$NDPI_REVISION"
    git -C "$NDPI_DIR" checkout --detach "$NDPI_REVISION"
fi
(cd "$NDPI_DIR" && ./autogen.sh && ./configure && make -j"${BUILD_JOBS:-2}")
