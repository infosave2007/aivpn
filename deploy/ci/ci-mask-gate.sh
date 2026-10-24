#!/usr/bin/env bash
# PFS, потери и внешние кадры проверяются живым клиентом и шлюзом.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MASK_DIR="${1:-$REPO/assets/masks}"
NDPI="${NDPI_READER:-$REPO/target/dpi-tools/ndpi/example/ndpiReader}"
[ -x "$NDPI" ] || { echo 'mask-gate: build the classifier with deploy/ci/build-dpi-tools.sh' >&2; exit 2; }
command -v tshark >/dev/null || { echo 'mask-gate: требуется tshark' >&2; exit 2; }
[ "$(realpath "$MASK_DIR")" = "$(realpath "$REPO/assets/masks")" ] || {
    echo 'mask-gate: живой прогон проверяет встроенный каталог assets/masks' >&2; exit 2;
}
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
(
    cd "$REPO"
    AIVPN_HANDSHAKE_PCAP_DIR="$work" cargo test --locked -p aivpn-server --lib handshake_loss_tests
)
python3 "$REPO/deploy/ci/check-mask-pcaps.py" "$MASK_DIR" "$work" "$NDPI"
