#!/usr/bin/env bash
# Проверяет реальные кадры всех публикуемых масок независимым nDPI.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MASK_DIR="${1:-$REPO/assets/masks}"
NDPI="${NDPI_READER:-$REPO/target/dpi-tools/ndpi/example/ndpiReader}"
MASKPCAP="${MASKPCAP:-$REPO/target/release/examples/maskpcap}"
[ -x "$NDPI" ] || { echo 'mask-gate: build the classifier with deploy/ci/build-dpi-tools.sh' >&2; exit 2; }
if [ ! -x "$MASKPCAP" ]; then
    (cd "$REPO" && cargo build --locked --release -p aivpn-common --features client-upload --example maskpcap)
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
shopt -s nullglob
masks=("$MASK_DIR"/*.json)
[ "${#masks[@]}" -gt 0 ] || { echo 'mask-gate: no masks found' >&2; exit 2; }
for mask in "${masks[@]}"; do
    "$MASKPCAP" "$mask" "$work/wire.pcap"
    "$NDPI" -i "$work/wire.pcap" -d -v 2 > "$work/dpi.txt" 2>&1
    python3 - "$mask" "$work/dpi.txt" <<'PY'
import json, pathlib, re, sys
mask = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected = {'WebRTC_STUN': 'STUN', 'QUIC': 'QUIC', 'HTTPS_H2': 'TLS', 'DNS_over_UDP': 'DNS'}.get(mask['spoof_protocol'])
flows = [line for line in pathlib.Path(sys.argv[2]).read_text().splitlines() if '[proto:' in line]
passed = expected and flows and all(
    '[Confidence: DPI]' in line and any(expected in value.split('.') for value in re.findall(r'\[proto: [0-9.]+/([^\]]+)\]', line))
    for line in flows)
print(f"mask-gate: {mask['mask_id']}: {'PASS' if passed else 'REJECT'} expected={expected}")
if not passed:
    print('\n'.join(flows), file=sys.stderr)
    sys.exit(1)
PY
done
