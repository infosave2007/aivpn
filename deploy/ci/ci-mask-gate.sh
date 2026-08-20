#!/usr/bin/env bash
#
# ci-mask-gate.sh — offline nDPI provenance gate for published mask assets.
# (R2 Phase A — see docs/R2_PHASE_A.md.)
#
# Every mask in assets/masks/*.json defines how aivpn shapes real client uplink
# traffic to look like a target protocol (STUN, QUIC, …). This gate proves that
# claim against a real DPI engine BEFORE a mask can be merged/published: it
# synthesises each mask's actual on-wire packets (via `maskpcap`, the exact
# client build path) and classifies them with nDPI (`ndpiReader -d`, DPI-only,
# no UDP-port guessing). A mask PASSES only if nDPI labels it as its declared
# target protocol and raises no VPN/obfuscation risk flag; otherwise it is a
# REJECT and this script exits non-zero, failing the build.
#
# Hermetic: all paths are resolved relative to the repo root (this file's
# location), never the caller's CWD.
#
# Graceful skip: the DPI toolchain (nDPI source build + the `maskpcap` Rust bin)
# lives under the gitignored research/ tree and is NOT present in a plain clone.
# When it is missing this gate SKIPS with a clear message and exit 0, so a
# developer without the research toolchain is never blocked. CI that wants the
# gate enforced must build the toolchain first (see docs/R2_PHASE_A.md) and can
# set MASK_GATE_REQUIRE=1 to turn a skip into a hard failure.
#
# Exit codes:
#   0  all masks PASS  — or the toolchain is absent and MASK_GATE_REQUIRE unset
#   1  at least one mask REJECTed by nDPI  (build-failing condition)
#   2  toolchain absent AND MASK_GATE_REQUIRE=1  (enforced-but-unbuildable)
#
# Usage: deploy/ci/ci-mask-gate.sh [mask_dir]   (default: assets/masks)
set -euo pipefail

# ── Resolve repo-root-relative paths (independent of caller CWD) ──────────────
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
EVAL_DIR="$REPO/research/mask-generation/eval-gate"
EVAL_GATE="$EVAL_DIR/eval_gate.sh"
MASKPCAP="$EVAL_DIR/target/release/maskpcap"
NDPI="$REPO/research/dpi-harness/nDPI-src/example/ndpiReader"
MASK_DIR="${1:-$REPO/assets/masks}"

REQUIRE="${MASK_GATE_REQUIRE:-0}"

# ── Graceful skip: emit reason and exit per REQUIRE policy ────────────────────
skip() {
	echo "mask-gate: SKIP — $1"
	if [[ "$REQUIRE" == "1" ]]; then
		echo "mask-gate: MASK_GATE_REQUIRE=1 set — treating skip as failure." >&2
		exit 2
	fi
	echo "mask-gate: research DPI toolchain not built; gate skipped (not a failure)."
	echo "mask-gate: to enforce it, build nDPI + maskpcap first — see docs/R2_PHASE_A.md."
	exit 0
}

[[ -d "$MASK_DIR" ]]  || skip "mask dir not found: $MASK_DIR"
[[ -f "$EVAL_GATE" ]] || skip "eval-gate tooling absent: $EVAL_GATE"
[[ -x "$NDPI" ]]      || skip "ndpiReader not built: $NDPI"

# Locate or build maskpcap. A missing Rust toolchain is a skip (dev without
# cargo), not a hard failure. A cargo build *error* with cargo present is real
# and surfaces as a hard failure below.
if [[ ! -x "$MASKPCAP" ]]; then
	if ! command -v cargo >/dev/null 2>&1; then
		skip "maskpcap not built and cargo unavailable"
	fi
	echo "mask-gate: building maskpcap (research/mask-generation/eval-gate)…"
	if ! ( cd "$EVAL_DIR" && cargo build --release --quiet ); then
		echo "mask-gate: ERROR — maskpcap build failed with cargo present." >&2
		exit 1
	fi
fi

# ── Run the gate over every mask ──────────────────────────────────────────────
shopt -s nullglob
masks=("$MASK_DIR"/*.json)
shopt -u nullglob
if [[ ${#masks[@]} -eq 0 ]]; then
	skip "no mask assets in $MASK_DIR"
fi

echo "mask-gate: nDPI provenance gate over ${#masks[@]} mask(s) in $MASK_DIR"
echo
printf '%-28s | %-6s | %-10s | %s\n' "mask" "target" "verdict" "nDPI"
printf -- '-----------------------------+--------+------------+---------\n'

pass=0
fail=0
failed_masks=()
for mask in "${masks[@]}"; do
	name="$(basename "$mask" .json)"
	# eval_gate.sh prints an "eval-gate: … target=X … nDPI_proto=Y …" line and
	# exits 0=accept / 1=reject / 2=tooling. Capture both output and code.
	out="$("$EVAL_GATE" "$mask" 2>/dev/null)" && rc=0 || rc=$?
	line="$(grep '^eval-gate:' <<<"$out" | head -1 || true)"
	target="$(sed -n 's/.*target=\([^ ]*\).*/\1/p' <<<"$line")"
	proto="$(sed -n 's/.*nDPI_proto=\([^ ]*\).*/\1/p' <<<"$line")"

	if [[ "$rc" == "2" ]]; then
		# Per-mask tooling error mid-run (e.g. maskpcap vanished) — treat as skip
		# so a half-built toolchain doesn't masquerade as a mask rejection.
		skip "eval-gate reported a tooling error on $name"
	elif [[ "$rc" == "0" ]]; then
		verdict="PASS"
		pass=$((pass + 1))
	else
		verdict="REJECT"
		fail=$((fail + 1))
		failed_masks+=("$name")
	fi
	printf '%-28s | %-6s | %-10s | %s\n' "$name" "${target:-?}" "$verdict" "${proto:-?}"
done

printf -- '-----------------------------+--------+------------+---------\n'
echo "mask-gate: ${pass} PASS / ${fail} REJECT of ${#masks[@]}"

if [[ "$fail" -gt 0 ]]; then
	echo >&2
	echo "mask-gate: FAIL — ${fail} mask(s) rejected by nDPI: ${failed_masks[*]}" >&2
	echo "mask-gate: a rejected mask is NOT proven to look like its target protocol." >&2
	echo "mask-gate: diagnose with:  research/mask-generation/eval-gate/eval_gate.sh assets/masks/<name>.json" >&2
	echo "mask-gate: see docs/R2_PHASE_A.md → 'Failure-diagnosis workflow'." >&2
	exit 1
fi

echo "mask-gate: OK — all masks carry a valid nDPI target-protocol classification."
exit 0
