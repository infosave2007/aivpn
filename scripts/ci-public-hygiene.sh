#!/usr/bin/env bash
#
# ci-public-hygiene.sh — vocabulary gate for the publicly distributed tree.
#
# The codebase carries a pluggable seam (the datagram-transport registry) whose
# alternative implementations are not part of this repository. The seam itself
# is meant to be unremarkable: a transport is registered, datagrams go through
# it. What must NOT appear in the public tree is vocabulary that describes a
# specific out-of-tree implementation — the third-party services it speaks to,
# or wording that frames it as anything more than "another datagram transport".
#
# One comment, feature name, log line or translation string is enough to undo
# the separation, and those slip in during ordinary work: a helpful doc-comment
# ("planned: X"), a debug log, a UI label. Review does not catch them
# reliably — hence a build gate.
#
# Hermetic: paths resolve relative to the repo root (this file's location),
# never the caller's CWD.
#
# Exit 0 = clean, exit 1 = a forbidden term is present.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

# ── Vocabulary ───────────────────────────────────────────────────────────────
# Only terms with NO legitimate use anywhere in this tree. See the rejected
# list below — that part matters as much as this one.
PATTERNS=(
  # Third-party service and vendor names.
  '\blivekit\b'
  '\bgoolom\b'
  'телемост'
  '\bsalutejazz\b'
  '\bsfu\b'
  # Compound that only exists in this context.
  '\bwhitelist-carrier\b'
)

# ── Deliberately NOT banned, so nobody "helpfully" adds them back ────────────
#
#   webrtc, stun, rtp, srtp, sdp, ice, vp8, quic
#     These belong to the traffic-mimicry subsystem, which is a published
#     feature of this product: masks shape client traffic to look like those
#     protocols (`SpoofProtocol::WebRTC_STUN`, `assets/masks/*.json`, the nDPI
#     provenance gate in ci-mask-gate.sh). Banning them flags several hundred
#     legitimate lines, and a gate that cannot be held at zero gets switched
#     off within a week. Their presence says "this VPN imitates WebRTC", which
#     is documented product behaviour — not "this VPN rides on someone's
#     conferencing service".
#
#   telemost (латиницей)
#     Имя МАСКИ трафика, а не сервиса-несущей: `webrtc_yandex_telemost_v1`,
#     `MaskOption::WebrtcYandexTelemostV1`, подпись «Yandex Telemost» в трёх
#     GUI (Linux, iOS, macOS). Мимикрия под Телемост — опубликованная функция
#     продукта, ровно как webrtc/stun/quic выше: она говорит «этот VPN
#     ИМИТИРУЕТ Телемост», а не «этот VPN ЕЗДИТ через Телемост». Забанить его
#     значит держать гейт красным на чистом дереве (проверено: 5 совпадений),
#     а гейт, который нельзя удержать на нуле, отключают через неделю.
#
#     Кириллическое «телемост» забанено и остаётся: в публичном дереве оно не
#     встречается ни разу, а закрытая сторона пишет свои подписи по-русски.
#     Это и есть разделяющий признак между двумя смыслами одного слова.
#
#   turn, room, ice
#     Ordinary English; word boundaries do not save them ("in turn", "device").
#
#   jazz
#     Matches unrelated dependency names. Covered by 'salutejazz'.
#
#   carrier / несущ* (the concept, in either language)
#     Both were tried and both failed on real content. English 'carrier' is
#     used throughout for mobile network operators ("port-preserving CGNAT
#     carriers"). Russian 'несущ*' is worse, not better: "реконнект при смене
#     несущей" is the same mobile-operator sense, and "масок, несущих
#     resonance-тег" is just the verb. Only the compound 'whitelist-carrier'
#     survives as unambiguous.
#
# WHAT THIS GATE DOES AND DOES NOT CATCH — read before trusting it.
#   Catches: names. A third-party service named in code, a comment, a feature
#   name, a log line or a translation. That is the highest-value leak class,
#   because a name is instantly searchable and identifies the design outright.
#   Does NOT catch: wording. A comment that describes the mechanism without
#   naming anyone ("tunnel this through a conferencing service") passes clean.
#   No word list can catch that without also flagging hundreds of legitimate
#   lines, at which point the gate gets disabled and protects nothing. Prose
#   review still matters; this gate exists so that review never has to be the
#   only thing standing between a stray name and a public release.

# ── What counts as the public tree ───────────────────────────────────────────
#
# Everything except build output and internal notes. There used to be
# exclusions here for the closed crates; they are gone because those crates are
# gone — the closed side lives in its own repository now, and a list naming it
# would itself be the kind of hint this gate exists to prevent. If a directory
# ever needs excluding again, that is a signal the separation slipped.

EXCLUDE_DIRS=(
  '.git'
  'target'
  'node_modules'
  # Already excluded from distribution by .gitignore.
  'docs'
  'research'
  # Generated web output: re-embeds every source and dependency string.
  '.svelte-kit'
  'build'
  'dist'
)

# Files whose contents we do not author. Kept as an explicit list rather than
# by loosening the patterns: each entry is a decision someone can review.
# The gate's own source necessarily contains every banned term.
ALLOWLIST_REGEX='(^|/)(Cargo\.lock|package-lock\.json|bun\.lock|yarn\.lock|ci-public-hygiene\.sh)$'

exclude_args=()
for d in "${EXCLUDE_DIRS[@]}"; do
  exclude_args+=(--exclude-dir="$d")
done

echo "── public-tree vocabulary gate ─────────────────────────────────────────"
echo "root: $REPO_ROOT"

hits_file="$(mktemp)"
trap 'rm -f "$hits_file"' EXIT

for pat in "${PATTERNS[@]}"; do
  # -I skips binaries, -o keeps the report to the matched term (a minified
  # bundle on one line would otherwise dump megabytes into CI output).
  grep -rIonEi "${exclude_args[@]}" -- "$pat" . 2>/dev/null |
    while IFS= read -r hit; do
      file="${hit#./}"
      file="${file%%:*}"
      [[ "$file" =~ $ALLOWLIST_REGEX ]] && continue
      printf '%s\n' "${hit#./}"
    done >>"$hits_file"
done

violations=$(wc -l <"$hits_file" | tr -d ' ')

if [ "$violations" -eq 0 ]; then
  echo "PASS — no forbidden vocabulary in the public tree."
  exit 0
fi

echo "FAIL — $violations occurrence(s) of forbidden vocabulary:"
echo ""
head -n 50 "$hits_file" | sed 's/^/  /'
[ "$violations" -gt 50 ] && echo "  … and $((violations - 50)) more"
echo ""
echo "These terms describe a specific out-of-tree implementation and must not"
echo "appear in the published tree — not in code, comments, feature names, log"
echo "messages, translations or manifests. Rephrase in terms of the seam itself"
echo "(a datagram transport being registered and used), or move the text into"
echo "the component that is not published."
exit 1
