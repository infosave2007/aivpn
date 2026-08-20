#!/usr/bin/env bash
#
# ci-selfcontained.sh — the public tree must build on its own.
#
# Cargo resolves EVERY declared dependency, including optional ones that are
# switched off, because it needs the name and version from their manifest. A
# path dependency pointing outside this repository is therefore not a
# "disabled option" — it is a hard parse error for anyone who merely cloned
# the repository:
#
#   error: failed to get `x` as a dependency of package `y`
#   Caused by: failed to read `../x/Cargo.toml`
#   Caused by: No such file or directory (os error 2)
#
# This gate catches exactly that, plus a build and test run with no extra
# feature enabled. It exists because the failure it prevents is invisible to
# whoever introduces it: their working copy has the sibling directory.
#
# Exit 0 = self-contained, exit 1 = something reaches outside the tree.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

echo "── self-contained public tree ──────────────────────────────────────────"
echo "root: $REPO_ROOT"

fail=0

# ── 1. No manifest may reference a path outside the tree ─────────────────────
while IFS= read -r manifest; do
    manifest_dir="$(cd "$(dirname "$manifest")" && pwd)"
    while IFS= read -r line; do
        # Only `path = "..."` entries; `paths` keys and prose are not matched
        # because the pattern anchors on the whole assignment.
        dep_path="$(sed -E 's/.*[^a-z_]path *= *"([^"]+)".*/\1/' <<<"$line")"
        [ "$dep_path" = "$line" ] && continue
        resolved="$(cd "$manifest_dir" && realpath -m -- "$dep_path" 2>/dev/null)"
        case "$resolved" in
            "$REPO_ROOT"|"$REPO_ROOT"/*) ;;
            *)
                echo "FAIL: ${manifest#"$REPO_ROOT"/} points outside the tree: $dep_path"
                fail=1
                ;;
        esac
    done < <(grep -E '(^|[^a-z_])path *= *"[^"]*"' "$manifest" || true)
done < <(find . -name Cargo.toml -not -path './target/*' -not -path './.git/*')

if [ "$fail" -eq 0 ]; then
    echo "  manifests: no path escapes the repository"
fi

# ── 2. Build and test with no extra feature ──────────────────────────────────
echo "  building the workspace with default features…"
cargo build --workspace --quiet || fail=1
echo "  testing the workspace with default features…"
cargo test --workspace --quiet || fail=1

if [ "$fail" -eq 0 ]; then
    echo "PASS — the public tree builds and tests on its own."
    exit 0
fi

echo "FAIL — the public tree does not build on its own."
exit 1
