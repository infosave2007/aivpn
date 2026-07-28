#!/usr/bin/env bash
# Syntax gate for the Apple (iOS/macOS) sources, runnable on Linux.
#
# WHY THIS EXISTS
# The Apple targets can only be BUILT on macOS with Xcode, so edits to
# platforms/ios and platforms/macos have historically gone in unverified —
# a truncated or malformed edit was only discovered on the operator's Mac.
#
# `swiftc -parse` runs the parser alone and never resolves imports, so the
# absence of SwiftUI/UIKit/Security/NetworkExtension on a Linux host does not
# matter. It catches exactly the class of defect that unverified editing
# produces: unbalanced braces, truncated hunks, malformed declarations.
#
# WHAT IT DOES NOT CATCH: type errors, missing or misspelled symbols, wrong API
# shapes. A green run here is not a substitute for a real Apple build.
#
# Gracefully SKIPS (exit 0) when no Swift toolchain is installed, so nobody is
# blocked by it. Install one with your distro's `swift` package to enable it.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

if ! command -v swiftc >/dev/null 2>&1; then
    echo "swift-parse: SKIP — no Swift toolchain (install 'swift' to enable)"
    exit 0
fi

echo "swift-parse: $(swiftc --version 2>&1 | head -1)"

fail=0
total=0
failed=()

while IFS= read -r f; do
    total=$((total + 1))
    if ! out=$(swiftc -parse "$f" 2>&1); then
        fail=$((fail + 1))
        failed+=("$f")
        echo "── PARSE FAILED: $f"
        echo "$out" | grep -E "error:" | head -10
    fi
done < <(find platforms/ios platforms/macos -name '*.swift' -type f | sort)

echo "swift-parse: $total file(s), $fail failure(s)"
if [ "$fail" -gt 0 ]; then
    printf 'failing:\n'
    printf '  %s\n' "${failed[@]}"
    exit 1
fi
