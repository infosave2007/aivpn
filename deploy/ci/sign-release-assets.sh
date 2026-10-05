#!/usr/bin/env bash
# Подписывает артефакты ключом выпуска Ed25519 и проверяет доверенный открытый ключ.
set -euo pipefail
: "${RELEASE_SIGNING_KEY_PEM:?RELEASE_SIGNING_KEY_PEM is required}"
: "${RELEASE_PUBLIC_KEY:?RELEASE_PUBLIC_KEY is required}"
[ "$#" -gt 0 ] || { echo 'No release assets supplied' >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
umask 077
printf '%s\n' "$RELEASE_SIGNING_KEY_PEM" > "$work/key.pem"
printf '%s' "$RELEASE_PUBLIC_KEY" | base64 -d > "$work/public.der"
openssl pkey -in "$work/key.pem" -pubout -outform DER -out "$work/derived.der" 2>/dev/null
cmp -s "$work/public.der" "$work/derived.der" || { echo 'Release public key mismatch' >&2; exit 1; }
for asset in "$@"; do
    [ -f "$asset" ] || { echo 'Release asset is not a regular file' >&2; exit 1; }
    openssl pkeyutl -sign -rawin -inkey "$work/key.pem" -in "$asset" -out "$asset.sig"
    openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey "$work/public.der" \
        -in "$asset" -sigfile "$asset.sig" >/dev/null
 done
