#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo 'Укажите путь для wintun.dll' >&2; exit 2; }
target=$1
scratch=$(mktemp -d "${TMPDIR:-/tmp}/aivpn-wintun.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

# Хеш опубликован на https://www.wintun.net/ для версии 0.14.1.
curl --fail --silent --show-error --location --connect-timeout 15 --max-time 120 \
    https://www.wintun.net/builds/wintun-0.14.1.zip -o "$scratch/wintun.zip"
printf '%s  %s\n' 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51 \
    "$scratch/wintun.zip" | sha256sum --check --status
unzip -p "$scratch/wintun.zip" wintun/bin/amd64/wintun.dll > "$scratch/wintun.dll"
test -s "$scratch/wintun.dll"
install -m 644 "$scratch/wintun.dll" "$target"
