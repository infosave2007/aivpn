#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

version="$(awk -F'"' '/^\[workspace\.package\]/{found=1; next} found && /^version = /{print $2; exit}' Cargo.toml)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "FAIL: некорректная версия workspace: $version" >&2
    exit 1
fi

fail=0

expect_contains() {
    local file="$1"
    local value="$2"
    local label="$3"
    if ! grep -Fq -- "$value" "$file"; then
        echo "FAIL: $label не соответствует $version" >&2
        fail=1
    fi
}

expect_contains platforms/android/app/build.gradle 'versionName = workspaceVersion' 'Android versionName'
expect_contains platforms/android/app/build.gradle 'versionCode = workspaceVersionCode' 'Android versionCode'
expect_contains platforms/ios/project.yml "MARKETING_VERSION: \"$version\"" 'iOS marketing version'
expect_contains platforms/ios/App/Info.plist '<string>$(MARKETING_VERSION)</string>' 'iOS app plist'
expect_contains platforms/ios/Tunnel/Info.plist '<string>$(MARKETING_VERSION)</string>' 'iOS tunnel plist'
expect_contains platforms/macos/Info.plist "<string>$version</string>" 'macOS plist'
expect_contains platforms/macos/aivpn-helper/main.swift "let HELPER_VERSION = \"$version\"" 'macOS helper'
expect_contains crates/aivpn-windows/build.rs 'env::var("CARGO_PKG_VERSION")' 'Windows manifest'
expect_contains crates/aivpn-windows/installer/aivpn-installer.nsi '!error "APP_VERSION is required"' 'Windows installer'
expect_contains docker-compose.yml "com.aivpn.version=$version" 'Docker label'
expect_contains platforms/openwrt/package/aivpn/Makefile "PKG_VERSION:=$version" 'OpenWrt package'
expect_contains platforms/openwrt/package/aivpn/Makefile 'PKG_SOURCE_URL:=https://github.com/vaminakov/aivpn.git' 'OpenWrt source URL'
expect_contains .github/workflows/ci.yml 'steps.workspace-version.outputs.version' 'CI artifact'
expect_contains CHANGELOG.md "## [$version]" 'CHANGELOG'
expect_contains "docs/RELEASE_$version.md" "выпуска $version" 'release settings'

openwrt_source="$(awk -F':=' '/^PKG_SOURCE_VERSION:=/{print $2; exit}' platforms/openwrt/package/aivpn/Makefile)"
if [[ ! "$openwrt_source" =~ ^[0-9a-f]{40}$ ]]; then
    echo "FAIL: OpenWrt source не закреплен на коммите" >&2
    fail=1
elif git cat-file -e "$openwrt_source:Cargo.toml" 2>/dev/null; then
    source_version="$(git show "$openwrt_source:Cargo.toml" | awk -F'"' '/^\[workspace\.package\]/{found=1; next} found && /^version = /{print $2; exit}')"
    if [[ "$source_version" != "$version" ]]; then
        echo "FAIL: OpenWrt source содержит версию $source_version вместо $version" >&2
        fail=1
    fi
fi

if (( fail != 0 )); then
    exit 1
fi

echo "PASS: версия выпуска $version согласована"
