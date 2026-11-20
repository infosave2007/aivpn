#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
ios_root="$repo_root/platforms/ios"
build_root="$ios_root/build/ios15"
archive="$build_root/Aivpn.xcarchive"
output="$repo_root/releases/aivpn-ios15.ipa"

if [[ "$(uname -s)" != Darwin ]]; then
    echo 'This build requires macOS with Xcode.' >&2
    exit 1
fi

for tool in cargo xcodebuild xcodegen; do
    command -v "$tool" >/dev/null || { echo "Missing build tool: $tool" >&2; exit 1; }
done

export IPHONEOS_DEPLOYMENT_TARGET=15.0
if [[ "${1:-}" != --package-only ]]; then
cd "$repo_root"
cargo build --locked --release --target aarch64-apple-ios -p aivpn-ios-core
mkdir -p crates/aivpn-ios-core/lib "$build_root" releases
cp target/aarch64-apple-ios/release/libaivpn_core.a crates/aivpn-ios-core/lib/

cd "$ios_root"
xcodegen generate --spec project.yml
xcodebuild archive -quiet \
    -project Aivpn.xcodeproj -scheme Aivpn -configuration Release \
    -destination 'generic/platform=iOS' -archivePath "$archive" \
    IPHONEOS_DEPLOYMENT_TARGET=15.0 \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
    SKIP_INSTALL=NO BUILD_LIBRARY_FOR_DISTRIBUTION=NO
fi

app="$archive/Products/Applications/Aivpn.app"
extension="$app/PlugIns/AivpnTunnel.appex"
# Ad-hoc signing does not add Xcode's usual identity entitlements. TrollStore
# preserves an existing dictionary, so supply explicit IDs for VPN ownership.
python3 - "$ios_root" "$build_root" <<'PY'
import pathlib, plistlib, sys
source, destination = map(pathlib.Path, sys.argv[1:])
for relative, bundle, output in (
    ('App/Aivpn.entitlements', 'com.aivpn.client', 'app.entitlements'),
    ('Tunnel/AivpnTunnel.entitlements', 'com.aivpn.client.tunnel', 'tunnel.entitlements'),
):
    entitlements = plistlib.loads((source / relative).read_bytes())
    entitlements['application-identifier'] = 'TROLLTROLL.' + bundle
    entitlements['com.apple.developer.team-identifier'] = 'TROLLTROLL'
    (destination / output).write_bytes(plistlib.dumps(entitlements))
PY
codesign --force --sign - --entitlements "$build_root/tunnel.entitlements" "$extension"
codesign --force --sign - --entitlements "$build_root/app.entitlements" "$app"
codesign --verify --deep --strict "$app"

python3 - "$app" "$extension" "$repo_root/Cargo.toml" <<'PY'
import pathlib, plistlib, re, subprocess, sys
*bundles, manifest = sys.argv[1:]
versions = re.findall(r'^version\s*=\s*"([^"]+)"', pathlib.Path(manifest).read_text(), re.MULTILINE)
assert len(versions) == 1, 'Cannot determine workspace version'
for name in bundles:
    path = pathlib.Path(name)
    info = plistlib.loads((path / 'Info.plist').read_bytes())
    assert info['MinimumOSVersion'] == '15.0', (path, info['MinimumOSVersion'])
    assert info['CFBundleShortVersionString'] == versions[0], info
    entitlements = plistlib.loads(subprocess.check_output(
        ['codesign', '-d', '--entitlements', ':-', str(path)], stderr=subprocess.DEVNULL))
    assert entitlements.get('application-identifier') == 'TROLLTROLL.' + info['CFBundleIdentifier']
    assert entitlements.get('com.apple.developer.team-identifier') == 'TROLLTROLL'
    assert 'packet-tunnel-provider' in entitlements.get(
        'com.apple.developer.networking.networkextension', []), (path, entitlements)
    for key in ('com.apple.security.application-groups', 'keychain-access-groups'):
        assert 'group.com.aivpn.client' in entitlements.get(key, []), (path, key)
    print(info['CFBundleIdentifier'], 'minimum iOS', info['MinimumOSVersion'])
    print('Verified signed Network Extension, App Group and Keychain entitlements')
PY

stage="$(mktemp -d "$build_root/package.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/Payload"
ditto "$app" "$stage/Payload/Aivpn.app"
rm -f "$output"
(cd "$stage" && zip -qr "$output" Payload)
cd "$(dirname "$output")"
shasum -a 256 "$(basename "$output")" > "$(basename "$output").sha256"
echo "Built $output"
