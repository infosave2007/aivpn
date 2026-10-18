"""Проверяет выбор бинарника для стандартного и перемещенного приложения."""
import pathlib
import subprocess
import tempfile

repo = pathlib.Path(__file__).resolve().parents[2]
policy = repo / "platforms/macos/ClientBinaryPolicy.swift"
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    test = root / "main.swift"
    test.write_text('''import Foundation
for bundle in ["/Applications/Aivpn.app", "/Applications/AIVPN.app"] {
    let selected = ClientBinaryPolicy.bundledPath(bundlePath: bundle, isExecutable: { _ in true })
    assert(selected == bundle + "/Contents/Resources/aivpn-client")
    assert(ClientBinaryPolicy.allowedPaths.contains(selected!))
    let macOSOnly = ClientBinaryPolicy.bundledPath(bundlePath: bundle, isExecutable: { $0.contains("/MacOS/") })
    assert(macOSOnly == bundle + "/Contents/MacOS/aivpn-client")
    assert(ClientBinaryPolicy.bundledPath(bundlePath: bundle, isExecutable: { _ in false }) == nil)
}
for bundle in ["/Applications/VPN/Aivpn.app", "/Applications/Aivpn 1.2.0.app", "/Volumes/AIVPN/Aivpn.app", "/Library/Aivpn.app", "/Users/user/Downloads/Aivpn.app"] {
    assert(ClientBinaryPolicy.bundledPath(bundlePath: bundle, isExecutable: { _ in true }) == nil)
}
assert(ClientBinaryPolicy.allowedPaths.contains(ClientBinaryPolicy.defaultPath))
print("macOS client path checks passed")
''')
    binary = root / "check"
    subprocess.run(["swiftc", str(policy), str(test), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
