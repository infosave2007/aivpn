"""Проверяет функцию открытия сертификата из исходника macOS helper."""
import os
import pathlib
import subprocess
import tempfile

repo = pathlib.Path(__file__).resolve().parents[2]
source = (repo / "platforms/macos/aivpn-helper/main.swift").read_text()
start = source.index("func openCertificate(")
function = source[start:source.index("\n}\n", start) + 3]
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory).resolve()
    native = root / "check.swift"
    native.write_text("""import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
""" + function + """
let fd = openCertificate(CommandLine.arguments[1])
let expected = CommandLine.arguments[2] == "valid"
if (fd >= 0) != expected { exit(1) }
if fd >= 0 { close(fd) }
""")
    binary = root / "check"
    subprocess.run(["swiftc", str(native), "-o", str(binary)], check=True)
    valid = root / "cert.bin"
    valid.write_bytes(b"certificate")
    empty = root / "empty"
    empty.touch()
    huge = root / "huge"
    huge.write_bytes(b"x" * 4097)
    symlink = root / "symlink"
    symlink.symlink_to(valid)
    directory_link = root / "directory-link"
    directory_link.symlink_to(root, target_is_directory=True)
    fifo = root / "fifo"
    os.mkfifo(fifo)
    cases = [(valid, True), (empty, False), (huge, False), (symlink, False),
             (directory_link / "cert.bin", False), (fifo, False), (root / "absent", False)]
    for path, expected in cases:
        subprocess.run([str(binary), str(path), "valid" if expected else "invalid"], check=True, timeout=5)
    print(f"Certificate checks: {len(cases)} passed")
