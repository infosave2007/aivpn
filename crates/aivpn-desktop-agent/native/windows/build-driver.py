#!/usr/bin/env python3
"""Сборка x64-драйвера Clang/LLD с установленными SDK и WDK. Подпись выполняется отдельно."""

import argparse
import json
from pathlib import Path
import subprocess


def virtual_directory(path):
    contents = []
    for item in sorted(path.iterdir()):
        if item.is_dir():
            entry = virtual_directory(item)
            entry["name"] = item.name
        else:
            entry = {"type": "file", "name": item.name, "external-contents": str(item)}
        contents.append(entry)
    return {"type": "directory", "name": str(path), "contents": contents}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-include", required=True, type=Path)
    parser.add_argument("--wdk-include", required=True, type=Path)
    parser.add_argument("--wdk-lib", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--lab", action="store_true", help="Счетчики только лабораторной сборки")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sdk, wdk, lib = (p.resolve() for p in (args.sdk_include, args.wdk_include, args.wdk_lib))
    for required in (sdk / "shared", wdk / "km", lib / "ntoskrnl.lib", lib / "fltMgr.lib"):
        if not required.exists():
            parser.error(f"Не найден {required}")
    overlay = output / "headers-vfs.json"
    overlay.write_text(json.dumps({"version": 0, "case-sensitive": False,
        "use-external-names": False, "roots": [virtual_directory(sdk), virtual_directory(wdk)]}))
    command = ["clang-cl", "--target=x86_64-pc-windows-msvc", "/c", "/kernel", "/W4", "/WX",
        "/O2", "/GS", "/Zl", "/std:c17", "/D_KERNEL_MODE", "/DNDIS630=1", "/D_AMD64_", "/D_WIN64",
        "/D_WIN32_WINNT=0x0A00", "/DNTDDI_VERSION=0x0A000008", "/clang:-ivfsoverlay", "/clang:" + str(overlay)]
    if args.lab:
        command.append("/DAIVPN_LAB=1")
    for include in (wdk / "km", wdk / "km/crt", sdk / "shared", sdk / "ucrt", sdk / "um"):
        command.extend(["/imsvc", str(include)])
    command.extend([str(source / "driver.c"), "/Fo" + str(output / "driver.obj")])
    subprocess.run(command, check=True)
    command = ["lld-link", "/dll", "/driver", "/subsystem:native", "/entry:GsDriverEntry",
        "/nodefaultlib", "/machine:x64", "/integritycheck", "/NXCOMPAT", "/DYNAMICBASE",
        "/out:" + str(output / "aivpn-app-routing.sys"), str(output / "driver.obj")]
    command.extend(str(lib / name) for name in ("ntoskrnl.lib", "fltMgr.lib", "fwpkclnt.lib", "ndis.lib", "wdmsec.lib", "BufferOverflowK.lib"))
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
