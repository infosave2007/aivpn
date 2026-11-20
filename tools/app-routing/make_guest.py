#!/usr/bin/env python3
"""Собирает отдельный офлайн-стенд из установленного ядра и локальных утилит."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sysconfig


def run(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def copy_file(source, root):
    source = Path(source)
    target = root / source.relative_to("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.chmod(target.stat().st_mode | 0o200)
    shutil.copyfile(source, target, follow_symlinks=True)
    target.chmod(source.stat().st_mode & 0o777)


def copy_program(source, root):
    copy_file(source, root)
    try:
        dependencies = run(["ldd", str(source)])
    except subprocess.CalledProcessError as error:
        if "not a dynamic executable" in error.output or "statically linked" in error.output:
            return
        raise
    for dependency in re.findall(r"(?:=>\s+)?(/[\w/+.@-]+)", dependencies):
        copy_file(dependency, root)


def link(target, source):
    if source.is_symlink() and os.readlink(source) == target:
        return
    source.symlink_to(target)


def copy_runtime(root):
    for program in ["/usr/lib/initcpio/busybox", "/usr/bin/ip", "/usr/bin/nft", "/usr/bin/modprobe", "/usr/bin/unshare", "/usr/bin/mount",
                    "/usr/bin/dbus-daemon", "/usr/bin/busctl", "/usr/bin/getent", "/usr/bin/resolvectl", "/usr/lib/systemd/systemd-resolved",
                    shutil.which("python3")]:
        copy_program(program, root)
    stdlib = Path(sysconfig.get_path("stdlib"))
    target = root / stdlib.relative_to("/")
    shutil.copytree(stdlib, target, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("site-packages", "test", "tests", "__pycache__",
                                                 "idlelib", "tkinter", "ensurepip"))
    for module in (stdlib / "lib-dynload").glob("*.so"):
        copy_program(module, root)
    for name in ["libnss_resolve.so.2", "libnss_dns.so.2", "libnss_files.so.2"]:
        library = Path("/usr/lib") / name
        if library.exists():
            copy_program(library, root)


def copy_modules(root, kernel):
    modules = ["veth", "dummy", "nf_tables", "nft_ct", "nft_nat", "nft_chain_nat", "nft_socket"]
    for name in modules:
        dependencies = run(["modprobe", "--show-depends", "--set-version", kernel, name])
        for line in dependencies.splitlines():
            if line.startswith("insmod "):
                copy_file(Path(line.split()[1]).resolve(), root)
    module_root = Path("/usr/lib/modules") / kernel
    for meta in module_root.glob("modules.*"):
        if meta.is_file():
            copy_file(meta, root)
    return modules


def configure_guest(root, source, modules):
    # modprobe ищет модули через /lib, как и динамический загрузчик.
    (root / "lib").mkdir(exist_ok=True)
    link("../usr/lib/modules", root / "lib/modules")
    (root / "sbin").mkdir(exist_ok=True)
    link("../usr/bin/modprobe", root / "sbin/modprobe")
    for directory in ["proc", "sys", "dev", "run", "tmp", "etc/systemd", "var/tmp", "lab", "root"]:
        (root / directory).mkdir(parents=True, exist_ok=True)
    link("../run", root / "var/run")
    (root / "tmp").chmod(0o1777)
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\nlab:x:1000:1000:lab:/tmp:/bin/sh\nsystemd-resolve:x:976:976::/:/bin/sh\n")
    (root / "etc/group").write_text("root:x:0:\nlab:x:1000:\nsystemd-resolve:x:976:\n")
    (root / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: resolve [!UNAVAIL=return] files dns\n")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n::1 localhost\n")
    (root / "etc/machine-id").write_text("a1b2c3d4e5f60123456789abcdef01234\n")
    (root / "bin").mkdir(exist_ok=True)
    for command in ["sh", "mount", "mkdir", "chmod", "chown", "poweroff", "sleep", "cat", "ln"]:
        link("../usr/lib/initcpio/busybox", root / "bin" / command)
    shutil.copy2(source / "linux_probe.py", root / "lab/linux_probe.py")
    shutil.copy2(source / "dns_context.py", root / "lab/dns_context.py")
    (root / "lab/.app-routing-guest").write_text("aivpn-offline-routing-lab\n")
    init = root / "init"
    init.write_text("#!/bin/sh\nset -eu\nexport PATH=/usr/bin:/bin\nmount -t proc proc /proc\nmount -t sysfs sysfs /sys\nmount -t devtmpfs devtmpfs /dev\nmount -t tmpfs tmpfs /run\nmount -t cgroup2 none /sys/fs/cgroup\nmodprobe -a " + " ".join(modules) + "\nset +e\npython3 /lab/linux_probe.py\necho AIVPN_PROBE_EXIT:$?\npoweroff -f\n")
    init.chmod(0o755)


def pack_guest(output, root, kernel):
    archive = output / "initramfs.cpio.gz"
    files = b".\0" + b"\0".join(os.fsencode(str(path.relative_to(root))) for path in root.rglob("*")) + b"\0"
    with archive.open("wb") as destination:
        cpio = subprocess.Popen(["cpio", "--null", "-o", "--format=newc", "--owner=0:0"],
                                cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        gzip = subprocess.Popen(["gzip", "-1"], stdin=cpio.stdout, stdout=destination)
        cpio.stdout.close()
        cpio.communicate(files)
        assert cpio.returncode == 0
        assert gzip.wait() == 0
    (output / "manifest.json").write_text(json.dumps({"kernel": kernel, "archive_bytes": archive.stat().st_size}, indent=2) + "\n")
    return archive


def build(output, kernel):
    if not re.fullmatch(r"[A-Za-z0-9._+-]+", kernel):
        raise ValueError("Недопустимая версия ядра")
    marker_file = output / ".aivpn-lab-output"
    if output.exists() and any(output.iterdir()):
        if not marker_file.is_file() or marker_file.read_text() != "aivpn-offline-routing-lab\n":
            raise ValueError("Нужен пустой каталог output или прежний каталог этого стенда")
    output.mkdir(parents=True, exist_ok=True)
    marker_file.write_text("aivpn-offline-routing-lab\n")
    root = output / "root"
    root.mkdir(exist_ok=True)
    source = Path(__file__).resolve().parent
    marker = output / "socket_mark"
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-O2", str(source / "socket_mark.c"),
                    "-o", str(marker), "-lbpf"], check=True)
    copy_runtime(root)
    copy_program(marker, root)
    shutil.move(root / marker.relative_to("/"), root / "usr/bin/socket_mark")
    modules = copy_modules(root, kernel)
    configure_guest(root, source, modules)
    print(pack_guest(output, root, kernel))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kernel", required=True)
    args = parser.parse_args()
    build(args.output.resolve(), args.kernel)
