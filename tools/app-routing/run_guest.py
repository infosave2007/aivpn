#!/usr/bin/env python3
"""Запускает изолированный KVM-стенд и проверяет его итог по JSON, а не коду выхода QEMU."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kernel", required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_dir() and (output / ".aivpn-lab-output").is_file():
        (output / "result.json").unlink(missing_ok=True)
    source = Path(__file__).resolve().parent
    subprocess.run([sys.executable, str(source / "make_guest.py"), "--output", str(output),
                    "--kernel", args.kernel], check=True)
    kernel = Path("/usr/lib/modules") / args.kernel / "vmlinuz"
    with (output / "serial.log").open("w") as log:
        subprocess.run(["qemu-system-x86_64", "-accel", "kvm", "-cpu", "host", "-m", "1024",
                        "-smp", "2", "-nodefaults", "-nographic", "-no-reboot", "-monitor", "none",
                        "-serial", "stdio", "-nic", "none", "-kernel", str(kernel),
                        "-initrd", str(output / "initramfs.cpio.gz"), "-append",
                        "console=ttyS0 panic=1 oops=panic quiet aivpn.app-routing-lab=1"],
                       stdout=log, stderr=subprocess.STDOUT, timeout=120, check=True)
    text = (output / "serial.log").read_text()
    summary = next((json.loads(line.split("AIVPN_SUMMARY ", 1)[1]) for line in text.splitlines()
                    if "AIVPN_SUMMARY " in line), None)
    if summary is None or "AIVPN_PROBE_EXIT:0" not in text or not summary["checks"]:
        raise SystemExit("Guest не завершил проверку: см. serial.log")
    if not all(check["ok"] for check in summary["checks"]):
        raise SystemExit("Одна из проверок guest не прошла: см. serial.log")
    required = {"early_mark_source_4", "early_mark_source_6", "scoped_nat_roundtrip_4",
                "scoped_nat_roundtrip_6", "caller_aware_dns_separates_identical_names",
                "dead_broker_has_no_system_dns_fallback_with_guard", "ordinary_dns_survives_broker_death",
                "early_mark_tcp_4", "early_mark_tcp_6", "scoped_nat_tcp_4", "scoped_nat_tcp_6",
                "missing_vpn_route_is_blocked_4", "missing_vpn_route_is_blocked_6",
                "system_path_survives_vpn_failure_4", "system_path_survives_vpn_failure_6",
                "malformed_nss_requests_do_not_kill_broker", "dbus_dns_bypasses_managed_nss_context"}
    if not required.issubset({check["name"] for check in summary["checks"]}):
        raise SystemExit("Guest не выполнил обязательные проверки")
    with kernel.open("rb") as image:
        summary["kernel_sha256"] = hashlib.file_digest(image, "sha256").hexdigest()
    summary["kernel"] = args.kernel
    summary["scope"] = "Linux managed NSS A-query prototype; not a complete application-routing backend"
    (output / "result.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    print(f"PASS: {len(summary['checks'])} проверок механизмов Linux; продуктовая функция еще не включена")


if __name__ == "__main__":
    main()
