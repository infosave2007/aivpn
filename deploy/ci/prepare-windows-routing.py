#!/usr/bin/env python3
"""Проверяет явные build-inputs драйвера для единого Windows-клиента."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def prepare(package, driver=None, altitude=None):
    package = Path(package)
    driver = driver or None
    altitude = altitude or None
    if bool(driver) != bool(altitude):
        raise ValueError("Для драйвера нужны файл и явно заданная высота minifilter")
    if driver and not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,16})?", altitude):
        raise ValueError("Некорректная высота minifilter")
    data = None
    if driver:
        driver = Path(driver)
        if driver.is_symlink() or not driver.is_file():
            raise ValueError("Нужен обычный файл подписанного драйвера")
        data = driver.read_bytes()
        if not data.startswith(b"MZ"):
            raise ValueError("Драйвер должен быть PE-образом")
    inputs = package / '.build-inputs'
    inputs.mkdir(parents=True, exist_ok=True)
    if data is not None:
        (inputs / 'routing-driver.sys').write_bytes(data)
    manifest = {'version': 2, 'altitude': altitude,
                'driver_sha256': hashlib.sha256(data).hexdigest() if data else None}
    (inputs / 'manifest.json').write_text(json.dumps(manifest, separators=(',', ':'))+'\n')
    (package / 'routing-bootstrap.nsh').write_text(f'!define ROUTING_ENABLED {int(bool(driver))}\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--driver')
    parser.add_argument('--altitude')
    args = parser.parse_args()
    prepare(args.package, args.driver, args.altitude)


if __name__ == '__main__':
    main()
