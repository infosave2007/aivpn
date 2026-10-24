#!/usr/bin/env python3
"""Сверяет JNI-экспорты собранной библиотеки с вызовами Android-приложения."""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--nm')
    args = parser.parse_args()
    nm = args.nm or shutil.which('llvm-nm')
    if not nm and os.environ.get('ANDROID_NDK_HOME'):
        candidates = sorted(Path(os.environ['ANDROID_NDK_HOME']).glob('toolchains/llvm/prebuilt/*/bin/llvm-nm*'))
        nm = str(candidates[0]) if candidates else None
    if not nm:
        parser.error('не найден llvm-nm; задайте --nm или ANDROID_NDK_HOME')
    kotlin = ROOT / 'platforms/android/app/src/main/java/com/aivpn/client/AivpnJni.kt'
    expected = {'Java_com_aivpn_client_AivpnJni_' + name
                for name in re.findall(r'external\s+fun\s+(\w+)', kotlin.read_text())}
    result = subprocess.run([nm, '-D', '--defined-only', str(args.library)], capture_output=True, text=True)
    if result.returncode:
        print('FAIL: не удалось прочитать таблицу символов', file=sys.stderr)
        return 1
    actual = {line.split()[-1] for line in result.stdout.splitlines() if line.split()}
    missing = sorted(expected - actual)
    if not expected or missing:
        print('FAIL: отсутствуют JNI-экспорты: ' + ', '.join(missing), file=sys.stderr)
        return 1
    print(f'PASS: все JNI-вызовы приложения доступны ({len(expected)})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
