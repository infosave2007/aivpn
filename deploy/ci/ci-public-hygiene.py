#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FORBIDDEN = {
    "25bf6a1d9829fb0e7b6a814b440a73c5963ba01c08cd106e0f54079bb2313824": "H01",
    "9b76d77a4033df6addf683558315afe932bead64eb93cfb396fb4401ad2dafa0": "H02",
    "bdf0d2ffa29c1350fcbb63bcb95cf93d25cf98c7857ea274e06debd2bf7f0e40": "H03",
    "97230afdb429163681fb52b7820648ab8d7f99a5b8da6a88a9e3b5b0e10086d1": "H04",
    "e287a4c805bd0c61ad3bad18ef42b96bd7ec93e1e321f9c85308b8da4e52cf05": "H05",
    "e4d9c0f3abcbc8ca9e7085ca5e76a679e0c7fd72cf75babf86945802ead1dc18": "H06",
}
SKIP_NAMES = {"Cargo.lock", "package-lock.json", "bun.lock", "yarn.lock"}
INTERNAL_PATH_DIGESTS = {
    "b951327c37d8a1ed4d5ed18908681f6aca718ecdfe174aa39cf2237547f92fe7",
    "bccc86317c281a19e56f3f941077ea61b3fb37d5bd527c518b92b188c4461251",
    "a1d1128ffe5a2849afb3ac4cad6413b6d75453babc7cac579b95c66a565fe4cc",
    "e026f56c08dcdea441a2aa620ab410ce91162062609b2430f5a13bc9b7cf93f1",
}
SERVICE_REPORT = re.compile(r"(^|/)CODE_REVIEW(?:_[^/]*)?\.md$", re.IGNORECASE)
TOKEN = re.compile(r"[\w-]+", re.UNICODE)


def tracked_paths() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def digest(token: str) -> str:
    return hashlib.sha256(token.casefold().encode("utf-8")).hexdigest()


def main() -> int:
    violations: list[str] = []
    for relative in tracked_paths():
        path = REPO_ROOT / relative
        if not path.is_file():
            continue
        path_parts = pathlib.PurePosixPath(relative).parts
        if SERVICE_REPORT.search(relative) or any(
            digest(part) in INTERNAL_PATH_DIGESTS for part in path_parts
        ):
            violations.append(f"{relative}: служебный путь")
            continue
        if pathlib.PurePosixPath(relative).name in SKIP_NAMES:
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="ignore")
        for line_number, line in enumerate(text.splitlines(), 1):
            for match in TOKEN.finditer(line):
                label = FORBIDDEN.get(digest(match.group(0)))
                if label:
                    violations.append(f"{relative}:{line_number}: {label}")

    if violations:
        print(f"FAIL: найдено нарушений границы репозитория: {len(violations)}")
        for violation in violations[:50]:
            print(f"  {violation}")
        if len(violations) > 50:
            print(f"  и еще {len(violations) - 50}")
        return 1

    print("PASS: граница публичного репозитория соблюдена")
    return 0


if __name__ == "__main__":
    sys.exit(main())
