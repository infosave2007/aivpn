"""Проверяет восстановление Git-каталога nDPI после очистки кеша Cargo."""
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

repo = pathlib.Path(__file__).resolve().parents[2]
script = repo / "deploy/ci/build-dpi-tools.sh"
real_git = shutil.which("git")
assert real_git

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    parent = root / "application"
    subprocess.run([real_git, "init", "-q", str(parent)], check=True)
    subprocess.run([real_git, "-C", str(parent), "remote", "add", "origin",
                    "https://example.invalid/application.git"], check=True)
    original_config = (parent / ".git/config").read_bytes()
    binary_dir = root / "bin"
    binary_dir.mkdir()
    shim = binary_dir / "git"
    shim.write_text('''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
if "fetch" in args:
    options = args[:args.index("fetch")]
    git_dir = subprocess.check_output(
        [os.environ["REAL_GIT"], *options, "rev-parse", "--absolute-git-dir"], text=True).strip()
    with pathlib.Path(os.environ["FETCH_LOG"]).open("a") as log:
        log.write(json.dumps({"git_dir": git_dir, "args": args}) + "\\n")
    sys.exit(1)
os.execv(os.environ["REAL_GIT"], [os.environ["REAL_GIT"], *args])
''')
    shim.chmod(0o755)
    sleep = binary_dir / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)

    for name, damaged in [("fresh", False), ("damaged-cache", True)]:
        checkout = parent / "target/dpi-tools" / name
        if damaged:
            (checkout / ".git/objects").mkdir(parents=True)
            (checkout / ".git/refs/heads").mkdir(parents=True)
        log = root / (name + ".jsonl")
        env = dict(os.environ, PATH=str(binary_dir) + os.pathsep + os.environ["PATH"],
                   REAL_GIT=real_git, FETCH_LOG=str(log), AIVPN_NDPI_DIR=str(checkout))
        result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
        assert result.returncode != 0, "Ошибка загрузки должна останавливать сборку"
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        assert len(calls) == 3, calls
        for call in calls:
            assert pathlib.Path(call["git_dir"]) == checkout / ".git", call
            assert "https://github.com/ntop/nDPI.git" in call["args"], call
            assert call["args"][-1] == "refs/tags/5.0", call
        assert (parent / ".git/config").read_bytes() == original_config
        assert not (parent / ".git/FETCH_HEAD").exists()
        print(f"DPI checkout {name}: PASS")
