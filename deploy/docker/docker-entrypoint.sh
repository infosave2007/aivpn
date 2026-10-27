#!/bin/sh
set -eu

exec python3 - "$@" <<'PY'
import json
import os
from pathlib import Path
import shutil
import sys

SERVER = "/usr/local/bin/aivpn-server"
arguments = sys.argv[1:]
MISSING = object()


def run_server():
    os.execv(SERVER, [SERVER, *arguments])


# Эти команды сами управляют файлами или обходятся без конфигурации сервера.
standalone = {"--import", "--validate-mask", "--gen-ca", "--gen-mask-signing-key",
              "--issue-cert", "--sign-mask-dir", "--help", "--version", "-h", "-V"}
if any(argument.split("=", 1)[0] in standalone for argument in arguments):
    run_server()


def cli_value(long_name, short_name=None):
    result = MISSING
    for index, argument in enumerate(arguments):
        if argument == "--":
            break
        if argument == long_name or argument == short_name:
            if index + 1 < len(arguments):
                result = arguments[index + 1]
        elif argument.startswith(long_name + "="):
            result = argument.split("=", 1)[1]
        elif short_name and argument.startswith(short_name) and len(argument) > len(short_name):
            result = argument[len(short_name):].removeprefix("=")
    return result


def env_text(name):
    if name not in os.environ:
        return MISSING
    raw = os.environ[name]
    try:
        value = json.loads(raw)
        if isinstance(value, str) or value is None:
            return value
    except ValueError:
        pass
    return raw


configured_path = cli_value("--config", "-c")
if configured_path is MISSING:
    configured_path = env_text("AIVPN_CONFIG")
if configured_path is MISSING:
    configured_path = env_text("AIVPN_CONFIG_PATH")
if configured_path is None:
    run_server()
config_path = Path(configured_path if configured_path is not MISSING else "/etc/aivpn/server.json")
if configured_path is MISSING and not os.path.lexists(config_path):
    config_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile("/usr/share/aivpn/server.json.example", config_path)
    config_path.chmod(0o600)
    print("Инициализирован файл конфигурации", flush=True)

# Ошибки содержимого и явно заданных путей объясняет общий resolver сервера.
try:
    config = json.loads(config_path.read_text())
except (OSError, ValueError):
    run_server()
if not isinstance(config, dict):
    run_server()
os.environ.setdefault("AIVPN_CONFIG", str(config_path))

configured_key = cli_value("--key-file")
if configured_key is MISSING:
    configured_key = env_text("AIVPN_KEY_FILE")
if configured_key is MISSING:
    configured_key = config.get("key_file")
if configured_key is None:
    key_path = Path("/etc/aivpn/server.key")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "wb") as key:
            key.write(os.urandom(32))
        print("Создан постоянный ключ сервера", flush=True)
    os.environ["AIVPN_KEY_FILE"] = str(key_path)

mask_dir = cli_value("--mask-dir")
if mask_dir is MISSING:
    mask_dir = env_text("AIVPN_MASK_DIR")
if mask_dir is MISSING:
    mask_dir = config.get("mask_dir")
if mask_dir is None:
    mask_dir = "/var/lib/aivpn/masks"
if not isinstance(mask_dir, str) or not mask_dir.strip():
    run_server()
masks = Path(mask_dir)
try:
    masks.mkdir(parents=True, exist_ok=True)
except OSError:
    run_server()
for source in Path("/usr/share/aivpn/preset-masks").glob("*.json"):
    target = masks / source.name
    if not target.exists():
        try:
            shutil.copyfile(source, target)
        except OSError:
            # Маски могут быть смонтированы только для чтения и уже готовы к работе.
            pass

run_server()
PY
