#!/usr/bin/env python3
"""Проверяет источники конфигурации контейнера без запуска VPN и изменения сети."""
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "deploy/docker/docker-entrypoint.sh").read_text()


class EntrypointTest(unittest.TestCase):
    def run_entrypoint(self, mode, cli=(), env=None, config=None, persisted=False, readonly_masks=False):
        with tempfile.TemporaryDirectory(prefix="aivpn-entrypoint-") as directory:
            root = Path(directory)
            default = root / "etc"
            shared = root / "share"
            default.mkdir()
            shared.mkdir()
            masks = root / "masks"
            presets = shared / "preset-masks"
            presets.mkdir()
            (presets / "bundled.json").write_text('{"id":"bundled"}')
            if readonly_masks:
                masks.mkdir()
                shutil.copyfile(next((ROOT / "assets/masks").glob("*.json")), masks / "custom.json")
                masks.chmod(0o555)
                config = {"key_file": "/configured.key", "mask_dir": str(masks)}
            (shared / "server.json.example").write_text(json.dumps({"key_file": None, "mask_dir": str(masks)}))
            default_config = default / "server.json"
            custom_config = root / "custom.json"
            if config is not None:
                (custom_config if mode == "custom" else default_config).write_text(json.dumps(config))
            if persisted:
                (default / "server.key").write_bytes(b"p" * 32)
            stub = root / "server"
            stub.write_text("#!/usr/bin/python3\nimport json, os, sys\nprint(json.dumps({'args':sys.argv[1:], 'env':{k:v for k,v in os.environ.items() if k in ('AIVPN_KEY_FILE','AIVPN_CONFIG','RUST_LOG')}}))\n")
            stub.chmod(0o700)
            source = SOURCE.replace("/etc/aivpn", str(default)).replace("/usr/share/aivpn", str(shared)).replace("/var/lib/aivpn/masks", str(masks)).replace("/usr/local/bin/aivpn-server", str(stub))
            script = root / "entrypoint.sh"
            script.write_text(source)
            args = [value.replace("CONFIG", str(custom_config)) for value in cli]
            environment = {"PATH": "/usr/bin:/bin"} | (env or {})
            environment = {key: str(custom_config) if value == "CONFIG" else value for key, value in environment.items()}
            output = subprocess.run(["sh", str(script), *args], env=environment, capture_output=True, text=True, timeout=5)
            self.assertEqual(output.returncode, 0, output.stderr)
            result = json.loads(output.stdout.splitlines()[-1])
            key = default / "server.key"
            result["default_key_exists"] = key.exists()
            result["default_key_length"] = key.stat().st_size if key.exists() else 0
            result["persisted_key_unchanged"] = key.exists() and key.read_bytes() == b"p" * 32
            result["default_config"] = default_config.exists()
            result["bundled_mask_exists"] = (masks / "bundled.json").exists()
            result["custom_mask_exists"] = (masks / "custom.json").exists()
            if readonly_masks:
                masks.chmod(0o755)
            return result

    def test_file_key_is_used_without_generating_another_identity(self):
        result = self.run_entrypoint("default", config={"key_file": "/configured.key"})
        self.assertFalse(result["default_key_exists"])
        self.assertNotIn("AIVPN_KEY_FILE", result["env"])
        self.assertNotIn("RUST_LOG", result["env"])

    def test_custom_config_and_key_sources_are_kept(self):
        for cli, env in [(("--config", "CONFIG", "--key-file", "/cli.key"), {}),
                         ((), {"AIVPN_CONFIG": "CONFIG", "AIVPN_KEY_FILE": "/env.key"}),
                         (("--config=CONFIG",), {"AIVPN_KEY_FILE": "/env.key"}),
                         (("-c=CONFIG",), {"AIVPN_KEY_FILE": "/env.key"}),
                         ((), {"AIVPN_CONFIG_PATH": "CONFIG", "AIVPN_KEY_FILE": "/env.key"})]:
            with self.subTest(cli=cli, env=env):
                result = self.run_entrypoint("custom", cli=cli, env=env, config={})
                self.assertFalse(result["default_key_exists"])
                self.assertFalse(result["default_config"])

    def test_fallback_key_is_persisted_without_injecting_cli_defaults(self):
        result = self.run_entrypoint("default", persisted=True)
        self.assertTrue(result["persisted_key_unchanged"])
        self.assertTrue(result["env"]["AIVPN_KEY_FILE"].endswith("/etc/server.key"))
        self.assertEqual(result["args"], [])
        self.assertNotIn("RUST_LOG", result["env"])

    def test_restore_does_not_seed_state(self):
        result = self.run_entrypoint("default", cli=("--import", "/fixture/backup.tar.gz"))
        self.assertFalse(result["default_key_exists"])
        self.assertFalse(result["default_config"])

    def test_explicit_null_clears_file_key_and_mask_directory(self):
        result = self.run_entrypoint("default", config={"key_file": "/configured.key", "mask_dir": "/missing/file-masks"},
            env={"AIVPN_KEY_FILE": "null", "AIVPN_MASK_DIR": "null"})
        self.assertTrue(result["default_key_exists"])
        self.assertEqual(result["default_key_length"], 32)
        self.assertTrue(result["bundled_mask_exists"])

    @unittest.skipIf(os.geteuid() == 0, "Для проверки прав нужен пользователь без root")
    def test_readonly_custom_mask_directory_does_not_block_server(self):
        result = self.run_entrypoint("default", readonly_masks=True)
        self.assertTrue(result["custom_mask_exists"])
        self.assertFalse(result["bundled_mask_exists"])

    def test_image_does_not_force_runtime_flags(self):
        for path in ("Dockerfile", "deploy/docker/Dockerfile.prebuilt"):
            with self.subTest(path=path):
                dockerfile = (ROOT / path).read_text()
                self.assertIn("CMD []", dockerfile)
                self.assertIn("python3", dockerfile.split("FROM debian:", 1)[1])


class InstallerSeedTest(unittest.TestCase):
    def test_public_endpoint_is_persisted_only_when_creating_config(self):
        source = (ROOT / "deploy/install-server.sh").read_text()
        functions = []
        for name in ("json_escape", "sed_escape_replacement", "seed_config"):
            start = source.index(name + "() {")
            functions.append(source[start:source.index("\n}\n", start) + 3])
        with tempfile.TemporaryDirectory(prefix="aivpn-seed-config-") as directory:
            path = Path(directory) / "server.json"
            script = "set -euo pipefail\nemit_marker() { :; }\n" + "\n".join(functions) + "\nseed_config\n"
            environment = os.environ | {"CONFIG_PATH": str(path), "SCRIPT_DIR": str(ROOT / "deploy"),
                "LISTEN_ADDR": "[::]:9443", "PUBLIC_SERVER_IP": "vpn.example:8443"}
            first = subprocess.run(["bash", "-c", script], env=environment, capture_output=True, timeout=5)
            self.assertEqual(first.returncode, 0, first.stderr.decode())
            config = json.loads(path.read_text())
            self.assertEqual(config["server_ip"], "vpn.example:8443")
            self.assertEqual(config["listen_addr"], "[::]:9443")
            previous = path.read_bytes()
            second = subprocess.run(["bash", "-c", script], env=environment | {"PUBLIC_SERVER_IP": "new.example"}, capture_output=True, timeout=5)
            self.assertEqual(second.returncode, 0, second.stderr.decode())
            self.assertEqual(path.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main(verbosity=2)
