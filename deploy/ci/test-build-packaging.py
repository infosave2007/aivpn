#!/usr/bin/env python3
"""Исполняет настоящие Make-рецепты с локальными заменами внешних команд."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]

STUB = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, shutil, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ['PACKAGING_FIXTURE'])
if name == 'docker':
    if args[0] == 'build':
        shutil.copyfile(args[args.index('-f') + 1], root / 'Dockerfile.generated')
    elif args[0] == 'cp':
        pathlib.Path(args[-1]).write_bytes(b'fixture binary')
elif name == 'appimagetool':
    pathlib.Path(args[-1]).write_bytes(b'fixture appimage')
elif name == 'ssh':
    with (root / 'ssh-calls.jsonl').open('a') as log:
        log.write(json.dumps(args) + '\n')
    if 'sha256sum' in args or args[-1].startswith('sha256sum '):
        data = (root / 'releases/aivpn-server-linux-x86_64').read_bytes()
        print(hashlib.sha256(data).hexdigest() + '  fixture')
elif name == 'scp':
    remote = args[-1].split(':', 1)[1]
    assert remote.startswith('/fixture-remote/')
    dest = root / 'remote' / remote.removeprefix('/fixture-remote/')
    dest.mkdir(parents=True, exist_ok=True)
    for arg in args[:-1]:
        if pathlib.Path(arg).is_file():
            shutil.copy2(arg, dest / pathlib.Path(arg).name)
elif name != 'cargo':
    raise SystemExit('unexpected command: ' + name)
'''


class PackagingTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='aivpn packaging ')
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for tool in ('docker', 'cargo', 'appimagetool', 'ssh', 'scp'):
            path = self.bin / tool
            path.write_text(STUB)
            path.chmod(0o700)
        shutil.copy2(REPO / 'Cargo.toml', self.root)
        for folder in ('target/release', 'releases', 'deploy/docker',
                       'deploy/config', 'assets/masks'):
            (self.root / folder).mkdir(parents=True)
        for name in ('aivpn-linux', 'aivpn-client', 'aivpn-ip-helper'):
            path = self.root / 'target/release' / name
            path.write_text('#!/bin/sh\nprintf "bundled:%s\\n" "$*"\n')
            path.chmod(0o700)
        (self.root / 'releases/aivpn-server-linux-x86_64').write_bytes(b'server fixture')
        for name in ('Dockerfile.prebuilt', 'docker-entrypoint.sh'):
            shutil.copy2(REPO / 'deploy/docker' / name, self.root / 'deploy/docker')
        shutil.copy2(REPO / 'docker-compose.yml', self.root)
        shutil.copy2(REPO / 'deploy/config/server.json.example', self.root / 'deploy/config')
        (self.root / 'assets/masks/fixture.json').write_text('{}')
        self.env = os.environ | {'PACKAGING_FIXTURE': str(self.root)}

    def make(self, target, *args):
        result = subprocess.run(['make', '-f', str(REPO / 'Makefile'), target,
                                 f'PATH={self.bin}:/usr/bin:/bin', *args], cwd=self.root,
                                env=self.env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_musl_context_contains_local_patches(self):
        self.make('server-musl-aarch64')
        dockerfile = (self.root / 'Dockerfile.generated').read_text()
        self.assertIn('COPY vendor vendor/', dockerfile)

    def test_apprun_executes_bundled_binary_with_spaces(self):
        self.make('linux-appimage')
        output = subprocess.check_output(
            [str(self.root / 'AppDir-aivpn-linux/AppRun'), 'argument with spaces'],
            text=True, timeout=5)
        self.assertEqual(output, 'bundled:argument with spaces\n')

    def test_server_deploy_transfers_every_copy_source(self):
        remote = self.root / 'remote'
        self.make('server-deploy', 'HOST=fixture.invalid', 'REMOTE=/fixture-remote')
        calls = [json.loads(line) for line in (self.root / 'ssh-calls.jsonl').read_text().splitlines()]
        self.assertTrue(all(call[-2] == 'root@fixture.invalid' for call in calls))
        self.assertTrue(any('apt-get update' in call[-1] for call in calls))
        self.assertTrue(any('$DC up -d' in call[-1] for call in calls))
        for line in (remote / 'deploy/docker/Dockerfile.prebuilt').read_text().splitlines():
            if line.startswith('COPY '):
                for pattern in line.split()[1:-1]:
                    self.assertTrue(list(remote.glob(pattern)), f'COPY missing: {pattern}')

    @unittest.skipUnless(shutil.which('docker'), 'docker compose не установлен')
    def test_monitoring_mounts_exist(self):
        result = subprocess.run([
            'docker', 'compose', '-f', 'docker-compose.yml', '-f',
            'deploy/monitoring/docker-compose.monitoring.yml', '--profile', 'monitoring',
            'config', '--format', 'json'], cwd=REPO, env=os.environ | {
                'AIVPN_GRAFANA_ADMIN_PASSWORD': 'test-only-not-a-secret'},
            text=True, capture_output=True, timeout=15)
        if result.returncode and 'compose' in result.stderr:
            self.skipTest('docker compose недоступен')
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(result.stdout)
        for service in ('prometheus', 'grafana'):
            for mount in config['services'][service]['volumes']:
                if mount['type'] == 'bind':
                    self.assertTrue(Path(mount['source']).exists(), mount['source'])

    def test_release_checkout_uses_publish_tag(self):
        workflow = (REPO / '.github/workflows/server-release-asset.yml').read_text()
        checkouts = re.findall(r'uses: actions/checkout@v4\n([^\n]*\n[^\n]*\n)', workflow)
        self.assertEqual(len(checkouts), 8)
        for options in checkouts:
            self.assertIn('ref:', options)
            self.assertIn('github.event.release.tag_name', options)
            self.assertIn('github.event.inputs.tag', options)

    def test_wintun_rejects_unverified_download_without_changing_target(self):
        curl = self.bin / 'curl'
        curl.write_text('#!/bin/sh\nwhile [ "$1" != "-o" ]; do shift; done\nprintf invalid > "$2"\n')
        curl.chmod(0o700)
        target = self.root / 'wintun.dll'
        target.write_bytes(b'old verified dll')
        result = subprocess.run(['sh', str(REPO / 'deploy/ci/fetch-wintun.sh'), str(target)],
                                env=self.env | {'PATH': f'{self.bin}:/usr/bin:/bin',
                                                'TMPDIR': str(self.root)}, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), b'old verified dll')
        self.assertEqual(list(self.root.glob('aivpn-wintun.*')), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
