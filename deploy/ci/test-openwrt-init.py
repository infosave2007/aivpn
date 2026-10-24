#!/usr/bin/env python3
"""Проверяет procd и правила блокировки с подставными командами."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
INIT = ROOT / 'platforms/openwrt/package/aivpn/files/aivpn.init'


class InitTest(unittest.TestCase):
    def start(self, **settings):
        with tempfile.TemporaryDirectory(prefix='aivpn-openwrt-') as temporary:
            directory = Path(temporary)
            logger = directory / 'record'
            logger.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['CALL_LOG'], 'a') as output:
    output.write(json.dumps(sys.argv[1:]) + '\\n')
''')
            logger.chmod(0o700)
            nft = directory / 'nft'
            nft.write_text('''#!/bin/sh
record nft "$@"
if [ "$1" = '-f' ]; then cat > "$NFT_LOG"; fi
''')
            nft.chmod(0o700)
            script = '''
config_load() { :; }
config_get() { eval "$1=\\\"\\${setting_$3-$4}\\\""; }
config_get_bool() { config_get "$@"; }
procd_open_instance() { record open; }
procd_set_param() { record set "$@"; }
procd_append_param() { record append "$@"; }
procd_close_instance() { record close; }
. "$INIT"
start_service
'''
            environment = os.environ | {
                'PATH': f'{directory}:/usr/bin:/bin', 'INIT': str(INIT),
                'CALL_LOG': str(directory / 'calls'), 'NFT_LOG': str(directory / 'nft-rules'),
            } | {f'setting_{key}': str(value) for key, value in settings.items()}
            result = subprocess.run(['sh', '-c', script], env=environment, capture_output=True, timeout=5)
            calls = directory / 'calls'
            rules = directory / 'nft-rules'
            return result, ([json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []), (rules.read_text() if rules.exists() else '')

    def test_default_preserves_wan_and_supervises_client(self):
        result, calls, rules = self.start(enabled=1, connection_key='test-profile')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(['set', 'env', 'AIVPN_CONNECTION_KEY=test-profile'], calls)
        self.assertIn(['set', 'respawn', '3600', '5', '0'], calls)
        self.assertIn(['append', 'command', '--tun-name', 'aivpn0', '--full-tunnel'], calls)
        self.assertNotIn(['append', 'command', '--kill-switch'], calls)
        self.assertEqual(rules, '')

    def test_explicit_block_survives_client_restart(self):
        result, calls, rules = self.start(enabled=1, connection_key='test-profile', kill_switch=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(['append', 'command', '--kill-switch'], calls)
        self.assertIn('hook forward priority -20', rules)
        self.assertIn('iifname != "aivpn0" oifname != "aivpn0" drop', rules)

    def test_manual_mode_requires_psk_before_start(self):
        result, calls, _ = self.start(enabled=1, server='192.0.2.1:8443', server_key='test-key')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(['open'], calls)
        result, calls, _ = self.start(enabled=1, server='192.0.2.1:8443', server_key='test-key', preshared_key='test-psk')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(['set', 'env', 'AIVPN_PRESHARED_KEY=test-psk'], calls)
        self.assertFalse(any('test-psk' in call for call in calls if 'command' in call))

    def test_disabled_service_clears_guard(self):
        result, calls, _ = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(['nft', 'delete', 'table', 'inet', 'aivpn_router_guard'], calls)
        self.assertNotIn(['open'], calls)


if __name__ == '__main__':
    unittest.main(verbosity=2)
