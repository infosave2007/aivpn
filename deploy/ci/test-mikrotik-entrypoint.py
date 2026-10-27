#!/usr/bin/env python3
"""Проверяет gateway-команды entrypoint, не открывая TUN и не меняя сеть."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

root = Path(__file__).resolve().parents[2]
source = (root / 'platforms/mikrotik/entrypoint.sh').read_text()
gateway = source[source.index('# Enable IP forwarding'):]


class GatewayTest(unittest.TestCase):
    def run_gateway(self, extra=None):
        with tempfile.TemporaryDirectory(prefix='aivpn-mikrotik-') as temp:
            work = Path(temp)
            log = work / 'calls.jsonl'
            for name in ('sysctl', 'iptables', 'ip6tables', 'client', 'sleep'):
                tool = work / name
                tool.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ['GATEWAY_LOG'], 'a') as f:
    f.write(json.dumps([name] + sys.argv[1:]) + '\\n')
if name == 'sleep': raise SystemExit(77)
if name in ('iptables', 'ip6tables') and ('-C' in sys.argv or os.environ.get('FAIL_FIREWALL')):
    raise SystemExit(1)
''')
                tool.chmod(0o700)
            # Меняется только абсолютный путь исполняемого клиента.
            script = 'set -e\n' + gateway.replace('/usr/local/bin/aivpn-client', str(work / 'client'))
            result = subprocess.run(['sh', '-c', script], env=os.environ | {
                'PATH': f'{work}:/usr/bin:/bin', 'AIVPN_KEY': 'test-key-not-a-secret',
                'GATEWAY_LOG': str(log)} | (extra or {}), capture_output=True, timeout=5)
            return result.returncode, [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def test_gateway_uses_same_tun_and_full_tunnel_by_default(self):
        code, calls = self.run_gateway()
        self.assertEqual(code, 77)
        client = next(call for call in calls if call[0] == 'client')
        self.assertIn('--full-tunnel', client)
        self.assertIn('--tun-name', client)
        tun = client[client.index('--tun-name') + 1]
        rules = [call for call in calls if call[0] == 'iptables' and '-A' in call]
        self.assertEqual(len(rules), 3)
        self.assertTrue(all(tun in rule for rule in rules))

    def test_firewall_error_stops_before_client(self):
        code, calls = self.run_gateway({'FAIL_FIREWALL': '1'})
        self.assertNotEqual(code, 0)
        self.assertFalse(any(call[0] == 'client' for call in calls))

    def test_blocking_is_optional_and_covers_both_families(self):
        _, calls = self.run_gateway()
        self.assertFalse(any('DROP' in call for call in calls))
        _, calls = self.run_gateway({'AIVPN_KILL_SWITCH': 'true'})
        client = next(call for call in calls if call[0] == 'client')
        self.assertIn('--kill-switch', client)
        for firewall in ('iptables', 'ip6tables'):
            self.assertIn([firewall, '-I', 'FORWARD', '1', '-i', 'eth0', '!', '-o', 'tun0', '-j', 'DROP'], calls)

    def test_invalid_interfaces_and_options_stop_before_network_changes(self):
        for extra in ({'LAN_IF': '-evil'}, {'AIVPN_TUN_NAME': 'a' * 16},
                      {'AIVPN_TUN_NAME': 'eth0'}, {'AIVPN_KILL_SWITCH': 'invalid'}):
            with self.subTest(extra=extra):
                code, calls = self.run_gateway(extra)
                self.assertNotEqual(code, 0)
                self.assertEqual(calls, [])

    def test_split_mode_and_custom_interface_are_forwarded(self):
        _, calls = self.run_gateway({'AIVPN_FULL_TUNNEL': 'false', 'AIVPN_TUN_NAME': 'aivpn0'})
        client = next(call for call in calls if call[0] == 'client')
        self.assertNotIn('--full-tunnel', client)
        self.assertEqual(client[client.index('--tun-name') + 1], 'aivpn0')

    def test_runtime_installs_iptables(self):
        runtime = (root / 'platforms/mikrotik/Dockerfile').read_text().split('FROM alpine:', 1)[1]
        self.assertIn('iptables', runtime.split('COPY ', 1)[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
