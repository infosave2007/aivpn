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
            for name in ('sysctl', 'iptables', 'client', 'sleep'):
                tool = work / name
                tool.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ['GATEWAY_LOG'], 'a') as f:
    f.write(json.dumps([name] + sys.argv[1:]) + '\\n')
if name == 'sleep': raise SystemExit(77)
if name == 'iptables' and ('-C' in sys.argv or os.environ.get('FAIL_FIREWALL')):
    raise SystemExit(1)
''')
                tool.chmod(0o700)
            # Меняется только абсолютный путь исполняемого клиента.
            script = 'set -e\n' + gateway.replace('/usr/local/bin/aivpn-client', str(work / 'client'))
            result = subprocess.run(['sh', '-c', script], env=os.environ | {
                'PATH': f'{work}:/usr/bin:/bin', 'AIVPN_KEY': 'test-key-not-a-secret',
                'GATEWAY_LOG': str(log)} | (extra or {}), capture_output=True, timeout=5)
            return result.returncode, [json.loads(line) for line in log.read_text().splitlines()]

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

    def test_runtime_installs_iptables(self):
        runtime = (root / 'platforms/mikrotik/Dockerfile').read_text().split('FROM alpine:', 1)[1]
        self.assertIn('iptables', runtime.split('COPY ', 1)[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
