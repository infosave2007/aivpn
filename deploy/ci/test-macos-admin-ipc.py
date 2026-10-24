#!/usr/bin/env python3
"""Проверяет настоящий Swift-клиент IPC на фрагментированных и оборванных ответах."""
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

REPO = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which('swiftc'), 'swiftc is unavailable')
class AdminIPCTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='aivpn-ipc-')
        cls.root = Path(cls.scratch.name)
        main = cls.root / 'main.swift'
        main.write_text('''import Foundation
if CommandLine.arguments[1] == "tcp" {
    let reply = LocalAdminIPC.clientRequest("fixture:role", port: UInt16(CommandLine.arguments[2])!, timeout: 1)
    print(reply?.utf8.count ?? -1)
} else {
let response = LocalAdminIPC.request(["action": "admin", "key": "fixture-session", "service": "role"], path: CommandLine.arguments[1], timeout: 1)
print(response?["status"] as? String ?? "nil")
}
''')
        cls.client = cls.root / 'client'
        subprocess.run(['swiftc', str(REPO / 'platforms/macos/LocalAdminIPC.swift'), str(main), '-o', str(cls.client)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def exercise(self, mode):
        path = str(self.root / f'{mode}.sock')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(path)
        listener.listen(1)
        received = []
        failures = []

        def exact(peer, length):
            result = b''
            while len(result) < length:
                part = peer.recv(length - len(result))
                if not part:
                    raise AssertionError('truncated request')
                result += part
            return result

        def serve():
            try:
                with listener.accept()[0] as peer:
                    size = struct.unpack('>I', exact(peer, 4))[0]
                    received.append(json.loads(exact(peer, size)))
                    if mode == 'fragmented':
                        for part in [b'{"sta', b'tus":"', b'ok"}']:
                            peer.sendall(part)
                    elif mode == 'timeout':
                        peer.sendall(b'{"status":"ok"}')
                        time.sleep(1.5)
                    elif mode == 'oversized':
                        try:
                            peer.sendall(b'x' * (2 * 1024 * 1024 + 1))
                        except BrokenPipeError:
                            pass
                    else:
                        peer.sendall(b'{"status":')
            except Exception as error:
                failures.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        output = subprocess.run([str(self.client), path], check=True, capture_output=True, text=True, timeout=5)
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(received, [{'action': 'admin', 'key': 'fixture-session', 'service': 'role'}])
        return output.stdout.strip()

    def test_fragmented_response(self):
        self.assertEqual(self.exercise('fragmented'), 'ok')

    def test_partial_response_is_rejected(self):
        self.assertEqual(self.exercise('truncated'), 'nil')

    def test_timeout_does_not_accept_a_partial_stream(self):
        self.assertEqual(self.exercise('timeout'), 'nil')

    def test_response_allocation_is_bounded(self):
        self.assertEqual(self.exercise('oversized'), 'nil')

    def test_tcp_large_fragmented_reply_and_truncated_frame(self):
        for truncated in [False, True]:
            with self.subTest(truncated=truncated), socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                failures = []

                def serve():
                    try:
                        with listener.accept()[0] as peer:
                            request = b''
                            while len(request) < 4:
                                request += peer.recv(4 - len(request))
                            size = struct.unpack('>I', request)[0]
                            request = b''
                            while len(request) < size:
                                request += peer.recv(size - len(request))
                            self.assertEqual(request, b'fixture:role')
                            peer.sendall(struct.pack('>I', 350000))
                            body = b'x' * (349999 if truncated else 350000)
                            for start in range(0, len(body), 701):
                                peer.sendall(body[start:start + 701])
                    except Exception as error:
                        failures.append(error)

                worker = threading.Thread(target=serve)
                worker.start()
                output = subprocess.run([str(self.client), 'tcp', str(listener.getsockname()[1])],
                                        check=True, capture_output=True, text=True, timeout=5)
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(failures, [])
                self.assertEqual(output.stdout.strip(), '-1' if truncated else '350000')


if __name__ == '__main__':
    unittest.main()
