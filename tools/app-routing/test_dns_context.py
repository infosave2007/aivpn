"""Проверки границ протокола тестового NSS-посредника без сетевых привилегий."""

from collections import deque
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

import dns_context
from linux_probe import dns_answer


def request(name="example.aivpn.test", family=socket.AF_INET):
    return {"method": "io.systemd.Resolve.ResolveHostname", "parameters": {"name": name, "family": family}}


class FrameTests(unittest.TestCase):
    def read(self, frame):
        reader, writer = socket.socketpair()
        with reader, writer:
            writer.sendall(frame)
            writer.shutdown(socket.SHUT_WR)
            return dns_context.read_message(reader)

    def test_valid_frame(self):
        message = request()
        self.assertEqual(self.read(json.dumps(message).encode() + b"\0"), message)

    def test_invalid_frames(self):
        for frame in [b"{}", b"[1]\0", b"null\0", b"{\0", b"\xff\0", b"x" * 65537 + b"\0"]:
            with self.subTest(size=len(frame)), self.assertRaises(ValueError):
                self.read(frame)

    def test_frame_at_limit(self):
        raw = json.dumps(request()).encode()
        self.assertEqual(self.read(raw + b" " * (65535 - len(raw)) + b"\0"), request())


class ReplyTests(unittest.TestCase):
    def answer(self, message, selected=True, ready=True):
        with patch.object(dns_context, "lookup_address", return_value=[198, 51, 100, 7]) as lookup:
            reply = dns_context.reply_for(message, selected, ready)
        return reply, lookup

    def test_selected_dns_is_not_sent_to_system_when_vpn_is_down(self):
        reply, lookup = self.answer(request(), ready=False)
        self.assertEqual(reply, {"error": "io.systemd.Resolve.NetworkDown"})
        lookup.assert_not_called()

    def test_system_dns_keeps_working_when_vpn_is_down(self):
        reply, lookup = self.answer(request(), selected=False, ready=False)
        self.assertEqual(reply["parameters"]["addresses"][0]["address"], [198, 51, 100, 7])
        lookup.assert_called_once_with("example.aivpn.test", False)

    def test_selected_ipv4_query_uses_selected_upstream(self):
        reply, lookup = self.answer(request())
        self.assertEqual(reply["parameters"]["addresses"][0]["family"], socket.AF_INET)
        lookup.assert_called_once_with("example.aivpn.test", True)

    def test_valid_name_boundaries_and_unspecified_family(self):
        name = ".".join(["a" * 63] * 3 + ["b" * 61])
        reply, lookup = self.answer(request(name, 0))
        self.assertIn("parameters", reply)
        lookup.assert_called_once_with(name, True)
        reply, lookup = self.answer(request(name + "b"))
        self.assertIn("error", reply)
        lookup.assert_not_called()

    def test_invalid_input_does_not_reach_upstream(self):
        messages = [request("non-ascii-\u0438.aivpn.test"), request("a..test"), request("x" * 64 + ".test"),
                    request("a\0.test"), request("a b.test"), request(""),
                    request("a.test", socket.AF_INET6), request(123), {"parameters": []},
                    {"method": "not-supported", "parameters": {}}]
        for message in messages:
            with self.subTest(message=message):
                reply, lookup = self.answer(message)
                self.assertIn("error", reply)
                lookup.assert_not_called()


class UpstreamTests(unittest.TestCase):
    def query(self, change=None):
        with patch.object(dns_context.socket, "socket") as factory:
            upstream = factory.return_value.__enter__.return_value

            def response(_size):
                query = upstream.send.call_args.args[0]
                answer = dns_answer(query, "198.51.100.7")
                return change(answer) if change else answer

            upstream.recv.side_effect = response
            return dns_context.lookup_address("a.aivpn.test", True)

    def test_accepts_test_endpoint_a_record(self):
        self.assertEqual(self.query(), [198, 51, 100, 7])

    def test_rejects_mismatched_id_truncated_and_unexpected_answers(self):
        changes = [lambda reply: reply[:1], lambda reply: reply + b"extra",
                   lambda reply: bytes([reply[0] ^ 1]) + reply[1:],
                   lambda reply: reply[:3] + b"\x83" + reply[4:]]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.query(change)


class BrokerTests(unittest.TestCase):
    def test_bad_connection_does_not_break_next_request(self):
        state = {"ready": False, "requests": deque(maxlen=128), "rejected": 0, "stop": False}
        group = Path(f"/proc/{os.getpid()}/cgroup").read_text().strip().split(":", 2)[2]
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "resolve")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(8)
                worker = threading.Thread(target=dns_context.serve, args=(listener, group, state), daemon=True)
                worker.start()
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                        connection.settimeout(3)
                        connection.connect(path)
                        connection.sendall(b"{\0")
                        self.assertEqual(connection.recv(1), b"")
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                        connection.settimeout(3)
                        connection.connect(path)
                        connection.sendall(json.dumps(request()).encode() + b"\0")
                        reply = json.loads(connection.recv(4096).rstrip(b"\0"))
                    self.assertEqual(reply, {"error": "io.systemd.Resolve.NetworkDown"})
                    self.assertEqual(state["rejected"], 1)
                    self.assertEqual(state["requests"][0], {"pid": os.getpid(), "uid": os.getuid(), "selected": True})
                finally:
                    state["stop"] = True
                    listener.shutdown(socket.SHUT_RDWR)
                    worker.join(timeout=3)
                self.assertFalse(worker.is_alive())


if __name__ == "__main__":
    unittest.main()
