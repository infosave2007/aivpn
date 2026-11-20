"""Проверяет полноту PCAP без сокетов, root и изменения сети."""

import argparse
import importlib.util
from pathlib import Path
import socket
import struct
import threading
import unittest

arguments = argparse.ArgumentParser()
arguments.add_argument("--probe", type=Path, default=Path(__file__).with_name("linux_binding_probe.py"))
options, remaining = arguments.parse_known_args()
spec = importlib.util.spec_from_file_location("capture_probe", options.probe)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class CaptureTest(unittest.TestCase):
    def test_dns_frame_is_saved_even_when_the_scenario_filter_ignores_it(self):
        query = bytes.fromhex("123401000001000000000000") + b"\x04test\x03lab\x04test\0\0\x01\0\x01"
        udp = struct.pack("!HHHH", 53000, 53, 8 + len(query), 0) + query
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         socket.inet_aton("192.0.2.2"), socket.inet_aton("192.0.2.1"))
        frame = bytes(12) + b"\x08\x00" + ip + udp
        metadata = ("wan0", 0, 4)
        self.assertIsNone(probe.Capture.decode(frame, metadata))

        capture = probe.Capture.__new__(probe.Capture)
        capture.raw, capture.events, capture.stop = [], [], threading.Event()

        class OnePacket:
            def recvfrom(self, _size):
                capture.stop.set()
                return frame, metadata

        capture.read(OnePacket())
        self.assertEqual(len(capture.raw), 1)
        self.assertEqual(capture.raw[0][1], frame)
        self.assertEqual(capture.events, [])


if __name__ == "__main__":
    unittest.main(argv=[__file__, *remaining])
