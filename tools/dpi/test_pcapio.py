"""Регрессии чтения полных и фрагментированных UDP-захватов."""

import struct
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pcapio


def capture(packets):
    result = bytearray(struct.pack("<IHHiIII", pcapio.PCAP_MAGIC, 2, 4, 0, 0, 65535, 101))
    for packet in packets:
        result.extend(struct.pack("<IIII", 1, 0, len(packet), len(packet)))
        result.extend(packet)
    return bytes(result)


def udp(payload):
    return struct.pack("!HHHH", 40000, 60000, len(payload) + 8, 0) + payload


def ipv4(body, offset=0, more=False, ident=7):
    header = bytearray(20)
    header[0], header[8], header[9] = 0x45, 64, 17
    header[2:4] = (len(body) + 20).to_bytes(2, "big")
    header[4:6] = ident.to_bytes(2, "big")
    header[6:8] = ((offset // 8) | (0x2000 if more else 0)).to_bytes(2, "big")
    header[12:16], header[16:20] = bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2))
    header[10:12] = pcapio._ip_checksum(header).to_bytes(2, "big")
    return bytes(header) + body


def ipv6(body, next_header):
    header = bytearray(40)
    header[0], header[6], header[7] = 0x60, next_header, 64
    header[4:6] = len(body).to_bytes(2, "big")
    header[8:24], header[24:40] = bytes.fromhex("20010db8000000000000000000000001"), bytes.fromhex("20010db8000000000000000000000002")
    return bytes(header) + body


def v6_fragment(body, offset=0, more=False):
    return ipv6(struct.pack("!BBHI", 17, 0, offset | int(more), 7) + body, 44)


class PcapTests(unittest.TestCase):
    def read(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            path.write_bytes(data)
            return pcapio.read_udp_payloads(str(path))

    def test_both_byte_orders_and_timestamp_precisions_are_supported(self):
        packet = ipv4(udp(b"data"))
        for endian in ("<", ">"):
            for magic in (pcapio.PCAP_MAGIC, 0xA1B23C4D):
                header = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 101)
                record = struct.pack(endian + "IIII", 1, 100, len(packet), len(packet))
                self.assertEqual(self.read(header + record + packet), [b"data"])

    def test_ipv4_fragments_can_arrive_out_of_order(self):
        payload = bytes(range(64))
        body = udp(payload)
        packets = [ipv4(body[24:], 24), ipv4(body[:24], 0, True)]
        self.assertEqual(self.read(capture(packets)), [payload])

    def test_ipv6_extensions_fragments_and_atomic_fragment(self):
        payload = bytes(range(64))
        body = udp(payload)
        extensions = bytes([60, 0]) + bytes(6) + bytes([17, 0]) + bytes(6)
        self.assertEqual(self.read(capture([ipv6(extensions + body, 0)])), [payload])
        self.assertEqual(self.read(capture([v6_fragment(body[24:], 24), v6_fragment(body[:24], 0, True)])), [payload])
        self.assertEqual(self.read(capture([v6_fragment(body)])), [payload])
        # По RFC 8200 Next Header берется из нулевого фрагмента.
        changed = bytearray(v6_fragment(body[24:], 24))
        changed[40] = 60
        self.assertEqual(self.read(capture([bytes(changed), v6_fragment(body[:24], 0, True)])), [payload])

    def test_overlapping_missing_and_excessive_fragments_are_rejected(self):
        body = udp(bytes(range(64)))
        for packets in [
            [ipv4(body[:24], 0, True)],
            [ipv4(body[:24], 0, True), ipv4(body[8:32], 8, True)],
            [ipv4(body[:24], 0, True, ident=index) for index in range(65)],
            [v6_fragment(body[:24], 0, True), v6_fragment(body[:24], 0, True)],
        ]:
            with self.subTest(packets=len(packets)), self.assertRaises(ValueError):
                self.read(capture(packets))

    def test_truncated_records_ip_udp_and_extension_headers_are_rejected(self):
        valid = capture([ipv4(udp(b"data"))])
        for data in [
            valid[:-1], valid + b"x", capture([b"\x45"]),
            capture([ipv4(b"123")]), capture([ipv4(struct.pack("!HHHH", 1, 2, 100, 0))]),
            capture([ipv6(bytes([17, 1]) + bytes(6), 0)]),
        ]:
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                self.read(data)


if __name__ == "__main__":
    unittest.main()
