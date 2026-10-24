#!/usr/bin/env python3
"""Регрессии валидатора PCAP, не требующие внешнего DPI-инструмента."""
import importlib.util
import binascii
import pathlib
import struct
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "mask_gate", pathlib.Path(__file__).with_name("check-mask-pcaps.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def stun_frame(kind, attributes, dirty=False):
    parts = []
    for key, value in attributes:
        pad = bytes((-len(value)) % 4)
        if dirty and pad:
            pad = b"\x01" + bytes(len(pad) - 1)
            dirty = False
        parts.append(struct.pack(">HH", key, len(value)) + value + pad)
    body = b"".join(parts)
    header = struct.pack(">HHI", kind, len(body) + 8, 0x2112A442) + bytes(12)
    prefix = header + body
    return prefix + struct.pack(">HHI", 0x8028, 4, binascii.crc32(prefix) ^ 0x5354554E)


def turn_auth():
    return [(6, b"user"), (0x14, b"telegram.org"), (0x15, b"nonce"), (8, bytes(20))]


class MaskGateTests(unittest.TestCase):
    def test_sdes_uses_its_ten_byte_tag_and_requires_ice_and_media(self):
        media = bytes.fromhex("806f00010000000001020304") + bytes(10)
        self.assertEqual(gate.rtc(media, auth_tag=10), "SRTP")
        with self.assertRaises(AssertionError):
            gate.rtc(media)
        self.assertEqual(gate.SPOOF_EXPECTED["WebRTC_SDES_SRTP"], "SDES")
        self.assertEqual(gate.dpi_name("SDES"), "STUN")
        gate.expect_stages("SDES", {"bootstrap", "ICE", "SRTP", "RTCP"})
        for stages in [{"ICE"}, {"SRTP"}, {"ICE", "SRTP", "DTLS"}]:
            with self.assertRaises(AssertionError):
                gate.expect_stages("SDES", stages)

    def test_turn_channel_cannot_hide_outer_allocation_or_bootstrap(self):
        for packet in [stun_frame(3, [(0x19, bytes.fromhex("11000000"))]),
                       bytes.fromhex("001100002112a442") + bytes(12)]:
            channel = bytes.fromhex("4000") + len(packet).to_bytes(2, "big") + packet
            with self.assertRaises(AssertionError):
                gate.rtc(channel)

    def test_turn_channel_is_unwrapped_and_lengths_are_checked(self):
        media = bytes.fromhex("806f00010000000001020304") + bytes(16)
        channel = bytes.fromhex("4000") + len(media).to_bytes(2, "big") + media
        self.assertEqual(gate.rtc(channel), "SRTP")
        for broken in [channel[:-1], channel + bytes(4), bytes.fromhex("8000") + channel[2:]]:
            with self.assertRaises(AssertionError):
                gate.rtc(broken)

    def test_turn_control_checks_authentication_attributes_and_fingerprint(self):
        def message(kind, attributes):
            body = b"".join(struct.pack(">HH", key, len(value)) + value + bytes((-len(value)) % 4)
                            for key, value in attributes)
            header = struct.pack(">HHI", kind, len(body) + 8, 0x2112a442) + bytes(12)
            prefix = header + body
            return prefix + struct.pack(">HHI", 0x8028, 4, binascii.crc32(prefix) ^ 0x5354554e)
        allocate = message(3, [(0x0019, bytes.fromhex("11000000"))])
        self.assertEqual(gate.rtc(allocate), "Allocate")
        authenticated = message(8, [(6, b"user"), (0x14, b"telegram.org"), (0x15, b"nonce"),
                                    (0x12, bytes.fromhex("00010001c0000201")), (8, bytes(20))])
        self.assertEqual(gate.rtc(authenticated), "Permission")
        for broken in [authenticated[:-1], message(8, [(6, b"user")]),
                       message(8, [(8, bytes(20)), (6, b"unsigned")])]:
            with self.assertRaises(AssertionError):
                gate.rtc(broken)

    def test_turn_channel_padding_and_nested_ice_dtls(self):
        media = bytes.fromhex("806f00010000000001020304") + bytes(17)
        exact = bytes.fromhex("4000") + len(media).to_bytes(2, "big") + media
        padded = bytes.fromhex("4000") + len(media).to_bytes(2, "big") + media + bytes(3)
        self.assertEqual(gate.rtc(exact), "SRTP")
        self.assertEqual(gate.rtc(padded), "SRTP")
        dirty = bytes.fromhex("4000") + len(media).to_bytes(2, "big") + media + b"\x00\x00\x01"
        ice = stun_frame(1, [(6, b"user"), (0x24, bytes.fromhex("6e000000")), (8, bytes(20))])
        dtls = bytes.fromhex("16fefd00000000000000000002") + bytes(2)
        self.assertEqual(gate.rtc(bytes.fromhex("4000") + len(ice).to_bytes(2, "big") + ice), "ICE")
        self.assertEqual(gate.rtc(bytes.fromhex("4000") + len(dtls).to_bytes(2, "big") + dtls), "DTLS")
        for broken in [dirty, bytes.fromhex("4001") + exact[2:]]:
            with self.assertRaises(AssertionError):
                gate.rtc(broken)

    def test_turn_methods_cover_auth_padding_fingerprint_and_replies(self):
        address = bytes.fromhex("00010001c0000201")
        ipv6 = bytes.fromhex("0002") + bytes(18)
        lifetime = (600).to_bytes(4, "big")
        auth = turn_auth()
        self.assertEqual(gate.rtc(stun_frame(3, [
            (0x0019, bytes.fromhex("11000000")), (0x000D, lifetime), *auth])), "Allocate")
        self.assertEqual(gate.rtc(stun_frame(4, [(0x000D, lifetime), *auth])), "Refresh")
        self.assertEqual(gate.rtc(stun_frame(8, [(6, b"user"), (0x14, b"telegram.org"),
                                                 (0x15, b"nonce"), (0x12, ipv6), (8, bytes(20))])),
                         "Permission")
        self.assertEqual(gate.rtc(stun_frame(9, [(0x000C, bytes.fromhex("40000000")),
                                                 (0x12, address), *auth])), "ChannelBind")
        self.assertEqual(gate.rtc(stun_frame(0x0103, [
            (0x0016, address), (0x0020, address), (0x000D, lifetime), (8, bytes(20))])), "Allocate")
        self.assertEqual(gate.rtc(stun_frame(0x0104, [(0x000D, lifetime), (8, bytes(20))])), "Refresh")
        self.assertEqual(gate.rtc(stun_frame(0x0108, [(8, bytes(20))])), "Permission")
        self.assertEqual(gate.rtc(stun_frame(0x0109, [(8, bytes(20))])), "ChannelBind")
        denied = stun_frame(0x0113, [
            (0x0009, bytes.fromhex("00000401") + b"Unauthorized"),
            (0x0014, b"telegram.org"), (0x0015, b"nonce")])
        self.assertEqual(gate.rtc(denied), "Allocate")
        self.assertEqual(gate.rtc(stun_frame(0x0114, [
            (0x0009, bytes.fromhex("00000400") + b"Request rejected"), (8, bytes(20))])), "Refresh")
        marked = bytearray(bytes.fromhex("806f00010000000001020304") + bytes(16))
        marked[1] |= 0x80
        self.assertEqual(gate.rtc(bytes(marked)), "SRTP")
        report = bytes.fromhex("80c90001") + b"\x11\x22\x33\x44" + bytes(20)
        self.assertEqual(gate.rtc(report), "RTCP")
        overlong = bytearray(report)
        overlong[2:4] = (30).to_bytes(2, "big")
        full = bytes.fromhex("806f00010000000001020304") + bytes(1380 - 12)
        self.assertEqual(len(full), 1380)
        self.assertEqual(gate.rtc(full), "SRTP")
        broken_crc = bytearray(stun_frame(3, [(0x0019, bytes.fromhex("11000000"))]))
        broken_crc[-1] ^= 1
        rejected = [
            stun_frame(3, [(0x0019, bytes.fromhex("06000000"))]),
            stun_frame(3, [(0x0019, bytes.fromhex("11000000")), (6, b"user")]),
            stun_frame(4, auth),
            stun_frame(4, [(0x000D, b"\x00\x00"), *auth]),
            stun_frame(8, [(6, b"us:r"), (0x14, b"telegram.org"), (0x15, b"nonce"),
                           (0x12, address), (8, bytes(20))]),
            stun_frame(8, [(6, b"user"), (0x14, b"telegram.org"), (0x15, b"nonce"),
                           (0x12, address), (8, bytes(20))], dirty=True),
            stun_frame(8, [(6, b"user"), (6, b"next"), (0x14, b"telegram.org"),
                           (0x15, b"nonce"), (0x12, address), (8, bytes(20))]),
            stun_frame(9, [(0x000C, bytes.fromhex("40010000")), (0x12, address), *auth]),
            stun_frame(0x0103, [(0x000D, lifetime), (8, bytes(20))]),
            stun_frame(0x0113, [
                (0x0009, bytes.fromhex("00000401") + b"Unauthorized"),
                (0x0014, b"telegram.org"), (0x0015, b"nonce"), (8, bytes(20))]),
            bytes(broken_crc),
            full + b"\x00",
            overlong,
        ]
        for broken in rejected:
            with self.assertRaises(AssertionError):
                gate.rtc(broken)

    def test_turn_spoof_requires_setup_and_inner_media(self):
        self.assertEqual(gate.SPOOF_EXPECTED["WebRTC_TURN_DTLS_SRTP"], "TURN")
        self.assertEqual(gate.dpi_name("TURN"), "STUN")
        self.assertEqual(gate.dpi_name("RTC"), "STUN")
        self.assertEqual(gate.dpi_name("QUIC"), "QUIC")
        gate.expect_stages("TURN", {"Allocate", "Permission", "ChannelBind", "ICE", "DTLS", "SRTP"})
        gate.expect_stages("RTC", {"ICE", "DTLS", "SRTP"})
        with self.assertRaises(AssertionError):
            gate.expect_stages("TURN", {"ICE", "DTLS", "SRTP"})

    def test_rtc_rejects_fake_dtls_and_rtp_without_authentication_tag(self):
        for packet in [bytes.fromhex("16fefd00000000000000000010") + bytes(2),
                       bytes.fromhex("806f00010000000001020304")]:
            with self.assertRaises(AssertionError):
                gate.rtc(packet)

    def test_rtc_accepts_record_structure_but_does_not_call_it_crypto_verification(self):
        self.assertEqual(gate.rtc(bytes.fromhex("16fefd00000000000000000002") + bytes(2)), "DTLS")
        self.assertEqual(gate.rtc(bytes.fromhex("806f00010000000001020304") + bytes(16)), "SRTP")

    def test_stun_rejects_truncated_attribute_and_wrong_length(self):
        packet = bytearray.fromhex("001100082112a442") + bytearray(12)
        packet += bytes.fromhex("c0720001") + bytes(4)
        gate.stun(packet)
        for position, value in [(3, 4), (23, 5)]:
            broken = packet.copy()
            broken[position] = value
            with self.assertRaises(AssertionError):
                gate.stun(broken)

    def test_pcap_rejects_truncated_record(self):
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "broken.pcap"
            path.write_bytes(header + struct.pack("<IIII", 0, 0, 100, 100))
            with self.assertRaises(AssertionError):
                list(gate.packets(path))

    def test_classifier_requires_dpi_confidence_and_expected_protocol(self):
        for output in ["", "[proto: 91/QUIC][Confidence: Match by port]",
                       "[proto: 78/STUN][Confidence: DPI]"]:
            with patch.object(gate.subprocess, "run") as run:
                run.return_value.stdout = output
                with self.assertRaises(AssertionError):
                    gate.classify("ndpiReader", pathlib.Path("capture.pcap"), "QUIC")
        with patch.object(gate.subprocess, "run") as run:
            run.return_value.stdout = "[proto: 91.223/QUIC.Google][Confidence: DPI]"
            gate.classify("ndpiReader", pathlib.Path("capture.pcap"), "QUIC")


if __name__ == "__main__":
    unittest.main()
