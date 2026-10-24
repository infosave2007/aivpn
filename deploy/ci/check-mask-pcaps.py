#!/usr/bin/env python3
"""Проверяет внешний двусторонний трафик живого handshake, а не его заготовку."""
import json
import binascii
import pathlib
import re
import struct
import subprocess
import sys
import tempfile


def packets(path):
    data = path.read_bytes()
    assert data[:4] == bytes.fromhex("d4c3b2a1"), path
    assert struct.unpack_from("<I", data, 20)[0] == 101, path
    offset = 24
    while offset < len(data):
        assert offset + 16 <= len(data), path
        size, original = struct.unpack_from("<II", data, offset + 8)
        end = offset + 16 + size
        assert size == original and end <= len(data), path
        packet = data[offset + 16:end]
        assert packet[0] == 0x45 and packet[9] == 17, path
        assert struct.unpack_from(">H", packet, 2)[0] == len(packet), path
        assert not struct.unpack_from(">H", packet, 6)[0] & 0x3FFF, path
        assert struct.unpack_from(">H", packet, 24)[0] == len(packet) - 20, path
        yield packet[28:], data[offset:end], packet[12:16]
        offset = end


def stun(payload):
    assert len(payload) >= 24 and len(payload) % 4 == 0
    assert payload[:2] == bytes.fromhex("0011")
    assert payload[4:8] == bytes.fromhex("2112a442")
    assert struct.unpack_from(">H", payload, 2)[0] == len(payload) - 20
    offset = 20
    while offset < len(payload):
        assert offset + 4 <= len(payload)
        length = struct.unpack_from(">H", payload, offset + 2)[0]
        offset += 4 + ((length + 3) & ~3)
        assert offset <= len(payload)
    assert offset == len(payload)


def classify(ndpi, path, expected):
    output = subprocess.run([ndpi, "-i", str(path), "-d", "-v", "2"],
                            check=True, capture_output=True, text=True, timeout=60).stdout
    flows = [line for line in output.splitlines() if "[proto:" in line]
    assert flows and all("[Confidence: DPI]" in line and any(
        expected in value.split(".")
        for value in re.findall(r"\[proto: [0-9.]+/([^\]]+)\]", line))
        for line in flows), (path, flows)


# Коды атрибутов совпадают с stun, которым пользуется turn_wire.
USERNAME = 0x0006
INTEGRITY = 0x0008
ERROR_CODE = 0x0009
CHANNEL_NUMBER = 0x000C
LIFETIME = 0x000D
XOR_PEER = 0x0012
REALM = 0x0014
NONCE = 0x0015
XOR_RELAYED = 0x0016
REQUESTED_TRANSPORT = 0x0019
XOR_MAPPED = 0x0020
FINGERPRINT = 0x8028
TURN_CHANNEL = 0x4000
TURN_NAMES = {3: "Allocate", 4: "Refresh", 8: "Permission", 9: "ChannelBind"}
SPOOF_EXPECTED = {
    "WebRTC_STUN": "STUN",
    "WebRTC_DTLS_SRTP": "RTC",
    "WebRTC_TURN_DTLS_SRTP": "TURN",
    "WebRTC_SDES_SRTP": "SDES",
    "QUIC": "QUIC",
}


def dpi_name(expected):
    # Снаружи и обычный WebRTC, и TURN для nDPI выглядят как STUN.
    return "STUN" if expected in ("RTC", "TURN", "SDES") else expected


def expect_stages(expected, stages):
    if expected == "RTC":
        assert {"ICE", "DTLS", "SRTP"} <= stages, stages
    elif expected == "TURN":
        # Refresh ставится таймером на 180 секунд, короткий захват его не содержит.
        assert {"Allocate", "Permission", "ChannelBind", "ICE", "DTLS", "SRTP"} <= stages, stages
    elif expected == "SDES":
        assert {"ICE", "SRTP"} <= stages and "DTLS" not in stages, stages


def stun_method(value):
    return (value & 0x000F) | ((value >> 1) & 0x0070) | ((value >> 2) & 0x0F80)


def stun_class(value):
    return ((value >> 4) & 0x1) | ((value >> 7) & 0x2)


def channel_payload(payload):
    # Маска всегда использует канал 0x4000. Длина не включает нулевой хвост до кратности 4.
    assert len(payload) >= 4
    number, length = struct.unpack_from(">HH", payload, 0)
    assert number == TURN_CHANNEL
    assert 1 <= length <= 1376
    padded = (length + 3) & ~3
    assert len(payload) in (4 + length, 4 + padded)
    # Отправитель маски padding не добавляет. Если хвост есть, он обязан быть нулевым.
    if len(payload) != 4 + length:
        assert payload[4 + length:] == bytes(padded - length)
    return payload[4:4 + length]


def stun_attributes(payload):
    # Повтор, обрезка, атрибут после integrity и чужой CRC32 сюда не проходят.
    # Совпадение CRC32 не заменяет проверку HMAC.
    assert 20 <= len(payload) <= 1380 and len(payload) % 4 == 0
    assert payload[0] & 0xC0 == 0 and payload[4:8] == bytes.fromhex("2112a442")
    assert struct.unpack_from(">H", payload, 2)[0] == len(payload) - 20
    offset, attributes, integrity = 20, {}, False
    while offset < len(payload):
        assert offset + 4 <= len(payload) and len(attributes) < 64
        kind, length = struct.unpack_from(">HH", payload, offset)
        end = offset + 4 + ((length + 3) & ~3)
        assert end <= len(payload) and kind not in attributes
        assert payload[offset + 4 + length:end] == bytes(end - (offset + 4 + length))
        if integrity:
            assert kind == FINGERPRINT
        value = payload[offset + 4:offset + 4 + length]
        if kind == INTEGRITY:
            assert length == 20
            integrity = True
        if kind == FINGERPRINT:
            assert length == 4 and end == len(payload)
            assert int.from_bytes(value, "big") == (binascii.crc32(payload[:offset]) ^ 0x5354554e)
        attributes[kind] = value
        offset = end
    assert offset == len(payload) and FINGERPRINT in attributes
    return attributes


def token(attributes, kind, low, high, separator=False):
    value = attributes.get(kind)
    assert value is not None and low <= len(value) <= high
    assert all(0x21 <= byte <= 0x7E for byte in value)
    assert not separator or b":" not in value
    return value


def long_term(attributes):
    token(attributes, USERNAME, 4, 64, separator=True)
    token(attributes, REALM, 1, 64, separator=True)
    token(attributes, NONCE, 1, 128)
    assert len(attributes.get(INTEGRITY, b"")) == 20


def xor_address(value):
    assert value is not None and len(value) in (8, 20) and value[0] == 0
    assert int.from_bytes(value[:2], "big") == (1 if len(value) == 8 else 2)


def error_status(value):
    assert value is not None and len(value) >= 4 and value[0] == value[1] == 0
    assert 3 <= value[2] <= 6 and value[3] <= 99
    return value[2] * 100 + value[3]


def turn_request(method, attributes):
    if method == 3:
        assert attributes.get(REQUESTED_TRANSPORT) == bytes.fromhex("11000000")
        if LIFETIME in attributes:
            assert len(attributes[LIFETIME]) == 4
        if any(kind in attributes for kind in (USERNAME, REALM, NONCE, INTEGRITY)):
            long_term(attributes)
        return
    if method == 4:
        assert len(attributes.get(LIFETIME, b"")) == 4
    elif method == 8:
        xor_address(attributes.get(XOR_PEER))
    else:
        assert attributes.get(CHANNEL_NUMBER) == bytes.fromhex("40000000")
        xor_address(attributes.get(XOR_PEER))
    long_term(attributes)


def turn_success(method, attributes):
    assert len(attributes.get(INTEGRITY, b"")) == 20
    if method in (3, 4):
        assert len(attributes.get(LIFETIME, b"")) == 4
    if method == 3:
        xor_address(attributes.get(XOR_RELAYED))
        xor_address(attributes.get(XOR_MAPPED))


def turn_error(attributes):
    code = error_status(attributes.get(ERROR_CODE))
    if code in (401, 438):
        assert INTEGRITY not in attributes
        token(attributes, REALM, 1, 64, separator=True)
        token(attributes, NONCE, 1, 128)
    else:
        assert len(attributes.get(INTEGRITY, b"")) == 20


def turn_control(payload):
    attributes = stun_attributes(payload)
    method = stun_method(struct.unpack_from(">H", payload, 0)[0])
    kind = stun_class(struct.unpack_from(">H", payload, 0)[0])
    assert method in TURN_NAMES and kind in (0, 2, 3)
    if kind == 0:
        turn_request(method, attributes)
    elif kind == 2:
        turn_success(method, attributes)
    else:
        turn_error(attributes)
    return TURN_NAMES[method]


def rtp_or_rtcp(payload, auth_tag=16):
    # Размер тега задается профилем. Сам тег и SRTCP здесь не вскрываются.
    assert 128 <= payload[0] <= 191 and len(payload) >= 12 + auth_tag
    if 192 <= payload[1] <= 223:
        size = (int.from_bytes(payload[2:4], "big") + 1) * 4
        assert 8 <= size <= len(payload)
        return "RTCP"
    assert 96 <= (payload[1] & 0x7F) <= 127
    assert int.from_bytes(payload[8:12], "big") != 0
    return "SRTP"


def rtc(payload, wrapped=False, auth_tag=16):
    # Здесь только раскладка кадра. HMAC, AEAD и replay не доказываются:
    # их закрывает отдельный живой двусторонний прогон.
    assert payload and len(payload) <= 1380
    if not wrapped and payload[0] & 0xC0 == 0x40:
        kind = rtc(channel_payload(payload), True, auth_tag)
        assert kind in ("ICE", "DTLS", "SRTP", "RTCP")
        return kind
    if payload[:2] == bytes.fromhex("0011"):
        stun(payload)
        return "bootstrap"
    if payload[0] <= 3:
        if stun_method(int.from_bytes(payload[:2], "big")) in TURN_NAMES:
            return turn_control(payload)
        assert payload[:2] in [bytes.fromhex("0001"), bytes.fromhex("0101")]
        assert len(payload) >= 20 and len(payload) % 4 == 0
        assert payload[4:8] == bytes.fromhex("2112a442")
        assert struct.unpack_from(">H", payload, 2)[0] == len(payload) - 20
        offset, attributes = 20, {}
        while offset < len(payload):
            assert offset + 4 <= len(payload)
            kind, length = struct.unpack_from(">HH", payload, offset)
            end = offset + 4 + ((length + 3) & ~3)
            assert end <= len(payload) and kind not in attributes
            attributes[kind] = payload[offset + 4:offset + 4 + length]
            if kind == 0x8028:
                assert length == 4 and end == len(payload)
                assert int.from_bytes(attributes[kind], "big") == (binascii.crc32(payload[:offset]) ^ 0x5354554e)
            offset = end
        assert len(attributes.get(0x0008, b"")) == 20
        assert len(attributes.get(0x8028, b"")) == 4
        if payload[:2] == bytes.fromhex("0001"):
            assert attributes.get(0x0006) and len(attributes.get(0x0024, b"")) == 4
        return "ICE"
    if 20 <= payload[0] <= 63:
        offset = 0
        while offset < len(payload):
            assert offset + 13 <= len(payload)
            assert 20 <= payload[offset] <= 25 and payload[offset + 1:offset + 3] == bytes.fromhex("fefd")
            offset += 13 + int.from_bytes(payload[offset + 11:offset + 13], "big")
            assert offset <= len(payload)
        return "DTLS"
    return rtp_or_rtcp(payload, auth_tag)


def check(path, expected, ndpi):
    records = list(packets(path))
    assert records and {record[2] for record in records} == {
        bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])}, path
    stages = set()
    for payload, _, source in records:
        assert len(payload) <= 1380, (path, len(payload))
        if expected in ("RTC", "TURN", "SDES"):
            if expected == "SDES":
                assert payload[0] <= 3 or 128 <= payload[0] <= 191
            elif expected == "RTC":
                assert not 64 <= payload[0] <= 127
            elif payload[:2] != bytes.fromhex("0011") and not 64 <= payload[0] <= 127:
                assert payload[0] <= 3 and stun_method(int.from_bytes(payload[:2], "big")) in TURN_NAMES
            stages.add(rtc(payload, auth_tag=10 if expected == "SDES" else 16))
        elif expected == "STUN":
            stun(payload)
        else:
            assert payload[0] & 0x40, path
            if payload[0] & 0xF0 == 0xC0:
                assert payload[1:5] == bytes([0, 0, 0, 1]), path
                # RFC 9000: серверный Initial только с ACK может быть короче 1200.
                if source == bytes([192, 0, 2, 1]):
                    assert len(payload) >= 1200, path
    malformed = subprocess.run(["tshark", "-n", "-r", str(path), "-Y", "_ws.malformed",
                                "-T", "fields", "-e", "frame.number", "-e", "_ws.expert.message"],
                               check=True, capture_output=True, text=True, timeout=60).stdout.strip()
    assert not malformed, (path, malformed)
    expect_stages(expected, stages)
    classify(ndpi, path, dpi_name(expected))
    # Первый пакет тоже обязан определяться по DPI, без помощи позднего decoy.
    with tempfile.TemporaryDirectory(prefix="aivpn-first-packet-") as directory:
        first = pathlib.Path(directory) / "first.pcap"
        first.write_bytes(path.read_bytes()[:24] + records[0][1])
        classify(ndpi, first, dpi_name(expected))


def main():
    masks, captures, ndpi = map(pathlib.Path, sys.argv[1:])
    checked = 0
    minimum = 0
    for source in sorted(masks.glob("*.json")):
        mask = json.loads(source.read_text())
        expected = SPOOF_EXPECTED[mask["spoof_protocol"]]
        paths = sorted(captures.glob(mask["mask_id"] + "-*.pcap"))
        required = [(a, b, 20, "false") for a, b in [(0, 0), (1, 0), (2, 0), (0, 2), (2, 2)]]
        if mask["mask_id"] in ["webrtc_zoom_v3", "quic_https_v2"]:
            required += [(1, 2, rtt, "true") for rtt in [100, 500]]
        minimum += len(required)
        for a, b, rtt, duplicate in required:
            name = f"{mask['mask_id']}-init{a}-hello{b}-rtt{rtt}-dup{duplicate}.pcap"
            assert (captures / name).is_file(), (mask["mask_id"], "Нет сценария", name)
        for path in paths:
            if path.stem.endswith("-switch"):
                continue
            check(path, expected, str(ndpi))
            checked += 1
        print(f"mask-gate: {mask['mask_id']}: PASS ({len(paths)} PCAP)", flush=True)
    assert checked >= minimum, (checked, minimum)
    print(f"mask-gate: проверено {checked} двусторонних потоков и их первых пакетов")


if __name__ == "__main__":
    main()
