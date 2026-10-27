"""Чтение и запись классического PCAP с RAW IP (DLT 101).

В файлы репозитория полезная нагрузка не пишется. Временный PCAP для учителя
nDPI создается только в /tmp и удаляется сразу после вердикта.
"""

from __future__ import annotations

import struct


PCAP_MAGIC = 0xA1B2C3D4
DLT_RAW = 101


def _ip_checksum(header: bytes) -> int:
    total = sum(
        int.from_bytes(header[index : index + 2], "big") for index in range(0, len(header), 2)
    )
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class _Fragments:
    def __init__(self):
        self.pending = {}

    def add(self, key, offset, more, payload, now, metadata):
        if not payload or offset + len(payload) > 65535 or (more and len(payload) % 8):
            raise ValueError("Некорректный размер IP-фрагмента")
        if any(now - item["created"] > 60 for item in self.pending.values()):
            raise ValueError("Истек срок сборки IP-фрагментов")
        if key not in self.pending:
            if len(self.pending) >= 64:
                raise ValueError("Слишком много незавершенных IP-пакетов")
            self.pending[key] = {"created": now, "chunks": {}, "total": None, "metadata": metadata if offset == 0 else None}
        item = self.pending[key]
        if offset == 0:
            if item["metadata"] is not None and item["metadata"] != metadata:
                raise ValueError("Конфликт заголовков первых IP-фрагментов")
            item["metadata"] = metadata
        end = offset + len(payload)
        if item["total"] is not None and end > item["total"]:
            raise ValueError("IP-фрагмент выходит за конец пакета")
        for previous, chunk in item["chunks"].items():
            if offset < previous + len(chunk) and previous < end:
                if key[0] == 4 and previous == offset and chunk == payload:
                    return None
                raise ValueError("Перекрывающиеся IP-фрагменты")
        if not more:
            if item["total"] is not None and item["total"] != end:
                raise ValueError("Конфликт размера IP-пакета")
            if any(start + len(chunk) > end for start, chunk in item["chunks"].items()):
                raise ValueError("Прежний IP-фрагмент выходит за конец пакета")
            item["total"] = end
        item["chunks"][offset] = payload
        if item["total"] is None:
            return None
        cursor = 0
        chunks = []
        for start, chunk in sorted(item["chunks"].items()):
            if start != cursor:
                return None
            chunks.append(chunk)
            cursor += len(chunk)
        if cursor != item["total"]:
            return None
        del self.pending[key]
        return b"".join(chunks), item["metadata"]


def _udp(src, dst, payload):
    if len(payload) < 8:
        raise ValueError("Усеченный заголовок UDP")
    sport, dport, length = struct.unpack_from("!HHH", payload)
    if length < 8 or length > len(payload):
        raise ValueError("Усеченный пакет или некорректная длина UDP")
    return (src, dst, sport, dport), payload[8:length]


def _ipv6_body(next_header, body, src, dst, fragments, now, depth=0, allow_fragment=True, prefix_length=0):
    # RFC 8200: длины расширений и смещения относятся к фрагментируемой части.
    while depth <= 8:
        if next_header == 17:
            return _udp(src, dst, body)
        if next_header in (0, 43, 60, 51):
            if depth == 8:
                raise ValueError("Слишком длинная цепочка заголовков IPv6")
            if len(body) < 2:
                raise ValueError("Усеченный заголовок расширения IPv6")
            length = (body[1] + (2 if next_header == 51 else 1)) * (4 if next_header == 51 else 8)
            if length > len(body):
                raise ValueError("Некорректная длина расширения IPv6")
            prefix_length += length
            next_header, body = body[0], body[length:]
            depth += 1
        elif next_header == 44:
            if not allow_fragment or len(body) < 8:
                raise ValueError("Некорректный заголовок фрагмента IPv6")
            following = body[0]
            flags = int.from_bytes(body[2:4], "big")
            offset, more = flags & 0xfff8, bool(flags & 1)
            fragment = body[8:]
            if offset or more:
                key = (6, src, dst, body[4:8])
                assembled = fragments.add(key, offset, more, fragment, now, (following, depth, prefix_length))
                if assembled is None:
                    return None
                fragment, (following, depth, prefix_length) = assembled
                if prefix_length + len(fragment) > 65535:
                    raise ValueError("Собранный пакет IPv6 слишком велик")
            return _ipv6_body(following, fragment, src, dst, fragments, now, depth + 1, False, prefix_length)
        else:
            return None
    raise ValueError("Слишком длинная цепочка заголовков IPv6")


def _udp_from_packet(packet: bytes, fragments: _Fragments, now: float):
    if not packet:
        raise ValueError("Пустой IP-пакет")
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            raise ValueError("Усеченный заголовок IPv4")
        ihl = (packet[0] & 0x0F) * 4
        total = int.from_bytes(packet[2:4], "big")
        if ihl < 20 or total < ihl or total > len(packet):
            raise ValueError("Некорректная длина IPv4")
        if packet[9] != 17:
            return None
        src, dst = packet[12:16], packet[16:20]
        flags = int.from_bytes(packet[6:8], "big")
        offset, more = (flags & 0x1fff) * 8, bool(flags & 0x2000)
        payload = packet[ihl:total]
        if offset or more:
            assembled = fragments.add((4, src, dst, packet[4:6], 17), offset, more, payload, now, ihl)
            if assembled is None:
                return None
            payload, first_ihl = assembled
            if first_ihl + len(payload) > 65535:
                raise ValueError("Собранный пакет IPv4 слишком велик")
        return _udp(src, dst, payload)
    if version == 6:
        if len(packet) < 40:
            raise ValueError("Усеченный заголовок IPv6")
        total = 40 + int.from_bytes(packet[4:6], "big")
        if total > len(packet):
            raise ValueError("Усеченный пакет IPv6")
        return _ipv6_body(packet[6], packet[40:total], packet[8:24], packet[24:40], fragments, now)
    raise ValueError("Неизвестная версия IP")


def _scan_udp(path: str) -> tuple[list[bytes], list[tuple[bool, list[bytes]]]]:
    with open(path, "rb") as handle:
        data = handle.read()
    if len(data) < 24:
        raise ValueError(f"слишком короткий PCAP: {path}")
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if data[:4] not in formats:
        raise ValueError(f"нужен классический PCAP, не pcapng: {path}")
    endian, timestamp_scale = formats[data[:4]]
    _magic, _major, _minor, _tz, _sig, _snap, link = struct.unpack_from(endian + "IHHiIII", data, 0)
    if link != DLT_RAW:
        raise ValueError(f"нужен DLT 101 (RAW IP), получен {link}: {path}")
    flat: list[bytes] = []
    grouped: dict[tuple[bytes, bytes, int, int], list[bytes]] = {}
    order: list[tuple[bytes, bytes, int, int]] = []
    fragments = _Fragments()
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("Усеченный заголовок записи PCAP")
        _ts, _fraction, incl, _orig = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if incl > _orig or offset + incl > len(data):
            raise ValueError("Усеченная запись PCAP")
        packet = data[offset : offset + incl]
        offset += incl
        parsed = _udp_from_packet(packet, fragments, _ts + _fraction / timestamp_scale)
        if parsed is None:
            continue
        key, payload = parsed
        flat.append(payload)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(payload)
    if fragments.pending:
        raise ValueError("PCAP содержит незавершенные IP-фрагменты")
    # Инициатор определяется первым направлением обмена, а не номером порта.
    # Экспортер начинает захват с клиентского bootstrap.
    initiators = set()
    directions: list[tuple[bool, list[bytes]]] = []
    for key in order:
        src, dst, sport, dport = key
        reverse = (dst, src, dport, sport)
        upstream = reverse not in initiators
        if upstream:
            initiators.add(key)
        directions.append((upstream, grouped[key]))
    return flat, directions


def read_udp_payloads(path: str) -> list[bytes]:
    """Полезные нагрузки UDP из RAW-IP PCAP, в порядке файла. Адреса не возвращаются."""
    flat, _directions = _scan_udp(path)
    return flat


def read_udp_directions(path: str) -> list[tuple[bool, list[bytes]]]:
    """Потоки UDP по одному направлению, в порядке первого кадра.

    Первый элемент истинен только для восходящего направления.
    Список нагрузок сохраняет порядок и повторы кадров этого потока.
    """
    _flat, directions = _scan_udp(path)
    return directions


def write_directed_udp_pcap(
    path: str, frames: list[tuple[bytes, bytes, int, int, bytes]]
) -> None:
    """IPv4/UDP, DLT 101. Кадр: адрес источника, адрес назначения, порты, нагрузка."""
    out = bytearray()
    out += struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, DLT_RAW)
    for index, (src, dst, sport, dport, payload) in enumerate(frames):
        if len(src) != 4 or len(dst) != 4:
            raise ValueError("направленный PCAP пишет только IPv4")
        if not 0 <= sport <= 65535 or not 0 <= dport <= 65535:
            raise ValueError("порт UDP вне диапазона")
        total = 28 + len(payload)
        header = bytearray(28)
        header[0] = 0x45
        header[2:4] = (total).to_bytes(2, "big")
        header[8] = 64
        header[9] = 17
        header[12:16] = src
        header[16:20] = dst
        header[10:12] = _ip_checksum(bytes(header[:20])).to_bytes(2, "big")
        header[20:22] = int(sport).to_bytes(2, "big")
        header[22:24] = int(dport).to_bytes(2, "big")
        header[24:26] = (8 + len(payload)).to_bytes(2, "big")
        header += payload
        usec = (index * 1000) % 1_000_000
        sec = 1 + (index * 1000) // 1_000_000
        out += struct.pack("<IIII", sec, usec, len(header), len(header))
        out += header
    with open(path, "wb") as handle:
        handle.write(out)


def write_uplink_pcap(path: str, payloads: list[bytes]) -> None:
    """Один клиентский uplink: IPv4/UDP, DLT 101, без полезной нагрузки в имени."""
    frames = [
        (bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2)), 50000, 443, payload) for payload in payloads
    ]
    write_directed_udp_pcap(path, frames)
