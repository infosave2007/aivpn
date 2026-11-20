"""Передает проверяемые данные пробе скорости через отдельное соединение стенда."""
import time

MAX_BYTES = 256 * 1024 * 1024
MAX_RATE = 125_000_000
BLOCK = 65536


def _read_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            return None
        result.extend(part)
    return result


def bulk_connection(connection,peer):
    connection.settimeout(10)
    try:
        header = _read_exact(connection, 9)
        if header is None:
            return
        kind = header[:1]
        total = int.from_bytes(header[1:], "big")
        if kind not in (b"U", b"D", b"P") or not 0 < total <= MAX_BYTES:
            return
        rate = 0
        if kind == b"P":
            value = _read_exact(connection, 8)
            if value is None:
                return
            rate = int.from_bytes(value, "big")
            if not 0 < rate <= MAX_RATE or total > rate * 120:
                return
        pattern = bytes(range(251))
        observed = ("observed=" + peer[0]).encode("ascii").ljust(64, b"\0")
        offset = 0
        if kind != b"U":
            connection.sendall(observed)
        started = time.monotonic()
        while offset < total:
            if kind == b"U":
                data = connection.recv(min(BLOCK, total - offset))
                if not data:
                    return
                width = len(data)
            else:
                width = min(BLOCK, total - offset)
                if rate:
                    delay = (offset + width) / rate - (time.monotonic() - started)
                    if delay > 0:
                        time.sleep(delay)
            expected = (pattern * ((width + 500) // 251 + 1))[
                offset % 251:offset % 251 + width
            ]
            if kind == b"U":
                if data != expected:
                    return
            else:
                connection.sendall(expected)
            offset += width
        if kind == b"U":
            connection.sendall(observed)
    except OSError:
        pass
    finally:
        connection.close()
