"""Считает обновления действующей регистрации транспорта без записи в карты BPF."""

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import struct
import sys
import time


def observe(pid):
    if platform.machine() != "x86_64" or not 1 < pid < 2**31:
        raise RuntimeError("Проба требует Linux x86_64 и PID действующего работника")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def bpf(command, data):
        raw = ctypes.create_string_buffer(data)
        result = libc.syscall(321, command, raw, len(data))
        if result < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return result

    def started():
        text = Path(f"/proc/{pid}/stat").read_text()
        return int(text[text.rfind(")") + 2:].split()[19])

    def lookup(fd, key):
        value = ctypes.create_string_buffer(72)
        bpf(1, struct.pack("=IIQQQ", fd, 0, ctypes.addressof(key), ctypes.addressof(value), 0))
        return value.raw

    identity = started()
    descriptors = []
    matching = []
    try:
        paths = list(Path("/sys/fs/bpf/aivpn_app_routes").glob("*/maps/transport_sockets"))
        if len(paths) > 8:
            raise RuntimeError("Слишком много независимых карт для этой пробы")
        for path in paths:
            name = ctypes.create_string_buffer(os.fsencode(path))
            # BPF_F_RDONLY не дает пробе менять регистрацию службы.
            fd = bpf(7, struct.pack("=QII", ctypes.addressof(name), 0, 8))
            descriptors.append(fd)
            info = ctypes.create_string_buffer(256)
            bpf(15, struct.pack("=IIQ", fd, len(info), ctypes.addressof(info)))
            kind, _, key_size, value_size, capacity = struct.unpack_from("=IIIII", info.raw)
            if (kind, key_size, value_size, capacity) != (1, 8, 72, 256):
                raise RuntimeError("Схема карты транспорта изменилась")
            key = None
            for _ in range(257):
                following = ctypes.c_uint64()
                try:
                    bpf(4, struct.pack("=IIQQQ", fd, 0, ctypes.addressof(key) if key else 0,
                                       ctypes.addressof(following), 0))
                except OSError as error:
                    if error.errno == errno.ENOENT:
                        break
                    raise
                key = following
                value = lookup(fd, key)
                if struct.unpack_from("=I", value, 36)[0] == pid and struct.unpack_from("=I", value, 32)[0]:
                    matching.append((fd, key))
            else:
                raise RuntimeError("Карта транспорта меняется во время обхода")
        if len(matching) != 1:
            raise RuntimeError(f"Ожидалась одна регистрация работника, получено {len(matching)}")
        fd, key = matching[0]
        expiries, margins = [], []
        begin = time.monotonic()
        for _ in range(100):
            expiry = struct.unpack_from("=Q", lookup(fd, key), 24)[0]
            expiries.append(expiry)
            margins.append((expiry - time.monotonic_ns()) / 1e9)
            time.sleep(.01)
        if started() != identity:
            raise RuntimeError("Работник сменился во время наблюдения")
        renewals = sum(left != right for left, right in zip(expiries, expiries[1:]))
        return {
            "renewals": renewals,
            "seconds": time.monotonic() - begin,
            "min_remaining_seconds": min(margins),
            "max_remaining_seconds": max(margins),
            "expected_minimum": 2,
            "expected_maximum": 8,
            "pass": 2 <= renewals <= 8 and min(margins) > 8,
        }
    finally:
        for fd in descriptors:
            os.close(fd)


if __name__ == "__main__":
    result = observe(int(sys.argv[1]))
    print(json.dumps(result))
    raise SystemExit(0 if result["pass"] else 1)
