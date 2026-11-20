"""Снимки ресурсов настоящей службы в изолированном Linux-стенде."""

import ctypes
import errno
import os
from pathlib import Path
import struct

_LIBRARY = None


def _library():
    global _LIBRARY
    if _LIBRARY is None:
        library = ctypes.CDLL("libbpf.so.1", use_errno=True)
        library.bpf_obj_get.argtypes = [ctypes.c_char_p]
        library.bpf_obj_get.restype = ctypes.c_int
        library.bpf_obj_get_info_by_fd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
        library.bpf_obj_get_info_by_fd.restype = ctypes.c_int
        library.bpf_map_get_next_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        library.bpf_map_get_next_key.restype = ctypes.c_int
        _LIBRARY = library
    return _LIBRARY


def process_sample(pid, expected_start=None):
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError("Требуется PID действующей службы или работника")
    root = Path(f"/proc/{pid}")
    raw = (root / "stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    started = int(fields[19])
    if expected_start is not None and expected_start != started:
        raise RuntimeError("Измеряемый процесс сменился")
    status = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines() if ":" in line)
    maps = set()
    for descriptor in (root / "fdinfo").iterdir():
        try:
            values = dict(line.split(":", 1) for line in descriptor.read_text().splitlines() if ":" in line)
        except FileNotFoundError:
            continue
        if "map_id" in values:
            maps.add(int(values["map_id"]))
    return {
        "pid": pid,
        "start_ticks": started,
        "rss_kib": int(status["VmRSS"].split()[0]),
        "fd_count": len(list((root / "fd").iterdir())),
        "threads": int(status["Threads"]),
        "map_ids": sorted(maps),
    }


def pinned_maps(namespace):
    if len(namespace) != 32 or any(char not in "0123456789abcdef" for char in namespace):
        raise ValueError("Некорректное пространство имен BPF")
    library = _library()
    result = {}
    for path in sorted((Path("/sys/fs/bpf/aivpn_app_routes") / namespace / "maps").iterdir()):
        descriptor = library.bpf_obj_get(os.fsencode(path))
        if descriptor < 0:
            raise OSError(ctypes.get_errno(), "Не удалось открыть собственную карту BPF")
        try:
            info = ctypes.create_string_buffer(256)
            size = ctypes.c_uint(len(info))
            if library.bpf_obj_get_info_by_fd(descriptor, info, ctypes.byref(size)):
                raise OSError(ctypes.get_errno(), "Не удалось прочитать схему карты BPF")
            kind, identity, key_size, _, capacity = struct.unpack_from("=5I", info.raw)
            row = {"id": identity, "kind": kind, "capacity": capacity}
            # Storage освобождает ядро; у array заняты все ячейки. Ключи hash не выводим.
            if kind in (1, 5, 9, 10, 13):
                if not 0 < key_size <= 4096 or not 0 < capacity <= 1024 * 1024:
                    raise RuntimeError("Схема карты не подходит для ограниченного обхода")
                previous = None
                keys = set()
                for _ in range(2 * capacity + 1):
                    following = ctypes.create_string_buffer(key_size)
                    if library.bpf_map_get_next_key(descriptor, previous, following):
                        error = ctypes.get_errno()
                        if error != errno.ENOENT:
                            raise OSError(error, "Не удалось обойти собственную карту BPF")
                        break
                    keys.add(following.raw)
                    previous = following
                else:
                    raise RuntimeError("Карта продолжает меняться во время снимка ресурсов")
                row["entries"] = len(keys)
            result[path.name] = row
        finally:
            os.close(descriptor)
    if not result:
        raise RuntimeError("Собственные закрепленные карты не найдены")
    return result


def kernel_inventory():
    # Область подсчета - отдельное ядро стенда, без чужих программ пользователя.
    flags = Path("/proc/cmdline").read_text().split()
    if not {"aivpn.app-routing-lab=1", "aivpn.vertical-path=1"}.issubset(flags):
        raise RuntimeError("Общий счетчик BPF разрешен только в изолированном стенде")
    return {kind: _object_ids(kind) for kind in ("map", "prog", "btf")}


def _object_ids(kind):
    library = _library()
    next_id = getattr(library, f"bpf_{kind}_get_next_id")
    next_id.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
    next_id.restype = ctypes.c_int
    descriptor_for = getattr(library, f"bpf_{kind}_get_fd_by_id")
    descriptor_for.argtypes = [ctypes.c_uint]
    descriptor_for.restype = ctypes.c_int
    previous = 0
    identities = []
    for _ in range(16384):
        following = ctypes.c_uint()
        if next_id(previous, ctypes.byref(following)):
            error = ctypes.get_errno()
            if error == errno.ENOENT:
                return {"live_count": len(identities), "ids": identities}
            raise OSError(error, "Не удалось перечислить объекты BPF")
        if following.value <= previous:
            raise RuntimeError("Ядро вернуло непоследовательный ID BPF")
        previous = following.value
        descriptor = descriptor_for(previous)
        if descriptor < 0:
            error = ctypes.get_errno()
            if error == errno.ENOENT:
                continue
            raise OSError(error, "Не удалось подтвердить живой объект BPF")
        try:
            identities.append(previous)
        finally:
            os.close(descriptor)
    raise RuntimeError("Перечисление объектов BPF превысило предел стенда")
