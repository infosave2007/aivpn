"""Прототип передачи контекста NSS в отдельном стенде; поддерживает только тестовый A-запрос."""

from collections import deque
import json
import os
from pathlib import Path
import re
import socket
import struct
import threading


def read_message(connection):
    frame = bytearray()
    while b"\0" not in frame:
        chunk = connection.recv(4096)
        if not chunk:
            raise ValueError("Незавершенный запрос")
        frame.extend(chunk)
        if len(frame) > 65536:
            raise ValueError("Запрос превышает лимит")
    message = json.loads(frame.split(b"\0", 1)[0])
    if not isinstance(message, dict):
        raise ValueError("Запрос должен быть объектом")
    return message


def valid_name(name):
    if not isinstance(name, str) or not name.isascii() or len(name) > 253:
        return False
    return re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", name) is not None and all(
        len(label) <= 63 for label in name.split("."))


def lookup_address(name, selected):
    request_id = os.urandom(2)
    question = b"".join(bytes([len(label)]) + label for label in name.encode("ascii").split(b"."))
    question += b"\x00\x00\x01\x00\x01"
    query = request_id + b"\x01\x00\x00\x01" + b"\x00" * 6 + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
        upstream.settimeout(1)
        upstream.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0xa1 if selected else 0)
        upstream.connect(("198.18.0.53" if selected else "192.0.2.53", 53))
        upstream.send(query)
        response = upstream.recv(4096)
    # Стенд принимает только точный формат своего одноадресного DNS endpoint.
    expected = request_id + b"\x81\x80\x00\x01\x00\x01" + b"\x00" * 4 + question
    expected += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04"
    if len(response) != len(expected) + 4 or response[:-4] != expected:
        raise ValueError("Неожиданный DNS-ответ стенда")
    return list(response[-4:])


def reply_for(message, selected, ready):
    if selected and not ready:
        return {"error": "io.systemd.Resolve.NetworkDown"}
    if message.get("method") != "io.systemd.Resolve.ResolveHostname":
        return {"error": "io.systemd.Resolve.NoSuchResourceRecord"}
    parameters = message.get("parameters", {})
    if not isinstance(parameters, dict):
        return {"error": "io.systemd.Resolve.InvalidResourceKey"}
    name = parameters.get("name")
    if not valid_name(name) or parameters.get("family", 0) not in (0, socket.AF_INET):
        return {"error": "io.systemd.Resolve.InvalidResourceKey"}
    return {"parameters": {"addresses": [{"family": socket.AF_INET, "ifindex": 0,
            "address": lookup_address(name, selected)}], "name": name, "flags": 1}}


def handle(connection, selected_group, state):
    connection.settimeout(2)
    pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    message = read_message(connection)
    cgroup = Path(f"/proc/{pid}/cgroup").read_text().strip().split(":", 2)[2]
    selected = cgroup == selected_group
    state["requests"].append({"pid": pid, "uid": uid, "selected": selected})
    connection.sendall(json.dumps(reply_for(message, selected, state["ready"])).encode() + b"\0")


def serve(listener, selected_group, state):
    while not state["stop"]:
        try:
            connection, _ = listener.accept()
        except OSError:
            if state["stop"]:
                return
            raise
        with connection:
            try:
                handle(connection, selected_group, state)
            except (OSError, ValueError, IndexError):
                state["rejected"] += 1


def start(path, selected_group):
    from linux_probe import require_guest
    require_guest()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(8)
    state = {"ready": True, "requests": deque(maxlen=128), "rejected": 0, "stop": False}
    worker = threading.Thread(target=serve, args=(listener, selected_group, state), daemon=True)
    worker.start()
    return listener, state
