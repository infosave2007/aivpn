import socket
import struct
import threading
import time
import unittest

from windows_goodput_server import bulk_connection


class SenderPacingTest(unittest.TestCase):
    def test_fast_receiver_observes_sender_rate_and_complete_payload(self):
        client, server = socket.socketpair()
        client.settimeout(4)
        thread = threading.Thread(target=bulk_connection, args=(server, ("127.0.0.1", 1234)))
        thread.start()
        size = 1024 * 1024
        rate = 1024 * 1024
        try:
            started = time.monotonic()
            client.sendall(b"P" + struct.pack("!QQ", size, rate))
            data = bytearray()
            while len(data) < size + 64:
                part = client.recv(min(65536, size + 64 - len(data)))
                self.assertTrue(part, "Сервер закрыл поток до полного ответа")
                data.extend(part)
            elapsed = time.monotonic() - started
            self.assertEqual(data[:64], b"observed=127.0.0.1".ljust(64, b"\0"))
            pattern = bytes(range(251))
            self.assertEqual(data[64:], (pattern * (size // 251 + 1))[:size])
            self.assertGreaterEqual(elapsed, 0.9, "Отправитель не соблюдает ограничение скорости")
            self.assertLess(elapsed, 3.5)
        finally:
            client.close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), "Поток стенда не завершился")


if __name__ == "__main__":
    unittest.main()
