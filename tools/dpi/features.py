"""23 признака окна, в той же арифметике, что `dpi_gate.rs`.

Интервалы между пакетами сознательно не входят в вектор: у офлайн-захватов
они не описывают протокол. Пороги и доли считаются так же, как во встроенном
гейте, включая приведение энтропии к f32 до усреднения.
"""

from __future__ import annotations

import math
import os

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")

import numpy as np

WINDOW = 24
N_FEATURES = 23
FEATURE_SCHEMA_VERSION = 2
FEATURE_SCHEMA_NAME = "quic-short-header-byte0-invariant"
SIZE_BINS = (
    (0, 100),
    (100, 300),
    (300, 600),
    (600, 1000),
    (1000, 1400),
    (1400, 65535),
)
FEATURE_NAMES = (
    "n_pkts",
    "sz_mean",
    "sz_std",
    "sz_min",
    "sz_max",
    "sz_med",
    "sz_p10",
    "sz_p90",
    "szfrac_0_100",
    "szfrac_100_300",
    "szfrac_300_600",
    "szfrac_600_1000",
    "szfrac_1000_1400",
    "szfrac_1400p",
    "ent_first16",
    "ent_full",
    "byte0_mean",
    "byte0_msb_frac",
    "quic_longform_frac",
    "stun_type_frac",
    "stun_magic_frac",
    "stun_lenconsistent_frac",
    "dns_looksdns_frac",
)
STUN_TYPES = (b"\x00\x01", b"\x01\x01", b"\x00\x03", b"\x01\x11")
STUN_MAGIC = b"\x21\x12\xa4\x42"

# Ожидаемый вектор из модульного теста `feature_extraction_matches_python_reference`.
REFERENCE_PACKETS = (
    ("stun", 56, 76),
    ("stun", 20, 40),
    ("stun", 8, 28),
    ("rnd", 1100, 3),
    ("rnd", 1200, 9),
    ("rnd", 200, 21),
)
REFERENCE_FEATURES = (
    6.0,
    440.66667,
    505.47623,
    28.0,
    1200.0,
    76.0,
    28.0,
    1100.0,
    0.5,
    0.16666667,
    0.0,
    0.0,
    0.33333334,
    0.0,
    3.9375,
    6.6259175,
    84.0,
    0.5,
    0.16666667,
    0.5,
    0.5,
    0.5,
    0.0,
)


def f32(value: float) -> float:
    """Число, которое точно совпадает с каким-то f32."""
    return float(np.float32(value))


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = float(len(data))
    entropy = 0.0
    for count in counts:
        if count:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy


def round_half_even(value: float) -> float:
    floor = math.floor(value)
    diff = value - floor
    if diff < 0.5:
        return floor
    if diff > 0.5:
        return floor + 1.0
    if int(floor) % 2 == 0:
        return floor
    return floor + 1.0


def percentile(sorted_sizes: list[int], q: float) -> float:
    if not sorted_sizes:
        return 0.0
    idx = int(round_half_even(q * (len(sorted_sizes) - 1)))
    idx = min(max(idx, 0), len(sorted_sizes) - 1)
    return float(sorted_sizes[idx])


def header_flags(packet: bytes) -> dict[str, float]:
    length = len(packet)
    stored_len = min(length, 65535)
    raw_byte0 = packet[0] if packet else 0
    byte0 = 0x40 if raw_byte0 & 0xC0 == 0x40 else raw_byte0
    normalized = bytes([byte0]) + packet[1:] if packet and byte0 != raw_byte0 else packet
    stun_type = (
        length >= 2 and (packet[0] & 0xC0) == 0 and packet[:2] in STUN_TYPES
    )
    magic_ok = length >= 8 and packet[4:8] == STUN_MAGIC
    stun_lenok = False
    if length >= 4:
        msg_len = (packet[2] << 8) | packet[3]
        stun_lenok = msg_len + 20 == length
    dns_ok = False
    if length >= 12:
        qd = (packet[4] << 8) | packet[5]
        an = (packet[6] << 8) | packet[7]
        dns_ok = qd == 1 and an <= 16
    n16 = min(length, 16)
    return {
        "len": float(stored_len),
        "byte0": float(byte0),
        "has_byte0": 1.0 if length > 0 else 0.0,
        "stun_type": 1.0 if stun_type else 0.0,
        "magic_ok": 1.0 if magic_ok else 0.0,
        "stun_lenok": 1.0 if stun_lenok else 0.0,
        "dns_ok": 1.0 if dns_ok else 0.0,
        "ent16": f32(shannon_entropy(normalized[:n16])),
        "ent_full": f32(shannon_entropy(normalized)),
        "quic_long": 1.0 if length > 0 and (byte0 & 0xC0) == 0xC0 else 0.0,
        "msb": 1.0 if length > 0 and (byte0 & 0x80) != 0 else 0.0,
        "band": (
            "00"
            if length > 0 and byte0 < 0x40
            else "40"
            if length > 0 and byte0 < 0x80
            else "80"
            if length > 0 and byte0 < 0xC0
            else "C0"
            if length > 0
            else "empty"
        ),
    }


def vector(packets: list[bytes]) -> list[float]:
    """Вектор из 23 f32 в порядке `extract_features`."""
    feats = [0.0] * N_FEATURES
    count = len(packets)
    if count == 0:
        return feats
    meta = [header_flags(packet) for packet in packets]
    sizes = [int(item["len"]) for item in meta]
    nf = f32(float(count))
    mean = sum(sizes) / count
    var = sum((size - mean) ** 2 for size in sizes) / count
    ordered = sorted(sizes)
    feats[0] = nf
    feats[1] = f32(mean)
    feats[2] = f32(math.sqrt(var))
    feats[3] = f32(float(ordered[0]))
    feats[4] = f32(float(ordered[-1]))
    feats[5] = f32(percentile(ordered, 0.5))
    feats[6] = f32(percentile(ordered, 0.10))
    feats[7] = f32(percentile(ordered, 0.90))
    bins = [0] * len(SIZE_BINS)
    for size in sizes:
        for index, (lo, hi) in enumerate(SIZE_BINS):
            if lo <= size < hi:
                bins[index] += 1
                break
    for index, bin_count in enumerate(bins):
        feats[8 + index] = f32(float(np.float32(bin_count) / np.float32(count)))
    feats[14] = f32(sum(item["ent16"] for item in meta) / count)
    feats[15] = f32(sum(item["ent_full"] for item in meta) / count)
    byte_sum = 0
    byte_n = 0
    msb = 0
    quic_long = 0
    for item in meta:
        if item["has_byte0"]:
            byte_sum += int(item["byte0"])
            byte_n += 1
            msb += int(item["msb"])
            quic_long += int(item["quic_long"])
    if byte_n:
        feats[16] = f32(float(np.float32(byte_sum) / np.float32(byte_n)))
        feats[17] = f32(float(np.float32(msb) / np.float32(byte_n)))
        feats[18] = f32(float(np.float32(quic_long) / np.float32(byte_n)))
    feats[19] = f32(float(np.float32(sum(item["stun_type"] for item in meta)) / np.float32(count)))
    feats[20] = f32(float(np.float32(sum(item["magic_ok"] for item in meta)) / np.float32(count)))
    feats[21] = f32(float(np.float32(sum(item["stun_lenok"] for item in meta)) / np.float32(count)))
    feats[22] = f32(float(np.float32(sum(item["dns_ok"] for item in meta)) / np.float32(count)))
    return [f32(item) for item in feats]


def stun_pkt(msg_len: int, total: int) -> bytes:
    packet = bytearray(
        [
            0x00,
            0x01,
            (msg_len >> 8) & 0xFF,
            msg_len & 0xFF,
            0x21,
            0x12,
            0xA4,
            0x42,
        ]
    )
    for index in range(max(0, total - 8)):
        packet.append((index * 37 + 11) & 0xFF)
    del packet[total:]
    return bytes(packet)


def rnd_pkt(total: int, seed: int) -> bytes:
    return bytes(((seed * 131 + index * 97 + 7) & 0xFF) for index in range(total))


def packets_from_spec(spec: list[dict]) -> list[bytes]:
    packets: list[bytes] = []
    for step in spec:
        repeat = int(step.get("repeat", 1))
        op = step["op"]
        for k in range(repeat):
            if op == "stun":
                packets.append(stun_pkt(int(step["msg_len"]), int(step["total"])))
            elif op == "rnd":
                if "seed" in step:
                    seed = int(step["seed"])
                    total = int(step["total"])
                else:
                    seed = k * int(step["seed_mul"]) + int(step["seed_add"])
                    total = int(step["total_base"]) + (k % int(step["mod"])) * int(step["scale"])
                packets.append(rnd_pkt(total, seed))
            elif op == "quic_short":
                total = int(step["total"])
                first = int(step["byte0"])
                if total < 1 or not 0x40 <= first < 0x80:
                    raise ValueError("неверный синтетический short header")
                packets.append(bytes([first]) + rnd_pkt(total, int(step["seed"]))[1:])
            else:
                raise ValueError(f"неизвестная операция пакета: {op}")
    return packets


def reference_window() -> list[bytes]:
    packets = []
    for kind, a, b in REFERENCE_PACKETS:
        if kind == "stun":
            packets.append(stun_pkt(a, b))
        else:
            packets.append(rnd_pkt(a, b))
    return packets


def reference_ok(tol: float = 1e-3) -> tuple[bool, float]:
    got = vector(reference_window())
    worst = 0.0
    for got_i, want_i in zip(got, REFERENCE_FEATURES):
        scale = max(abs(want_i), 1.0)
        worst = max(worst, abs(got_i - want_i) / scale)
    return worst <= tol, worst
