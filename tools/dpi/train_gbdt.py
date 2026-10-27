#!/usr/bin/env python3
"""Обучение GBDT-гейта по матрице из 30 независимых захватов.

В каждой части train, val и test лежат все 10 семейств. Это удержание сессии,
а не удержание семейства. Порог и гиперпараметры ниже зафиксированы в коде
и не подбираются по val или test. В подгонку входят только окна реальных
захватов и порчи, которые принял учитель nDPI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from threadpoolctl import threadpool_limits

sys.path.insert(0, str(Path(__file__).resolve().parent))
import features as F  # noqa: E402
import pcapio  # noqa: E402
import teacher  # noqa: E402

SEED = 0
N_TREES = 120
MAX_DEPTH = 3
LEARNING_RATE = 0.15
THRESHOLD = 0.5
PRIMARY_STRIDE = 24
OVERLAP_STRIDE = 8
JOBS = 2
NEG_PACKETS = 48
# Зазор задан до подсчета контроля. Это не порог гейта и по test не двигается.
MATERIAL_MARGIN = 0.05
NEG_VARIANTS = ("xor_header", "noise_same_len", "broken_replay", "random_noise")
PARTITIONS = ("train", "val", "test")
MASKS = (
    "webrtc_zoom_v3",
    "quic_https_v2",
    "webrtc_yandex_telemost_v1",
    "webrtc_vk_teams_v1",
    "webrtc_sberjazz_v1",
    "sber_salute_v1",
    "whatsapp_voip_v1",
    "avito_api_v1",
    "telegram_calls_v1",
    "vk_video_v1",
)
TITLES = {
    "webrtc_zoom_v3": "Zoom",
    "quic_https_v2": "QUIC HTTPS",
    "webrtc_yandex_telemost_v1": "Telemost",
    "webrtc_vk_teams_v1": "VK Teams",
    "webrtc_sberjazz_v1": "Jazz",
    "sber_salute_v1": "Salute",
    "whatsapp_voip_v1": "WhatsApp",
    "avito_api_v1": "Avito",
    "telegram_calls_v1": "Telegram",
    "vk_video_v1": "VK Video",
}
FORBIDDEN_CODEPOINTS = (0x0451, 0x0401, 0x2014, 0x2013)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_seed(text: str) -> int:
    value = 2166136261
    for byte in text.encode():
        value ^= byte
        value = (value * 16777619) & 0xFFFFFFFF
    return value or 1


def xorshift(state: int) -> int:
    state &= 0xFFFFFFFF
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= state >> 17
    state ^= (state << 5) & 0xFFFFFFFF
    return state & 0xFFFFFFFF


def fill_noise(length: int, state: int) -> tuple[bytes, int]:
    buf = bytearray(length)
    for index in range(length):
        state = xorshift(state)
        buf[index] = (state >> 16) & 0xFF
    return bytes(buf), state


def corrupt(variant: str, packets: list[bytes], seed: int) -> list[bytes]:
    base = packets[:NEG_PACKETS]
    if variant == "xor_header":
        out = []
        for packet in base:
            buf = bytearray(packet)
            for index in range(min(16, len(buf))):
                buf[index] ^= 0xFF
            out.append(bytes(buf))
        return out
    if variant == "noise_same_len":
        out = []
        state = seed
        for packet in base:
            payload, state = fill_noise(len(packet), state)
            out.append(payload)
        return out
    if variant == "broken_replay":
        stamp = bytes.fromhex("0102030405060708")
        out = []
        for packet in base:
            buf = bytearray(packet)
            buf[: min(8, len(buf))] = stamp[: min(8, len(buf))]
            if len(buf) >= 4:
                buf[2] = 0xFF
                buf[3] = 0xFF
            out.append(bytes(buf))
        return out
    if variant == "random_noise":
        lengths = (40, 80, 200, 400, 900, 1300)
        out = []
        state = seed
        for index in range(NEG_PACKETS):
            payload, state = fill_noise(lengths[index % len(lengths)], state)
            out.append(payload)
        return out
    raise ValueError(variant)


def window_starts(count: int, stride: int) -> list[int]:
    starts = []
    pos = 0
    while pos + F.WINDOW <= count:
        starts.append(pos)
        pos += stride
    return starts


def load_verified(path: Path) -> list[bytes]:
    data = json.loads(path.read_text())
    if not isinstance(data, list) or not data:
        raise ValueError(f"{path.name}: нужен непустой JSON-массив")
    packets = []
    for item in data:
        if not isinstance(item, str) or len(item) % 2 or any(c not in "0123456789abcdefABCDEF" for c in item):
            raise ValueError(f"{path.name}: элемент не является hex-строкой")
        packets.append(bytes.fromhex(item))
    return packets


def expected_pairs() -> set[tuple[str, str]]:
    return {(partition, mask_id) for partition in PARTITIONS for mask_id in MASKS}


def locate_pair(directory: Path, mask_id: str) -> tuple[Path, Path]:
    verified = directory / f"{mask_id}.verified.json"
    pcap = directory / f"{mask_id}.pcap"
    if not pcap.is_file():
        alt = directory / f"{mask_id}-training.pcap"
        if alt.is_file():
            pcap = alt
    return verified, pcap


def _entry(root: Path, partition: str, mask_id: str, verified: Path, pcap: Path, workload_seed: int | None) -> dict:
    if partition not in PARTITIONS:
        raise ValueError(f"неизвестная часть: {partition}")
    if mask_id not in MASKS:
        raise ValueError(f"неизвестная маска: {mask_id}")
    if not verified.is_file() or not pcap.is_file():
        raise ValueError(f"нет файлов захвата {partition}/{mask_id}")
    return {
        "partition": partition,
        "mask_id": mask_id,
        "title": TITLES[mask_id],
        "verified": verified,
        "pcap": pcap,
        "workload_seed": workload_seed,
        "capture_id": f"{partition}/{mask_id}",
    }


def discover_captures(root: Path) -> list[dict]:
    """Тридцать захватов: все семейства в train, val и test.

    Если рядом лежит manifest.json, он перечисляет пути. Иначе ожидается
    каталог `{part}/{mask_id}.pcap` и `{part}/{mask_id}.verified.json`.
    Один и тот же файл двум частям не отдается.
    """
    if not root.is_dir():
        raise ValueError(f"каталог захватов не найден: {root}")
    manifest = root / "manifest.json"
    if manifest.is_file():
        entries = _from_manifest(root, manifest)
    else:
        entries = []
        missing = []
        for partition in PARTITIONS:
            for mask_id in MASKS:
                verified, pcap = locate_pair(root / partition, mask_id)
                if not verified.is_file() or not pcap.is_file():
                    missing.append(f"{partition}/{mask_id}")
                    continue
                entries.append(_entry(root, partition, mask_id, verified, pcap, None))
        if missing:
            raise ValueError("матрица не полная, нет: " + ", ".join(missing))
    got = {(item["partition"], item["mask_id"]) for item in entries}
    if got != expected_pairs() or len(entries) != 30:
        missing = sorted(f"{part}/{mask}" for part, mask in expected_pairs() - got)
        extra = sorted(f"{item['partition']}/{item['mask_id']}" for item in entries if (item["partition"], item["mask_id"]) not in expected_pairs())
        raise ValueError(
            "нужны ровно 30 захватов, все 10 семейств в train, val и test; "
            f"нет: {', '.join(missing) or '-'}; лишние: {', '.join(extra) or '-'}"
        )
    seen: dict[str, str] = {}
    for item in entries:
        for key in ("verified", "pcap"):
            resolved = str(item[key].resolve())
            previous = seen.get(resolved)
            if previous:
                raise ValueError(f"файл захвата повторяется у {previous} и {item['capture_id']}")
            seen[resolved] = item["capture_id"]
    return sorted(entries, key=lambda item: (PARTITIONS.index(item["partition"]), MASKS.index(item["mask_id"])))


def _from_manifest(root: Path, manifest: Path) -> list[dict]:
    doc = json.loads(manifest.read_text())
    rows = doc.get("captures") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        raise ValueError("manifest.json: нужен список captures")
    entries = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("manifest.json: запись захвата должна быть объектом")
        partition = row.get("partition")
        mask_id = row.get("mask_id")
        if not isinstance(partition, str) or not isinstance(mask_id, str):
            raise ValueError("manifest.json: нужны partition и mask_id")
        verified = _manifest_path(root, row.get("verified"))
        pcap = _manifest_path(root, row.get("pcap"))
        seed = row.get("workload_seed")
        if seed is not None and not isinstance(seed, int):
            raise ValueError(f"workload_seed должен быть целым: {partition}/{mask_id}")
        entries.append(_entry(root, partition, mask_id, verified, pcap, seed))
    return entries


def discover_matched_captures(root: Path) -> list[dict]:
    """Дополнительные QUIC-сессии: repeats 0/1 в train, 2/3 только в test."""
    doc = json.loads((root / "manifest.json").read_text())
    rows = doc.get("captures") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError("matched manifest: нужен непустой список captures")
    entries = []
    identities = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("matched manifest: запись должна быть объектом")
        repetition = row.get("repetition")
        partition = row.get("partition")
        if type(repetition) is not int or repetition not in (0, 1, 2, 3):
            raise ValueError("matched manifest: неизвестный repetition")
        if partition != ("train" if repetition < 2 else "test"):
            raise ValueError("matched manifest: holdout repetition нельзя использовать в train")
        identity = row.get("capture_id", "")
        if not isinstance(identity, str) or not re.fullmatch(rf"{partition}/[A-Za-z0-9_-]{{1,96}}", identity) or identity in identities:
            raise ValueError("matched manifest: неверный или повторный capture_id")
        if row.get("mask_id") != "quic_https_v2" or row.get("implementation") not in ("aivpn", "masque"):
            raise ValueError("matched manifest: нужны AIVPN или MASQUE с положительной QUIC-семантикой")
        entry = _entry(root, partition, row["mask_id"], _manifest_path(root, row.get("verified")), _manifest_path(root, row.get("pcap")), None)
        entry.update(capture_id=identity, repetition=repetition, implementation=row["implementation"])
        entry["packet_selection"] = "wire_short_header_length_filtered_stride16; integrity-PASS session; not post-AEAD observer"
        entries.append(entry)
        identities.add(identity)
    return sorted(entries, key=lambda item: item["capture_id"])


def _manifest_path(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("manifest.json: путь pcap или verified пуст")
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path


def spoof_map(repo: Path) -> dict[str, str]:
    found = {}
    for path in sorted((repo / "assets" / "masks").glob("*.json")):
        doc = json.loads(path.read_text())
        mask_id = doc.get("mask_id")
        if isinstance(mask_id, str):
            found[mask_id] = str(doc.get("spoof_protocol", ""))
    return found


def band_fractions(packets: list[bytes]) -> dict[str, float]:
    counts = {key: 0 for key in ("00", "40", "80", "C0", "empty")}
    for packet in packets:
        counts[F.header_flags(packet)["band"]] += 1
    total = max(1, len(packets))
    return {f"band_{key.lower()}": counts[key] / total for key in ("00", "40", "80", "C0")}


def make_row(capture: dict, role: str, variant: str, y: int, packets: list[bytes], start: int, stride: int) -> dict:
    return {
        "partition": capture["partition"],
        "mask_id": capture["mask_id"],
        "capture_id": capture["capture_id"],
        "role": role,
        "variant": variant,
        "y": y,
        "start": start,
        "stride": stride,
        "x": F.vector(packets[start : start + F.WINDOW]),
    }


def rows_from_packets(capture: dict, role: str, variant: str, y: int, packets: list[bytes], stride: int) -> list[dict]:
    return [make_row(capture, role, variant, y, packets, start, stride) for start in window_starts(len(packets), stride)]


def judge_negative(ndpi: str, capture_id: str, variant: str, payloads: list[bytes]) -> dict:
    handle, path = tempfile.mkstemp(prefix="aivpn-dpi-neg-", suffix=".pcap")
    os.close(handle)
    try:
        pcapio.write_uplink_pcap(path, payloads)
        flows, detected, rc = teacher.label_pcap(ndpi, path)
        ok, reason = teacher.negative_ok(flows, detected, rc)
        return {
            "capture_id": capture_id,
            "variant": variant,
            "accepted": ok,
            "reason": reason,
            "proto": ",".join(flow.proto for flow in flows) or "none",
            "confidence": ",".join(flow.confidence for flow in flows) or "none",
            "returncode": rc,
            "payloads": payloads if ok else None,
        }
    finally:
        os.unlink(path)


def unchanged_context_ok(flows: list, returncode: int) -> tuple[bool, str]:
    if returncode != 0 or not flows:
        return False, "неизмененный standalone-контекст не классифицирован"
    if any(teacher.is_unknown(flow) or teacher.is_vpn(flow) or flow.confidence != "DPI" for flow in flows):
        return False, "неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности"
    return True, "неизмененный standalone-контекст известен учителю"


def judge_unchanged(ndpi: str, payloads: list[bytes]) -> dict:
    handle, path = tempfile.mkstemp(prefix="aivpn-dpi-control-", suffix=".pcap")
    os.close(handle)
    try:
        pcapio.write_uplink_pcap(path, payloads)
        flows, detected, rc = teacher.label_pcap(ndpi, path)
        ok, reason = unchanged_context_ok(flows, rc)
        return {"accepted": ok, "reason": reason, "proto": ",".join(flow.proto for flow in flows) or "none", "detected": detected, "returncode": rc}
    finally:
        os.unlink(path)


def guard_negative_context(result: dict, baseline: dict) -> dict:
    if baseline["accepted"]:
        return result
    return {**result, "accepted": False, "payloads": None, "reason": "Нет симметричного контроля: " + baseline["reason"]}


def floor_f32(threshold: float) -> np.float32:
    """Наибольший f32, который не превышает порог sklearn (double).

    Округление к ближайшему может поднять порог, и сравнение `x <= threshold`
    уйдет в другую ветку. Пол вниз сохраняет ветку исходного double.
    """
    original = np.float64(threshold)
    if not np.isfinite(original):
        raise RuntimeError("неконечный порог дерева")
    narrowed = np.float32(original)
    if np.float64(narrowed) > original:
        narrowed = np.nextafter(narrowed, np.float32(-np.inf))
    return np.float32(narrowed)


def assert_floor_examples() -> None:
    left = np.float32(1.0)
    right = np.nextafter(left, np.float32(np.inf))
    mid = (float(left) + float(right)) / 2.0
    floored = floor_f32(mid)
    if floored != left or float(right) <= float(floored) or float(np.float64(floored)) > mid:
        raise RuntimeError("пол порога f32 не отделяет соседние значения")
    if float(right) <= mid or not (float(left) <= mid):
        raise RuntimeError("контрольная точка пола порога собрана неверно")


def raw_init(clf: GradientBoostingClassifier, n_features: int) -> float:
    probe = np.zeros((1, n_features), dtype=np.float64)
    if not hasattr(clf, "_raw_predict_init"):
        raise RuntimeError("у sklearn нет _raw_predict_init, экспорт остановлен")
    value = np.asarray(clf._raw_predict_init(probe), dtype=np.float64)
    return float(value.reshape(-1)[0])


def export_nodes(clf: GradientBoostingClassifier) -> tuple[list[tuple], list[int], float]:
    nodes: list[tuple] = []
    offsets = [0]
    init = raw_init(clf, F.N_FEATURES)
    for tree_index in range(clf.n_estimators_):
        tree = clf.estimators_[tree_index, 0].tree_
        base = len(nodes)
        for index in range(tree.node_count):
            left = int(tree.children_left[index])
            right = int(tree.children_right[index])
            if left == -1:
                value = float(np.asarray(tree.value[index]).reshape(-1)[0])
                nodes.append((-1, 0.0, 0, 0, float(np.float32(value))))
            else:
                nodes.append(
                    (
                        int(tree.feature[index]),
                        float(floor_f32(float(tree.threshold[index]))),
                        base + left,
                        base + right,
                        0.0,
                    )
                )
        offsets.append(len(nodes))
    return nodes, offsets, init


def walk_prob(nodes: list[tuple], offsets: list[int], init: float, lr: float, features: list[float]) -> float:
    raw = np.float32(init)
    rate = np.float32(lr)
    row = np.asarray(features, dtype=np.float32)
    for tree_index in range(len(offsets) - 1):
        cursor = int(offsets[tree_index])
        for _ in range(64):
            feat, thr, left, right, value = nodes[cursor]
            if feat < 0:
                raw = np.float32(raw + rate * np.float32(value))
                break
            cursor = int(left if row[feat] <= np.float32(thr) else right)
        else:
            raise RuntimeError("слишком глубокий обход дерева")
    prob = np.float32(1.0) / (np.float32(1.0) + np.exp(np.float32(-raw)))
    return float(prob)


def sklearn_branch_mismatches(clf: GradientBoostingClassifier, nodes: list[tuple], offsets: list[int], rows: list[dict]) -> int:
    mismatches = 0
    matrix = np.asarray([row["x"] for row in rows], dtype=np.float64)
    for tree_index in range(clf.n_estimators_):
        tree = clf.estimators_[tree_index, 0].tree_
        base = offsets[tree_index]
        for row_index, row in enumerate(rows):
            cursor = 0
            values = matrix[row_index]
            while int(tree.children_left[cursor]) != -1:
                feat = int(tree.feature[cursor])
                if values[feat] <= tree.threshold[cursor]:
                    cursor = int(tree.children_left[cursor])
                else:
                    cursor = int(tree.children_right[cursor])
            local = base
            narrowed = np.asarray(row["x"], dtype=np.float32)
            for _ in range(64):
                feat, thr, left, right, _value = nodes[local]
                if feat < 0:
                    break
                local = int(left if narrowed[feat] <= np.float32(thr) else right)
            else:
                raise RuntimeError("обход экспортированного дерева не закончился")
            if local - base != cursor:
                mismatches += 1
    return mismatches


def sort_key(row: dict) -> tuple:
    return (row["partition"], row["mask_id"], row["capture_id"], row["role"], row["variant"], row["start"], row["y"])


def population_weights(rows: list[dict]) -> np.ndarray:
    """Равные массы классов, семейств и исходных сессий внутри семейства.

    Частота захватов не задает частоту реального трафика. Каждый имеющийся
    (семейство, класс) получает одинаковую долю массы своего класса, а
    исходные capture_id делят ее поровну независимо от числа окон и порч.
    Все окна сохраняются. Отсутствующие отрицательные группы не создаются.
    """
    counts: dict[tuple[str, int, str], int] = defaultdict(int)
    captures: dict[tuple[str, int], set[str]] = defaultdict(set)
    families: dict[int, set[str]] = defaultdict(set)
    for row in rows:
        if row.get("partition", "train") != "train":
            raise ValueError("веса вычисляются только по train")
        label = row["y"]
        mask_id = row["mask_id"]
        capture_id = row["capture_id"]
        if label not in (0, 1) or mask_id not in MASKS:
            raise ValueError("неизвестная группа обучающих весов")
        counts[(mask_id, label, capture_id)] += 1
        captures[(mask_id, label)].add(capture_id)
        families[label].add(mask_id)
    if set(families) != {0, 1}:
        raise ValueError("веса требуют оба класса")
    return np.asarray([
        len(rows) / (2 * len(families[row["y"]]) * len(captures[(row["mask_id"], row["y"])]) * counts[(row["mask_id"], row["y"], row["capture_id"])])
        for row in rows
    ], dtype=np.float64)


def population_summary(rows: list[dict]) -> dict:
    groups = defaultdict(lambda: {"windows": 0, "weight_sum": 0.0})
    captures = defaultdict(lambda: {"windows": 0, "weight_sum": 0.0})
    for row, weight in zip(rows, population_weights(rows)):
        group = groups[(row["mask_id"], row["y"])]
        group["windows"] += 1
        group["weight_sum"] += float(weight)
        capture = captures[(row["mask_id"], row["y"], row["capture_id"])]
        capture["windows"] += 1
        capture["weight_sum"] += float(weight)
    return {
        "policy": "equal_class_then_family_then_original_capture_then_windows",
        "formula": "N / (2 * K_class * C_mask_class * N_capture_mask_class)",
        "interpretation": "equal prior importance of supported families; not natural traffic frequency",
        "all_windows_retained": True,
        "groups": [{"mask_id": mask, "class": label, **group} for (mask, label), group in sorted(groups.items())],
        "captures": [{"mask_id": mask, "class": label, "capture_id": identity, **capture} for (mask, label, identity), capture in sorted(captures.items())],
    }


def fit_rows(rows: list[dict]) -> tuple[GradientBoostingClassifier, list[tuple], list[int], float]:
    ordered = sorted(rows, key=sort_key)
    matrix = np.asarray([row["x"] for row in ordered], dtype=np.float64)
    labels = np.asarray(["Unknown" if row["y"] == 1 else "OK" for row in ordered])
    if len(set(labels.tolist())) < 2:
        raise RuntimeError("в обучении только один класс")
    np.random.seed(SEED)
    clf = GradientBoostingClassifier(
        n_estimators=N_TREES,
        max_depth=MAX_DEPTH,
        learning_rate=LEARNING_RATE,
        subsample=1.0,
        max_features=None,
        random_state=SEED,
    )
    clf.fit(matrix, labels, sample_weight=population_weights(ordered))
    if list(clf.classes_) != ["OK", "Unknown"]:
        raise RuntimeError(f"неожиданный порядок классов: {list(clf.classes_)}")
    nodes, offsets, init = export_nodes(clf)
    return clf, nodes, offsets, init


def rust_f32(value: float) -> str:
    return repr(float(np.float32(value))) + "f32"


def render_model(nodes: list[tuple], offsets: list[int], init: float, note: str) -> str:
    lines = [
        "// @generated by tools/dpi/train_gbdt.py - DO NOT EDIT BY HAND.",
        "//",
        "// Binary reads-as-tunnel GradientBoosting gate (Unknown vs OK).",
        "// Fit: 120 trees, depth 3, learning rate 0.15, seed 0. Threshold 0.5 is fixed.",
        "// All 10 mask families are in the fit. val and test are other captures.",
        f"// {note}",
        "// Feature order matches dpi_gate::extract_features. IAT is not used.",
        "",
        "use super::GbdtNode;",
        "",
        "/// Схема признаков совпадает с Python и Rust; wire не меняется.",
        f"pub const FEATURE_SCHEMA_VERSION: u32 = {F.FEATURE_SCHEMA_VERSION};",
        "/// Number of input features (IAT dropped - see dpi_gate).",
        f"pub const N_FEATURES: usize = {F.N_FEATURES};",
        "/// Constant raw-score offset (GradientBoosting init prior, log-odds).",
        f"pub const INIT: f32 = {rust_f32(init)};",
        "/// Per-tree shrinkage applied to each tree's leaf contribution.",
        f"pub const LEARNING_RATE: f32 = {rust_f32(LEARNING_RATE)};",
        "/// Number of regression trees in the ensemble.",
        f"pub const N_TREES: usize = {len(offsets) - 1};",
        "",
        "/// Start index into [`NODES`] for each tree (len = N_TREES + 1).",
        f"pub const TREE_OFFSETS: [u32; {len(offsets)}] = [",
        "    " + ", ".join(str(item) for item in offsets) + ",",
        "];",
        "",
        "/// Flattened decision-tree node table for the whole ensemble.",
        f"pub const NODES: [GbdtNode; {len(nodes)}] = [",
    ]
    for feat, thr, left, right, value in nodes:
        lines.extend(
            [
                "    GbdtNode {",
                f"        feature: {feat},",
                f"        threshold: {rust_f32(thr)},",
                f"        left: {left},",
                f"        right: {right},",
                f"        value: {rust_f32(value)},",
                "    },",
            ]
        )
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def parse_old_model(path: Path) -> tuple[list[tuple], list[int], float, float] | None:
    text = path.read_text()
    try:
        init = float(text.split("pub const INIT: f32 = ", 1)[1].split("f32", 1)[0])
        lr = float(text.split("pub const LEARNING_RATE: f32 = ", 1)[1].split("f32", 1)[0])
        block = text.split("pub const TREE_OFFSETS:", 1)[1]
        inside = block.split("] = [", 1)[1].split("];", 1)[0]
        offsets = [int(piece.strip().rstrip(",")) for piece in inside.replace("\n", " ").split(",") if piece.strip()]
        nodes = []
        for chunk in text.split("GbdtNode {")[1:]:
            body = chunk.split("}", 1)[0]
            feat = int(body.split("feature:", 1)[1].split(",", 1)[0].strip())
            thr = float(body.split("threshold:", 1)[1].split("f32", 1)[0].strip())
            left = int(body.split("left:", 1)[1].split(",", 1)[0].strip())
            right = int(body.split("right:", 1)[1].split(",", 1)[0].strip())
            value = float(body.split("value:", 1)[1].split("f32", 1)[0].strip())
            nodes.append((feat, thr, left, right, value))
        if not nodes or not offsets:
            return None
        return nodes, offsets, init, lr
    except (IndexError, ValueError):
        return None


def model_feature_schema(path: Path) -> int:
    match = re.search(r"pub const FEATURE_SCHEMA_VERSION: u32 = (\d+);", path.read_text())
    return int(match.group(1)) if match else 1


def score_rows(rows: list[dict], nodes, offsets, init) -> list[float]:
    return [walk_prob(nodes, offsets, init, LEARNING_RATE, row["x"]) for row in rows]


def confusion(rows: list[dict], probs: list[float]) -> dict:
    tp = fp = fn = tn = 0
    for row, prob in zip(rows, probs):
        pred = 1 if prob > THRESHOLD else 0
        if row["y"] == 1 and pred == 1:
            tp += 1
        elif row["y"] == 0 and pred == 1:
            fp += 1
        elif row["y"] == 1 and pred == 0:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    total = tp + fp + fn + tn
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": (tp + tn) / total if total else 0.0,
        "balanced_accuracy": 0.5 * (tp / (tp + fn) + tn / (tn + fp)) if tp + fn and tn + fp else None,
        "n": total,
        "false_tunnel_rate": fp / (fp + tn) if fp + tn else 0.0,
        "missed_tunnel_rate": fn / (fn + tp) if fn + tp else 0.0,
    }


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float | None, float | None]:
    if total <= 0:
        return None, None
    phat = successes / total
    den = 1 + z * z / total
    centre = (phat + z * z / (2 * total)) / den
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * total)) / total) / den
    return max(0.0, centre - margin), min(1.0, centre + margin)


def majority_label(rows: list[dict]) -> int:
    ones = sum(row["y"] for row in rows)
    return 1 if ones >= (len(rows) - ones) else 0


def majority_metrics(rows: list[dict], majority: int) -> dict:
    dummy = [1.0 if majority == 1 else 0.0 for _ in rows]
    return confusion(rows, dummy)


def beats_constant(model: dict, baseline: dict, margin: float = MATERIAL_MARGIN) -> bool:
    score = model["balanced_accuracy"]
    constant = baseline["balanced_accuracy"]
    return score is not None and constant is not None and score > constant + margin


def per_mask(rows: list[dict], probs: list[float]) -> list[dict]:
    grouped: dict[str, list[tuple[dict, float]]] = defaultdict(list)
    for row, prob in zip(rows, probs):
        grouped[row["mask_id"]].append((row, prob))
    table = []
    for mask_id in MASKS:
        items = grouped.get(mask_id, [])
        if not items:
            continue
        pos = [(row, prob) for row, prob in items if row["y"] == 0]
        neg = [(row, prob) for row, prob in items if row["y"] == 1]

        def rate(pairs: list[tuple[dict, float]]) -> float | None:
            if not pairs:
                return None
            return sum(1 for _row, prob in pairs if prob > THRESHOLD) / len(pairs)

        table.append(
            {
                "mask_id": mask_id,
                "title": TITLES.get(mask_id, mask_id),
                "n_pos": len(pos),
                "n_neg": len(neg),
                "pos_mean_p": (sum(prob for _row, prob in pos) / len(pos)) if pos else None,
                "neg_mean_p": (sum(prob for _row, prob in neg) / len(neg)) if neg else None,
                "pos_flagged": rate(pos),
                "neg_flagged": rate(neg),
            }
        )
    return table


def leakage_problems(captures: list[dict], rows: list[dict]) -> list[str]:
    problems = []
    got = {(item["partition"], item["mask_id"]) for item in captures}
    if got != expected_pairs():
        problems.append("матрица захватов не равна 10 семействам на 3 части")
    seen_path: dict[str, str] = {}
    seen_hash: dict[tuple[str, str], str] = {}
    for item in captures:
        for key in ("verified", "pcap"):
            path = item.get(key)
            if isinstance(path, Path):
                resolved = str(path.resolve())
                previous = seen_path.get(resolved)
                if previous:
                    problems.append(f"общий файл у {previous} и {item['capture_id']}")
                seen_path[resolved] = item["capture_id"]
        for hash_key in ("verified_sha256", "pcap_sha256"):
            if hash_key not in item:
                continue
            digest = (hash_key, item[hash_key])
            previous = seen_hash.get(digest)
            if previous:
                problems.append(f"одинаковые байты {hash_key} у {previous} и {item['capture_id']}")
            seen_hash[digest] = item["capture_id"]
    identities = {item["capture_id"]: (item["partition"], item["mask_id"]) for item in captures}
    if len(identities) != len(captures):
        problems.append("повторный capture_id")
    groups: dict[str, str] = {}
    for row in rows:
        if identities.get(row["capture_id"]) != (row["partition"], row["mask_id"]):
            problems.append(f"окно {row['capture_id']} лежит в части {row['partition']}")
        previous = groups.get(row["capture_id"])
        if previous and previous != row["partition"]:
            problems.append(f"захват {row['capture_id']} попал в две части")
        groups[row["capture_id"]] = row["partition"]
        if row["partition"] == "train" and row["mask_id"] not in MASKS:
            problems.append("в обучении посторонняя группа")
    return problems


def json_roundtrip_features(features: list[float]) -> list[float]:
    encoded = json.dumps([float(np.float32(value)) for value in features])
    return [float(np.float32(value)) for value in json.loads(encoded)]


def fmt(value: float | None, digits: int = 3) -> str:
    if value is None:
        return "нет"
    text = f"{value:.{digits}f}"
    # Малый ненулевой зазор при шести знаках иначе печатается как 0.000000.
    if value != 0 and float(text) == 0.0:
        return f"{value:.6e}"
    return text


def render_report(ctx: dict) -> str:
    test = ctx["metrics"]["test"]
    val = ctx["metrics"]["val"]
    lines = [
        "# Отчет об обучении GBDT-гейта",
        "",
        "Гейт по окну из 24 кадров оценивает, похож ли уже отобранный внешний UDP-поток на туннель. Это приближение офлайн-вердикта nDPI. Гейт не заменяет nDPI и не показывает устойчивость к произвольному фильтру провайдера.",
        "",
        "## Матрица захватов",
        "",
        "Базовый каталог содержит все 10 семейств в train, val и test, по отдельной сессии. Дополнительные обычные QUIC/MASQUE и AIVPN-сессии имеют одну положительную QUIC-метку: это задача семейства протокола против Unknown, а не VPN против MASQUE. Повторы 0 и 1 допустимы в train, 2 и 3 оставлены для отдельного контроля после заморозки. Базовый генератор сохраняет длины внутренней нагрузки 8, 64, 256, 768, 1000, 4096; дополнительные сессии расширяют скорости, RTT и размеры. Контроль сессионный, семейства не исключались. Общие рецепты не доказывают перенос на произвольный трафик.",
        "",
        "Схема признаков 2 заменяет первый байт short header 0x40..0x7f на 0x40 только при вычислении среднего и обеих энтропий. Разрешенные spin и защищенные биты не определяют эти признаки. Wire и остальные семейства не меняются. Порог 0.5 не менялся.",
        "",
        "Базовые сессии используют проверенные кадры транспортного observer. Дополнительные сессии отбирают восходящие short-header кадры по длине, затем каждый шестнадцатый кадр. Это wire-only выборка исправных сессий, а не точное совпадение с live observer после AEAD. nDPI видит полный восходящий обмен; такое же ограничение контекста применяется к обеим реализациям.",
        "",
        "Провод этих захватов держит начальный и минимальный MTU 1200, верх PMTUD 1380 и внутренний бюджет 1140. Кадры прошлого провода в матрицу не входят. Если manifest не передал номер зерна, в публичные файлы он не подставляется. Различие захватов проверено попарно различными хэшами PCAP и списков кадров.",
        "",
        "Положительная метка требует QUIC или STUN с уверенностью DPI на целом PCAP, без угадывания по порту. Перед отрицательными порчами проверяется неизмененная выборка в том же standalone-контексте и с тем же числом кадров. Если она уже Unknown/VPN или не имеет DPI-уверенности, отрицательные метки не принимаются: отсутствие handshake нельзя приписывать порче. Иначе порча принимается только при вердикте Unknown или известный VPN. Остальные известные протоколы отклоняются. Производные остаются в части исходной сессии, синтетические векторы в fit не добавляются.",
        "",
        "Порог 0.5, 120 деревьев, глубина 3, скорость 0.15 и seed 0 не менялись. Основные числа считаются по неперекрывающимся окнам с шагом 24. Окна с шагом 8 в обучение не входят и приведены отдельно.",
        "",
        "Обучающие веса задают равную априорную важность классов, семейств внутри класса и исходных capture_id внутри семейства: w = N / (2 * K_class * C_mask_class * N_capture_mask_class). Все окна сохраняются. Порчи с одним capture_id остаются одной исходной сессией. Длинный захват не получает большую массу за число окон. Это заданная популяция поддержки, а не оценка естественной частоты трафика. Отсутствующие отрицательные группы не выдумываются.",
        "",
        "| Часть | Маска | Профиль | Протокол маски | Учитель nDPI | Кадров | Окон |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    if ctx.get("base_control_exposed"):
        lines[8:8] = ["Базовые val/test уже оценивались до исправления баланса обучающей популяции. Их числа ниже являются открытой диагностикой. Финальный контроль на новых сессиях оценивается отдельно после фиксации хэша модели; эти сессии не входят в fit.", ""]
    for item in ctx["provenance"]["masks"]:
        lines.append(
            f"| {item['partition']} | {item['title']} | `{item['mask_id']}` | {item['spoof_protocol']} | "
            f"{item['ndpi_proto']} / {item['ndpi_confidence']} | {item['verified_packets']} | {item['primary_windows']} |"
        )
    lines.extend(
        [
            "",
            "## Числа",
            "",
            f"Обучающих окон: {ctx['counts']['train']}, из них туннель: {ctx['counts']['train_tunnel']}. "
            f"Проверка: {ctx['counts']['val']}. Контроль: {ctx['counts']['test']}. "
            "Окно называется туннелем, если вероятность строго больше 0.5. "
            f"Константа большинства, посчитанная только по train, на контроле всегда отвечает классом {ctx['majority_name']}.",
            "",
            "| Выбор | Точность | Balanced accuracy | Точность туннеля | Полнота туннеля | F1 | Ложный туннель | Пропуск туннеля | Окон |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for title, block in (
        ("Проверка, модель", val),
        ("Контроль, модель", test),
        ("Проверка, константа", ctx["metrics"]["val_majority"]),
        ("Контроль, константа", ctx["metrics"]["test_majority"]),
    ):
        lines.append(
            f"| {title} | {fmt(block['accuracy'])} | {fmt(block['balanced_accuracy'])} | {fmt(block['precision'])} | {fmt(block['recall'])} | "
            f"{fmt(block['f1'])} | {fmt(block['false_tunnel_rate'])} | {fmt(block['missed_tunnel_rate'])} | {block['n']} |"
        )
    old_test = ctx["metrics"].get("test_old")
    if old_test:
        lines.append(
            f"| Контроль, прежняя таблица | {fmt(old_test['accuracy'])} | {fmt(old_test['balanced_accuracy'])} | {fmt(old_test['precision'])} | "
            f"{fmt(old_test['recall'])} | {fmt(old_test['f1'])} | {fmt(old_test['false_tunnel_rate'])} | "
            f"{fmt(old_test['missed_tunnel_rate'])} | {old_test['n']} |"
        )
        lines.append("")
        lines.append(
            "Строка прежней таблицы считает эти же контрольные окна ранее выгруженной моделью. "
            "Это не метрики старого диагностического пилота, и по этой строке деревья не подбирались."
        )
    lines.append("")
    fp_lo, fp_hi = ctx["uncertainty"]["test_false_tunnel"]
    bar = "выполнен" if ctx["material_met"] else "не выполнен"
    lines.append(
        f"Заранее заданный зазор к константе равен {fmt(MATERIAL_MARGIN)}. "
        f"На контроле он {bar}: balanced accuracy {fmt(test['balanced_accuracy'])} против {fmt(ctx['metrics']['test_majority']['balanced_accuracy'])}. "
        "Balanced accuracy равна полусумме полноты обоих классов; обе константы имеют 0.5 независимо от большинства. Precision, recall и FPR приведены отдельно. "
        "После этой сверки деревья и порог не менялись."
    )
    lines.append("")
    lines.append(
        f"Ложный туннель на контроле: {fmt(test['false_tunnel_rate'])} "
        f"(интервал Уилсона {fmt(fp_lo)}-{fmt(fp_hi)}). Интервал считает окна независимыми. "
        "Окна не перекрываются, но каждая маска представлена одной сессией, поэтому разброс по маскам важнее ширины интервала."
    )
    lines.extend(["", "Контроль по маскам. Доля у целевых окон - это ложный туннель.", ""])
    lines.extend(_mask_table(ctx["per_mask_test"]))
    saturated = [item for item in ctx["per_mask_test"] if item["n_pos"] and item["pos_flagged"] is not None and item["pos_flagged"] >= 1.0 - 1e-12]
    if saturated:
        detail = ", ".join(f"{item['title']} (средняя p {fmt(item['pos_mean_p'])})" for item in saturated)
        lines.extend(["", f"Целевые окна целиком выше порога: {detail}. Средний F1 этого не скрывает."])
    lines.extend(["", "Проверка val, в подгонку не входила.", ""])
    lines.extend(_mask_table(ctx["per_mask_val"]))
    overlap = ctx["metrics"].get("test_overlap")
    if overlap:
        lines.extend(
            [
                "",
                f"Дополнительно, шаг 8, только контроль, в обучение не входил: окон {overlap['n']}, "
                f"точность {fmt(overlap['accuracy'])}, ложный туннель {fmt(overlap['false_tunnel_rate'])}, "
                f"F1 {fmt(overlap['f1'])}. Это зависимые повторы основных окон, основной вывод по ним не делается.",
            ]
        )
    lines.extend(
        [
            "",
            "## Деревья",
            "",
            "Порог узла записывается как наибольший f32, который не выше double-порога sklearn. "
            f"Расхождение листа на основных окнах: {ctx['branch_mismatches']}. "
            f"Наибольший зазор вероятности sklearn и встроенного обхода f32 на проверке и контроле: {fmt(ctx['sklearn_gap'], 6)}. "
            "Публикуемые метрики посчитаны встроенным обходом.",
            "",
            "Две полные подгонки на одних и тех же обучающих окнах дали одинаковые узлы, смещения деревьев и начальное значение. Сравнивались результаты двух обучений, а не два рендера одного результата.",
            "",
            "Наиболее используемые признаки:",
            "",
        ]
    )
    for name, value in ctx["importances"][:8]:
        lines.append(f"- {name}: {fmt(value, 3)}")
    lines.extend(["", "## Что отброшено", ""])
    if ctx["rejected"]:
        for item in ctx["rejected"]:
            lines.append(
                f"- {item['capture_id']} / {item['variant']}: {item['reason']} "
                f"(учитель {item['proto']}, уверенность {item['confidence']})"
            )
    else:
        lines.append("Все построенные отрицательные варианты учитель принял как Unknown или известный VPN.")
    versions = ctx["versions"]
    lines.extend(
        [
            "",
            "## Воспроизведение",
            "",
            f"Python {versions['python']}, scikit-learn {versions['sklearn']}, numpy {versions['numpy']}, "
            f"scipy {versions['scipy']}, joblib {versions['joblib']}, threadpoolctl {versions['threadpoolctl']}. "
            f"nDPI: {versions['ndpi']}. Потоки BLAS: 1. Пул учителя: {JOBS}. Seed {SEED}.",
            "",
            "Повтор при тех же захватах и тех же версиях должен дать ту же таблицу. Другая сборка sklearn режет деревья иначе, поэтому версии закреплены в requirements.txt.",
            "",
        ]
    )
    return "\n".join(lines)


def _mask_table(items: list[dict]) -> list[str]:
    lines = [
        "| Маска | Целевых окон | Ложный туннель | Средняя p | Отрицательных окон | Поймано | Средняя p |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in items:
        lines.append(
            f"| {item['title']} | {item['n_pos']} | {fmt(item['pos_flagged'])} | {fmt(item['pos_mean_p'])} | "
            f"{item['n_neg']} | {fmt(item['neg_flagged'])} | {fmt(item['neg_mean_p'])} |"
        )
    return lines


def ndpi_version(ndpi: str) -> str:
    proc = subprocess.run([ndpi, "-h"], capture_output=True, text=True, check=False)
    text = (proc.stdout or "") + (proc.stderr or "")
    for line in text.splitlines():
        if "nDPI" in line:
            return line.strip()
    return "nDPI 5"


def _is_ordered_subsequence(need: list[bytes], have: list[bytes]) -> bool:
    if not need:
        return False
    index = 0
    for item in have:
        if item == need[index]:
            index += 1
            if index == len(need):
                return True
    return False


def verified_upstream_ok(verified: list[bytes], pcap_path: Path) -> bool:
    """Кадры идут по порядку одного восходящего потока, с учетом повторов.

    Сплошной отрезок не требуется. Выборка каждого 16-го кадра и пропуски
    рукопожатия остаются допустимой подпоследовательностью того же потока.
    """
    matched = 0
    for upstream, payloads in pcapio.read_udp_directions(str(pcap_path)):
        if upstream and _is_ordered_subsequence(verified, payloads):
            matched += 1
    return matched == 1


def second_fit_matched(first: tuple, second: tuple) -> bool:
    """Истина только когда две подгонки совпали по узлам, смещениям и init."""
    return first == second


def build_dataset(captures: list[dict], ndpi: str, spoof: dict[str, str]) -> dict:
    prepared = []
    for capture in captures:
        packets = load_verified(capture["verified"])
        if len(packets) < F.WINDOW:
            raise RuntimeError(f"{capture['capture_id']}: меньше {F.WINDOW} проверенных кадров")
        if not verified_upstream_ok(packets, capture["pcap"]):
            raise RuntimeError(
                f"{capture['capture_id']}: проверенные кадры не являются "
                "подпоследовательностью одного восходящего потока"
            )
        item = dict(capture)
        item.update(
            {
                "packets": packets,
                "verified_sha256": sha256_file(capture["verified"]),
                "pcap_sha256": sha256_file(capture["pcap"]),
                "verified_packets": len(packets),
                "spoof_protocol": spoof.get(capture["mask_id"], ""),
                "header": band_fractions(packets),
            }
        )
        prepared.append(item)

    future_map = {}
    with ThreadPoolExecutor(max_workers=JOBS) as pool:
        for item in prepared:
            future = pool.submit(teacher.label_pcap, ndpi, str(item["pcap"]))
            future_map[future] = ("positive", item, None, None)
            baseline = pool.submit(judge_unchanged, ndpi, item["packets"][:NEG_PACKETS])
            future_map[baseline] = ("baseline", item, None, None)
            for variant in NEG_VARIANTS:
                payloads = corrupt(variant, item["packets"], stable_seed(item["capture_id"] + ":" + variant))
                future = pool.submit(judge_negative, ndpi, item["capture_id"], variant, payloads)
                future_map[future] = ("negative", item, variant, payloads)
        positive_results = {}
        baseline_results = {}
        negative_results = []
        for future in future_map:
            kind, item, variant, _payloads = future_map[future]
            if kind == "positive":
                positive_results[item["capture_id"]] = future.result()
            elif kind == "baseline":
                baseline_results[item["capture_id"]] = future.result()
            else:
                negative_results.append((item, future.result()))

    rows: list[dict] = []
    overlap_rows: list[dict] = []
    provenance_masks = []
    rejected = []
    accepted = []
    for item in prepared:
        flows, detected, rc = positive_results[item["capture_id"]]
        ok, reason = teacher.positive_ok(flows, detected, rc)
        proto = ",".join(flow.proto for flow in flows) or "none"
        confidence = ",".join(sorted({flow.confidence for flow in flows})) or "none"
        primary = rows_from_packets(item, "positive", "verified", 0, item["packets"], PRIMARY_STRIDE)
        if not primary:
            raise RuntimeError(f"{item['capture_id']}: нет основного окна")
        provenance_masks.append(
            {
                "mask_id": item["mask_id"],
                "title": item["title"],
                "partition": item["partition"],
                "capture_id": item["capture_id"],
                "workload_seed": item["workload_seed"],
                "spoof_protocol": item["spoof_protocol"],
                "verified_sha256": item["verified_sha256"],
                "pcap_sha256": item["pcap_sha256"],
                "verified_packets": item["verified_packets"],
                "ndpi_proto": proto,
                "ndpi_stack": ",".join(flow.stack for flow in flows),
                "ndpi_confidence": confidence,
                "ndpi_risks": sorted({risk for flow in flows for risk in flow.risks}),
                "ndpi_detected": detected,
                "ndpi_returncode": rc,
                "accepted_positive": ok,
                "positive_reason": reason,
                "standalone_context": baseline_results[item["capture_id"]],
                **({"implementation": item["implementation"], "repetition": item["repetition"]} if "implementation" in item else {}),
                "packet_selection": item.get("packet_selection", "authenticated_transport_observer_stride16"),
                "header": item["header"],
                "primary_windows": len(primary),
            }
        )
        if not ok:
            raise RuntimeError(f"{item['capture_id']}: положительная метка отклонена: {reason}")
        rows.extend(primary)
        overlap_rows.extend(rows_from_packets(item, "positive", "verified", 0, item["packets"], OVERLAP_STRIDE))

    for item, result in negative_results:
        result = guard_negative_context(result, baseline_results[item["capture_id"]])
        record = {key: value for key, value in result.items() if key != "payloads"}
        record["mask_id"] = item["mask_id"]
        record["partition"] = item["partition"]
        if result["accepted"] and result["payloads"] is not None:
            accepted.append(record)
            rows.extend(rows_from_packets(item, "negative", result["variant"], 1, result["payloads"], PRIMARY_STRIDE))
            overlap_rows.extend(rows_from_packets(item, "negative", result["variant"], 1, result["payloads"], OVERLAP_STRIDE))
        else:
            rejected.append(record)
    captures_for_leak = []
    for item in prepared:
        captures_for_leak.append(
            {
                "partition": item["partition"],
                "mask_id": item["mask_id"],
                "capture_id": item["capture_id"],
                "verified": item["verified"],
                "pcap": item["pcap"],
                "verified_sha256": item["verified_sha256"],
                "pcap_sha256": item["pcap_sha256"],
            }
        )
    problems = leakage_problems(captures_for_leak, rows)
    if problems:
        raise RuntimeError("утечка или дыра матрицы: " + "; ".join(problems))
    return {
        "rows": rows,
        "overlap_rows": overlap_rows,
        "provenance_masks": provenance_masks,
        "rejected": sorted(rejected, key=lambda item: (item["capture_id"], item["variant"])),
        "accepted": sorted(accepted, key=lambda item: (item["capture_id"], item["variant"])),
    }


def public_row(row: dict) -> dict:
    return {
        "partition": row["partition"],
        "mask_id": row["mask_id"],
        "capture_id": row["capture_id"],
        "role": row["role"],
        "variant": row["variant"],
        "y": row["y"],
        "start": row["start"],
        "stride": row["stride"],
        "x": [float(np.float32(value)) for value in row["x"]],
    }


def assert_public_text(text: str, extra: tuple[str, ...] = ()) -> None:
    for code in FORBIDDEN_CODEPOINTS:
        if chr(code) in text:
            raise RuntimeError("в публичном тексте запрещенный символ")
    for token in extra:
        if token and token in text:
            raise RuntimeError("в публичный текст попал локальный путь")
    if "/tmp/" in text:
        raise RuntimeError("в публичный текст попал локальный путь")


def write_assets(repo: Path, ctx: dict, model_text: str, extra_forbidden: tuple[str, ...] = ()) -> None:
    model_text = subprocess.run(
        ["rustfmt", "--edition", "2021"], input=model_text,
        capture_output=True, text=True, check=True,
    ).stdout
    asset_dir = repo / "assets" / "dpi"
    asset_dir.mkdir(parents=True, exist_ok=True)
    model_path = repo / "crates" / "aivpn-common" / "src" / "dpi_gate" / "model.rs"
    stored = [public_row(row) for row in sorted(ctx["rows"], key=sort_key)]
    window_lines = [json.dumps(row, ensure_ascii=True) for row in stored]
    assert_public_text("\n".join(window_lines), extra_forbidden)
    provenance = {
        "schema": 2,
        "matrix": "session_holdout_all_families",
        "model_sha256": hashlib.sha256(model_text.encode()).hexdigest(),
        "n_captures": len(ctx["provenance"]["masks"]),
        "feature_schema": {"version": F.FEATURE_SCHEMA_VERSION, "name": F.FEATURE_SCHEMA_NAME, "short_header_byte0": "0x40; spin and protected bits removed from features only"},
        "matched_training_sessions": sum(item.get("implementation") is not None and item["partition"] == "train" for item in ctx["provenance"]["masks"]),
        "primary_stride": PRIMARY_STRIDE,
        "overlap_stride": OVERLAP_STRIDE,
        "threshold": THRESHOLD,
        "material_margin": MATERIAL_MARGIN,
        "seed": SEED,
        "hyperparams": {"n_estimators": N_TREES, "max_depth": MAX_DEPTH, "learning_rate": LEARNING_RATE},
        "training_weights": ctx["training_weights"],
        "base_control_exposed": ctx.get("base_control_exposed", False),
        "material_criterion": "balanced_accuracy > constant_balanced_accuracy + margin",
        "jobs": JOBS,
        "blas_threads": 1,
        "versions": ctx["versions"],
        "masks": ctx["provenance"]["masks"],
        "rejected_negatives": ctx["rejected"],
        "accepted_negative_variants": ctx["accepted"],
        "old_model_sha256": ctx.get("old_model_sha256"),
        "no_payloads": True,
        "anchors": 0,
    }
    metrics = {
        "schema": 2,
        "feature_schema_version": F.FEATURE_SCHEMA_VERSION,
        "threshold": THRESHOLD,
        "material_margin": MATERIAL_MARGIN,
        "material_met": ctx["material_met"],
        "material_criterion": "balanced_accuracy > constant_balanced_accuracy + margin",
        "majority_class_tunnel": ctx["majority"] == 1,
        "counts": ctx["counts"],
        "metrics": ctx["metrics"],
        "per_mask_val": ctx["per_mask_val"],
        "per_mask_test": ctx["per_mask_test"],
        "importances": [{"name": name, "importance": value} for name, value in ctx["importances"]],
        "sklearn_probability_gap": ctx["sklearn_gap"],
        "branch_mismatches": ctx["branch_mismatches"],
        "second_fit_matched": ctx["second_fit_matched"],
        "uncertainty": {
            "test_false_tunnel_wilson95": list(ctx["uncertainty"]["test_false_tunnel"]),
            "note": "one session per mask; interval is narrower than mask-level uncertainty",
        },
    }
    heldout_rows = []
    for row, prob in zip(ctx["test_rows"], ctx["test_probs"]):
        features = json_roundtrip_features(row["x"])
        shipped = walk_prob(ctx["nodes"], ctx["offsets"], ctx["init"], LEARNING_RATE, features)
        heldout_rows.append(
            {
                "partition": "test",
                "mask_id": row["mask_id"],
                "capture_id": row["capture_id"],
                "role": row["role"],
                "variant": row["variant"],
                "y": row["y"],
                "start": row["start"],
                "x": features,
                "p": float(np.float32(shipped)),
            }
        )
    heldout = {
        "schema": 2,
        "feature_schema_version": F.FEATURE_SCHEMA_VERSION,
        "threshold": THRESHOLD,
        "material_margin": MATERIAL_MARGIN,
        "feature_names": list(F.FEATURE_NAMES),
        "train_count": ctx["counts"]["train"],
        "train_tunnel_count": ctx["counts"]["train_tunnel"],
        "rows": heldout_rows,
    }
    parity = {
        "schema": 2,
        "feature_schema_version": F.FEATURE_SCHEMA_VERSION,
        "windows": [
            {
                "name": "reference_mix",
                "packets": [
                    {"op": "stun", "msg_len": 56, "total": 76},
                    {"op": "stun", "msg_len": 20, "total": 40},
                    {"op": "stun", "msg_len": 8, "total": 28},
                    {"op": "rnd", "total": 1100, "seed": 3},
                    {"op": "rnd", "total": 1200, "seed": 9},
                    {"op": "rnd", "total": 200, "seed": 21},
                ],
                "x": json_roundtrip_features(F.vector(F.reference_window())),
            }
        ],
    }
    for first in (0x40, 0x7f):
        spec = [{"op": "quic_short", "total": 1200, "seed": 71, "byte0": first, "repeat": 24}]
        parity["windows"].append({"name": f"quic_short_{first}", "packets": spec, "x": json_roundtrip_features(F.vector(F.packets_from_spec(spec)))})
    parity["validation_cases"] = []
    for tp, fp, fn, tn, majority in (
        (1, 0, 0, 3, 0), (1, 0, 0, 3, 1), (3, 0, 0, 1, 0), (3, 0, 0, 1, 1),
        (0, 0, 1, 3, 0), (1, 3, 0, 0, 1), (0, 0, 0, 3, 0), (55, 45, 45, 55, 0),
    ):
        rows = [{"y": label} for label, count in ((1, tp), (0, fp), (1, fn), (0, tn)) for _ in range(count)]
        probabilities = [1.0] * (tp + fp) + [0.0] * (fn + tn)
        result = confusion(rows, probabilities)
        parity["validation_cases"].append({"tp": tp, "fp": fp, "fn": fn, "tn": tn, "majority_tunnel": bool(majority), "balanced_accuracy": result["balanced_accuracy"], "material_met": beats_constant(result, majority_metrics(rows, majority))})
    blobs = {
        "provenance.json": json.dumps(provenance, ensure_ascii=True, indent=2) + "\n",
        "metrics.json": json.dumps(metrics, ensure_ascii=True, indent=2) + "\n",
        "heldout_fixtures.json": json.dumps(heldout, ensure_ascii=True, indent=2) + "\n",
        "parity_fixtures.json": json.dumps(parity, ensure_ascii=True, indent=2) + "\n",
        "report.md": ctx["report"],
    }
    for name, text in blobs.items():
        assert_public_text(text, extra_forbidden)
    assert_public_text(model_text, extra_forbidden)
    with (asset_dir / "windows.jsonl").open("w") as handle:
        for line in window_lines:
            handle.write(line + "\n")
    for name, text in blobs.items():
        (asset_dir / name).write_text(text)
    model_path.write_text(model_text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--captures", type=Path, required=True)
    parser.add_argument("--matched-captures", type=Path)
    parser.add_argument("--base-control-exposed", action="store_true")
    parser.add_argument("--ndpi", type=Path, default=Path("target/dpi-tools/ndpi/example/ndpiReader"))
    parser.add_argument("--old-model", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    ndpi = str(args.ndpi if args.ndpi.is_absolute() else repo / args.ndpi)
    if not Path(ndpi).is_file():
        print(f"нет ndpiReader: {ndpi}", file=sys.stderr)
        return 2
    if args.old_model and model_feature_schema(args.old_model) != F.FEATURE_SCHEMA_VERSION:
        print("прежняя таблица имеет другую схему признаков; сравнение вероятностей отклонено", file=sys.stderr)
        return 2
    threadpool_limits(limits=1)
    assert_floor_examples()
    ok, worst = F.reference_ok()
    if not ok:
        print(f"эталонное окно признаков разошлось, относительная ошибка {worst}", file=sys.stderr)
        return 3
    try:
        captures = discover_captures(args.captures)
        if args.matched_captures:
            captures.extend(discover_matched_captures(args.matched_captures))
        print(f"захваты: {len(captures)}", file=sys.stderr)
        built = build_dataset(captures, ndpi, spoof_map(repo))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        print("частичный результат, модель не экспортировалась", file=sys.stderr)
        return 2

    rows = built["rows"]
    train_rows = [row for row in rows if row["partition"] == "train"]
    print(
        f"окна: всего {len(rows)}, train {len(train_rows)}, отклонено порч {len(built['rejected'])}",
        file=sys.stderr,
    )
    try:
        clf, nodes, offsets, init = fit_rows(train_rows)
        _clf2, nodes2, offsets2, init2 = fit_rows(train_rows)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 4
    note = f"primary stride {PRIMARY_STRIDE}. branch check follows. no anchor rows."
    matched = second_fit_matched((nodes, offsets, init), (nodes2, offsets2, init2))
    if not matched:
        print("повторное обучение дало другую таблицу", file=sys.stderr)
        return 4
    mismatches = sklearn_branch_mismatches(clf, nodes, offsets, rows)
    if mismatches:
        print(f"ветки f32 расходятся со sklearn: {mismatches}", file=sys.stderr)
        return 4
    note = f"primary stride {PRIMARY_STRIDE}. branch mismatches={mismatches}. second fit matched."

    def subset(partition: str) -> list[dict]:
        chosen = [row for row in rows if row["partition"] == partition]
        return sorted(chosen, key=sort_key)

    val_rows = subset("val")
    test_rows = subset("test")
    val_probs = score_rows(val_rows, nodes, offsets, init)
    test_probs = score_rows(test_rows, nodes, offsets, init)
    majority = majority_label(train_rows)
    metrics = {
        "val": confusion(val_rows, val_probs),
        "test": confusion(test_rows, test_probs),
        "val_majority": majority_metrics(val_rows, majority),
        "test_majority": majority_metrics(test_rows, majority),
        "train_insample": confusion(train_rows, score_rows(train_rows, nodes, offsets, init)),
    }
    overlap_test = [row for row in built["overlap_rows"] if row["partition"] == "test"]
    if overlap_test:
        metrics["test_overlap"] = confusion(overlap_test, score_rows(overlap_test, nodes, offsets, init))
    old_hash = None
    if args.old_model:
        parsed = parse_old_model(args.old_model)
        if not parsed:
            print("прежняя таблица не разобрана", file=sys.stderr)
            return 2
        old_nodes, old_offsets, old_init, old_lr = parsed
        old_probs = [walk_prob(old_nodes, old_offsets, old_init, old_lr, row["x"]) for row in test_rows]
        metrics["test_old"] = confusion(test_rows, old_probs)
        old_hash = sha256_file(args.old_model)

    held = val_rows + test_rows
    sklearn_gap = 0.0
    if held:
        matrix = np.asarray([row["x"] for row in held], dtype=np.float64)
        sk = clf.predict_proba(matrix)[:, list(clf.classes_).index("Unknown")]
        for prob, sk_prob in zip(score_rows(held, nodes, offsets, init), sk):
            sklearn_gap = max(sklearn_gap, abs(prob - float(sk_prob)))
    importances = sorted(
        zip(F.FEATURE_NAMES, [float(value) for value in clf.feature_importances_]),
        key=lambda item: -item[1],
    )
    versions = {
        "python": sys.version.split()[0],
        "sklearn": __import__("sklearn").__version__,
        "numpy": np.__version__,
        "scipy": __import__("scipy").__version__,
        "joblib": __import__("joblib").__version__,
        "threadpoolctl": __import__("threadpoolctl").__version__,
        "ndpi": ndpi_version(ndpi),
    }
    counts = {
        "train": len(train_rows),
        "train_tunnel": sum(row["y"] for row in train_rows),
        "val": len(val_rows),
        "test": len(test_rows),
    }
    material_met = beats_constant(metrics["test"], metrics["test_majority"])
    ctx = {
        "rows": rows,
        "training_weights": population_summary(train_rows),
        "base_control_exposed": args.base_control_exposed,
        "provenance": {"masks": built["provenance_masks"]},
        "metrics": metrics,
        "counts": counts,
        "majority": majority,
        "majority_name": "туннель" if majority == 1 else "цель",
        "material_met": material_met,
        "uncertainty": {"test_false_tunnel": wilson(metrics["test"]["fp"], metrics["test"]["fp"] + metrics["test"]["tn"])},
        "per_mask_test": per_mask(test_rows, test_probs),
        "per_mask_val": per_mask(val_rows, val_probs),
        "branch_mismatches": mismatches,
        "sklearn_gap": sklearn_gap,
        "importances": importances,
        "rejected": built["rejected"],
        "accepted": built["accepted"],
        "versions": versions,
        "old_model_sha256": old_hash,
        "nodes": nodes,
        "offsets": offsets,
        "init": init,
        "test_rows": test_rows,
        "test_probs": test_probs,
        "second_fit_matched": matched,
    }
    ctx["report"] = render_report(ctx)
    hidden = [str(args.captures.resolve())]
    if args.old_model:
        hidden.append(str(args.old_model.resolve()))
    try:
        assert_public_text(ctx["report"], tuple(hidden))
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 4
    write_assets(repo, ctx, render_model(nodes, offsets, init, note), tuple(hidden))
    print(
        f"готово: train={counts['train']} val={counts['val']} test={counts['test']} "
        f"test_acc={metrics['test']['accuracy']:.3f} test_fp={metrics['test']['false_tunnel_rate']:.3f} "
        f"material={'yes' if material_met else 'no'} rejected={len(built['rejected'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
