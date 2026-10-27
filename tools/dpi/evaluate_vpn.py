"""Проверка неизменной таблицы на независимых захватах настоящего VPN.

В обучение эти окна не попадают. В отчет пишутся только признаки и хэши,
без кадров, ключей, адресов и путей к исходным захватам.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import features as F
import teacher
import train_gbdt as T


def evaluate(captures: Path, model_path: Path, ndpi: str, provenance_path: Path) -> dict:
    provenance = json.loads(provenance_path.read_text())
    model_hash = T.sha256_file(model_path)
    if provenance.get("model_sha256") != model_hash:
        raise ValueError("Источники обучения относятся к другой таблице GBDT")
    sources = provenance.get("masks")
    if not isinstance(sources, list) or not sources:
        raise ValueError("Нет источников обучения для проверки независимости")
    training_hashes = {item[key] for item in sources for key in ("pcap_sha256", "verified_sha256")}
    model = T.parse_old_model(model_path)
    if model is None:
        raise ValueError("Не удалось прочитать таблицу GBDT")
    results = []
    paths = sorted(captures.glob("*/*.verified.json"))
    if not paths:
        raise ValueError("Нет независимых захватов VPN")
    seen = set()
    for verified in paths:
        pcap = verified.with_name(verified.name.removesuffix(".verified.json") + ".pcap")
        hashes = (T.sha256_file(verified), T.sha256_file(pcap))
        if any(value in training_hashes for value in hashes):
            raise ValueError("Захват уже использовался при обучении или контроле GBDT")
        if any(value in seen for value in hashes):
            raise ValueError("Один захват повторен в проверке")
        seen.update(hashes)
        packets = T.load_verified(verified)
        if not T.verified_upstream_ok(packets, pcap):
            raise ValueError("Проверенные кадры не принадлежат одному восходящему потоку PCAP")
        flows, detected, code = teacher.label_pcap(ndpi, str(pcap))
        if code != 0 or not flows or not all(teacher.is_vpn(flow) for flow in flows):
            raise ValueError("Учитель не подтвердил известный VPN")
        rows = []
        for start in T.window_starts(len(packets), F.WINDOW):
            x = F.vector(packets[start:start + F.WINDOW])
            probability = T.walk_prob(*model, x)
            rows.append({"start": start, "x": x, "p": probability})
        if not rows:
            raise ValueError("Слишком мало кадров для полного окна")
        results.append({"pcap_sha256": hashes[1], "verified_sha256": hashes[0],
                        "teacher_protocols": detected, "samples": len(packets), "rows": rows})
    count = sum(len(item["rows"]) for item in results)
    detected = sum(row["p"] > T.THRESHOLD for item in results for row in item["rows"])
    return {"schema": 1, "model_sha256": model_hash,
            "training_provenance_sha256": T.sha256_file(provenance_path),
            "training_overlap_checked": True,
            "threshold": T.THRESHOLD, "training_use": False, "stride": F.WINDOW,
            "windows": count, "detected": detected, "captures": results}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--captures", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--training-provenance", type=Path, required=True)
    parser.add_argument("--ndpi", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.captures, args.model, args.ndpi, args.training_provenance)
    text = json.dumps(result, ensure_ascii=True, indent=2) + "\n"
    T.assert_public_text(text)
    args.output.write_text(text)
    print(f"VPN: {result['detected']}/{result['windows']} окон распознано")
    return 0 if result["detected"] == result["windows"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
