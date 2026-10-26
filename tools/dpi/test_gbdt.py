"""Проверки признаков, учителя, утечки и границы экспорта.

Тесты не подмешивают старые векторы в обучение и не ходят в сеть.
Сверка уже выгруженных окон с таблицей лежит в ShippedAssetTests и
запускается после обучения.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np
from threadpoolctl import threadpool_limits

import features
import pcapio
import teacher
import train_gbdt


def _touch_matrix(root: Path) -> None:
    for partition in train_gbdt.PARTITIONS:
        for mask_id in train_gbdt.MASKS:
            directory = root / partition
            directory.mkdir(parents=True, exist_ok=True)
            (directory / f"{mask_id}.pcap").write_bytes(b"pcap")
            (directory / f"{mask_id}.verified.json").write_text("[]")


def _flow(proto: str, stack: str, confidence: str, risk: str = "") -> str:
    risk_bit = f"[Risk: ** {risk} **]" if risk else ""
    return (
        f"1 [proto: 1.2/{proto}][Stack: {stack}][Encrypted]"
        f"[Confidence: {confidence}]{risk_bit}"
    )


def _detected(*names: str) -> str:
    body = "\n".join(names)
    return f"Detected protocols:\n{body}\nProtocol statistics:\n"


class FeatureTests(unittest.TestCase):
    def test_quic_short_header_spin_and_protected_bits_do_not_change_features(self) -> None:
        reference = bytes([0x40]) + features.rnd_pkt(1200, 71)[1:]
        expected = features.vector([reference] * 24)
        for byte0 in range(0x40, 0x80):
            packet = bytes([byte0]) + reference[1:]
            self.assertEqual(features.vector([packet] * 24), expected, byte0)

    def test_nonquic_first_byte_is_not_normalized(self) -> None:
        body = features.rnd_pkt(1200, 71)[1:]
        self.assertNotEqual(features.vector([b"\x80" + body] * 24), features.vector([b"\x81" + body] * 24))

    def test_reference_window_matches_published_vector(self) -> None:
        ok, worst = features.reference_ok()
        self.assertTrue(ok, worst)
        self.assertEqual(len(features.vector(features.reference_window())), features.N_FEATURES)
        self.assertEqual(features.N_FEATURES, 23)
        self.assertEqual(features.WINDOW, 24)

    def test_empty_window_is_zero(self) -> None:
        self.assertEqual(features.vector([]), [0.0] * 23)


class TeacherTests(unittest.TestCase):
    def test_unchanged_standalone_context_must_not_already_have_negative_label(self) -> None:
        unknown = teacher.parse_flows(_flow("Unknown", "Unknown", "DPI"))
        self.assertFalse(train_gbdt.unchanged_context_ok(unknown, 0)[0])
        rtp = teacher.parse_flows(_flow("RTP", "RTP", "DPI"))
        self.assertTrue(train_gbdt.unchanged_context_ok(rtp, 0)[0])
        self.assertFalse(train_gbdt.unchanged_context_ok(rtp, 1)[0])
        negative = {"accepted": True, "payloads": [b"opaque"], "reason": "Unknown"}
        rejected = train_gbdt.guard_negative_context(negative, {"accepted": False, "reason": "unchanged Unknown"})
        self.assertFalse(rejected["accepted"])
        self.assertIsNone(rejected["payloads"])
        self.assertTrue(train_gbdt.guard_negative_context(negative, {"accepted": True})["accepted"])

    def test_positive_requires_quic_or_stun_with_dpi(self) -> None:
        flows = teacher.parse_flows(_flow("QUIC", "QUIC", "DPI", "Unidirectional Traffic"))
        detected = teacher.detected_protocols(_detected("QUIC"))
        ok, _reason = teacher.positive_ok(flows, detected, 0)
        self.assertTrue(ok)
        stun = teacher.parse_flows(_flow("STUN", "STUN", "DPI"))
        ok, _reason = teacher.positive_ok(stun, teacher.detected_protocols(_detected("STUN")), 0)
        self.assertTrue(ok)

    def test_positive_rejects_weak_confidence_vpn_and_extra_protocol(self) -> None:
        weak = teacher.parse_flows(_flow("QUIC", "QUIC", "Match"))
        ok, _reason = teacher.positive_ok(weak, teacher.detected_protocols(_detected("QUIC")), 0)
        self.assertFalse(ok)
        vpn = teacher.parse_flows(_flow("QUIC", "QUIC", "DPI", "Known VPN"))
        ok, _reason = teacher.positive_ok(vpn, teacher.detected_protocols(_detected("QUIC")), 0)
        self.assertFalse(ok)
        mixed = teacher.parse_flows(_flow("STUN", "STUN", "DPI"))
        ok, _reason = teacher.positive_ok(mixed, teacher.detected_protocols(_detected("STUN", "TLS")), 0)
        self.assertFalse(ok)
        ok, _reason = teacher.positive_ok([], [], 0)
        self.assertFalse(ok)

    def test_negative_accepts_only_unknown_or_known_vpn(self) -> None:
        unknown = teacher.parse_flows(_flow("Unknown", "Unknown", "DPI"))
        ok, _reason = teacher.negative_ok(unknown, [], 0)
        self.assertTrue(ok)
        vpn = teacher.parse_flows(_flow("OpenVPN", "OpenVPN", "DPI"))
        ok, _reason = teacher.negative_ok(vpn, teacher.detected_protocols(_detected("OpenVPN")), 0)
        self.assertTrue(ok)

    def test_negative_rejects_target_and_other_protocols(self) -> None:
        quic = teacher.parse_flows(_flow("QUIC", "QUIC", "DPI"))
        ok, _reason = teacher.negative_ok(quic, teacher.detected_protocols(_detected("QUIC")), 0)
        self.assertFalse(ok)
        tls = teacher.parse_flows(_flow("TLS", "TLS", "DPI"))
        ok, _reason = teacher.negative_ok(tls, teacher.detected_protocols(_detected("TLS")), 0)
        self.assertFalse(ok)
        hidden = teacher.parse_flows(_flow("Unknown", "Unknown", "DPI"))
        ok, _reason = teacher.negative_ok(hidden, teacher.detected_protocols(_detected("STUN")), 0)
        self.assertFalse(ok)

    def test_monitoring_is_not_tor_and_tor_word_is_vpn(self) -> None:
        monitored = teacher.parse_flows(_flow("QUIC", "QUIC", "DPI", "Monitoring"))
        self.assertFalse(teacher.is_vpn(monitored[0]))
        ok, _reason = teacher.positive_ok(monitored, teacher.detected_protocols(_detected("QUIC")), 0)
        self.assertTrue(ok)
        named = teacher.parse_flows(_flow("Monitoring", "Monitoring", "DPI"))
        self.assertFalse(teacher.is_vpn(named[0]))
        tor = teacher.parse_flows(_flow("TOR", "TOR", "DPI"))
        self.assertTrue(teacher.is_vpn(tor[0]))
        ok, _reason = teacher.positive_ok(tor, teacher.detected_protocols(_detected("TOR")), 0)
        self.assertFalse(ok)
        ok, _reason = teacher.negative_ok(tor, teacher.detected_protocols(_detected("TOR")), 0)
        self.assertTrue(ok)
        phrase = teacher.parse_flows(_flow("Unknown", "Unknown", "DPI", "Suspicious TOR relay"))
        self.assertTrue(teacher.is_vpn(phrase[0]))

    def test_nonzero_ndpi_exit_blocks_every_label(self) -> None:
        quic = teacher.parse_flows(_flow("QUIC", "QUIC", "DPI"))
        detected = teacher.detected_protocols(_detected("QUIC"))
        ok, reason = teacher.positive_ok(quic, detected, 1)
        self.assertFalse(ok)
        self.assertIn("1", reason)
        ok, _reason = teacher.positive_ok(quic, detected, 0)
        self.assertTrue(ok)
        unknown = teacher.parse_flows(_flow("Unknown", "Unknown", "DPI"))
        ok, reason = teacher.negative_ok(unknown, [], 2)
        self.assertFalse(ok)
        self.assertIn("2", reason)
        ok, _reason = teacher.negative_ok(unknown, [], 0)
        self.assertTrue(ok)
        ok, _reason = teacher.negative_ok(unknown, [], -9)
        self.assertFalse(ok)


class LeakageTests(unittest.TestCase):
    def test_matched_repetitions_are_bound_to_train_or_heldout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.pcap").write_bytes(b"pcap")
            (root / "a.json").write_text("[]")
            row = {"partition": "train", "mask_id": "quic_https_v2", "capture_id": "train/matched-r0-c0-masque", "implementation": "masque", "repetition": 0, "pcap": "a.pcap", "verified": "a.json"}
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"captures": [row]}))
            captures = train_gbdt.discover_matched_captures(root)
            self.assertEqual(captures[0]["capture_id"], row["capture_id"])
            row["repetition"] = 2
            manifest.write_text(json.dumps({"captures": [row]}))
            with self.assertRaises(ValueError):
                train_gbdt.discover_matched_captures(root)
            row["partition"] = "test"
            row["capture_id"] = "test/matched-r2-c0-masque"
            manifest.write_text(json.dumps({"captures": [row]}))
            self.assertEqual(train_gbdt.discover_matched_captures(root)[0]["partition"], "test")

    def test_verified_data_copy_is_rejected_even_if_pcap_metadata_changes(self) -> None:
        captures = []
        for partition in train_gbdt.PARTITIONS:
            for mask_id in train_gbdt.MASKS:
                identity = f"{partition}/{mask_id}"
                captures.append({"partition": partition, "mask_id": mask_id,
                                 "capture_id": identity, "verified_sha256": "verified:" + identity,
                                 "pcap_sha256": "pcap:" + identity})
        self.assertEqual(train_gbdt.leakage_problems(captures, []), [])
        pcap_only = [dict(item) for item in captures]
        pcap_only[10]["pcap_sha256"] = pcap_only[0]["pcap_sha256"]
        pcap_problems = train_gbdt.leakage_problems(pcap_only, [])
        self.assertTrue(any("pcap_sha256" in item for item in pcap_problems))
        self.assertFalse(any("verified_sha256" in item for item in pcap_problems))
        captures[10]["verified_sha256"] = captures[0]["verified_sha256"]
        verified_problems = train_gbdt.leakage_problems(captures, [])
        self.assertTrue(any("verified_sha256" in item for item in verified_problems))
        self.assertTrue(verified_problems)

    def test_directory_matrix_requires_all_thirty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _touch_matrix(root)
            found = train_gbdt.discover_captures(root)
            self.assertEqual(len(found), 30)
            (root / "train" / "whatsapp_voip_v1.pcap").unlink()
            with self.assertRaises(ValueError):
                train_gbdt.discover_captures(root)

    def test_manifest_rejects_shared_file_and_missing_family(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _touch_matrix(root)
            captures = []
            for partition in train_gbdt.PARTITIONS:
                for mask_id in train_gbdt.MASKS:
                    captures.append(
                        {
                            "partition": partition,
                            "mask_id": mask_id,
                            "pcap": f"{partition}/{mask_id}.pcap",
                            "verified": f"{partition}/{mask_id}.verified.json",
                        }
                    )
            (root / "manifest.json").write_text(json.dumps({"captures": captures}))
            self.assertEqual(len(train_gbdt.discover_captures(root)), 30)
            captures[0]["pcap"] = captures[1]["pcap"]
            (root / "manifest.json").write_text(json.dumps({"captures": captures}))
            with self.assertRaises(ValueError):
                train_gbdt.discover_captures(root)
            del captures[0]
            (root / "manifest.json").write_text(json.dumps({"captures": captures}))
            with self.assertRaises(ValueError):
                train_gbdt.discover_captures(root)

    def test_same_bytes_and_cross_partition_row_are_leakage(self) -> None:
        captures = []
        for index, (partition, mask_id) in enumerate(sorted(train_gbdt.expected_pairs())):
            captures.append(
                {
                    "partition": partition,
                    "mask_id": mask_id,
                    "capture_id": f"{partition}/{mask_id}",
                    "verified_sha256": f"v{index}",
                    "pcap_sha256": f"p{index}",
                }
            )
        train_cap = next(item for item in captures if item["partition"] == "train")
        other = next(item for item in captures if item["capture_id"] != train_cap["capture_id"])
        other["verified_sha256"] = train_cap["verified_sha256"]
        other["pcap_sha256"] = train_cap["pcap_sha256"]
        rows = [
            {
                "partition": "val",
                "mask_id": train_cap["mask_id"],
                "capture_id": train_cap["capture_id"],
                "y": 0,
            },
            {
                "partition": "test",
                "mask_id": train_cap["mask_id"],
                "capture_id": train_cap["capture_id"],
                "y": 0,
            },
        ]
        problems = train_gbdt.leakage_problems(captures, rows)
        self.assertTrue(any("одинаковые байты" in item for item in problems))
        self.assertTrue(any("лежит в части" in item for item in problems))
        self.assertTrue(any("две части" in item for item in problems))


class ExportTests(unittest.TestCase):
    def test_floor_keeps_the_double_branch(self) -> None:
        train_gbdt.assert_floor_examples()
        left = np.float32(1.0)
        right = np.nextafter(left, np.float32(np.inf))
        mid = (float(left) + float(right)) / 2.0
        floored = train_gbdt.floor_f32(mid)
        self.assertEqual(floored, left)
        self.assertLessEqual(float(np.float64(floored)), mid)
        self.assertGreater(float(right), mid)
        self.assertFalse(float(right) <= float(floored))

    def test_two_fits_export_the_same_table(self) -> None:
        threadpool_limits(limits=1)
        rng = np.random.RandomState(0)
        rows = []
        for index in range(40):
            rows.append(
                {
                    "partition": "train",
                    "mask_id": "quic_https_v2",
                    "capture_id": "train/quic_https_v2",
                    "role": "positive" if index % 2 == 0 else "negative",
                    "variant": "unit",
                    "y": index % 2,
                    "start": index,
                    "stride": 24,
                    "x": [float(np.float32(value)) for value in rng.normal(size=features.N_FEATURES)],
                }
            )
        _clf_a, nodes_a, offsets_a, init_a = train_gbdt.fit_rows(rows)
        _clf_b, nodes_b, offsets_b, init_b = train_gbdt.fit_rows(rows)
        self.assertEqual((nodes_a, offsets_a, init_a), (nodes_b, offsets_b, init_b))
        note = "unit"
        self.assertEqual(
            train_gbdt.render_model(nodes_a, offsets_a, init_a, note),
            train_gbdt.render_model(nodes_b, offsets_b, init_b, note),
        )

    def test_public_row_has_no_payload(self) -> None:
        row = {
            "partition": "train",
            "mask_id": "quic_https_v2",
            "capture_id": "train/quic_https_v2",
            "role": "positive",
            "variant": "verified",
            "y": 0,
            "start": 0,
            "stride": 24,
            "x": [1.0] * 23,
            "payloads": [b"\x00"],
        }
        public = train_gbdt.public_row(row)
        self.assertNotIn("payloads", public)
        self.assertEqual(set(public), {
            "partition",
            "mask_id",
            "capture_id",
            "role",
            "variant",
            "y",
            "start",
            "stride",
            "x",
        })

    def test_tiny_probability_gap_is_not_printed_as_zero(self) -> None:
        gap = 8.161429210229443e-08
        text = train_gbdt.fmt(gap, 6)
        self.assertEqual(text, "8.161429e-08")
        self.assertNotEqual(float(text), 0.0)
        self.assertEqual(train_gbdt.fmt(0.0, 6), "0.000000")
        self.assertEqual(train_gbdt.fmt(0.0, 3), "0.000")
        self.assertEqual(train_gbdt.fmt(0.025, 3), "0.025")
        self.assertEqual(train_gbdt.fmt(None), "нет")

    def test_second_fit_flag_is_the_comparison(self) -> None:
        same = ((-1, 0.0, 0, 0, 1.0), [0, 1], 0.25)
        other = ((-1, 0.0, 0, 0, 2.0), [0, 1], 0.25)
        self.assertTrue(train_gbdt.second_fit_matched(same, same))
        self.assertFalse(train_gbdt.second_fit_matched(same, other))
        source = Path(train_gbdt.__file__).read_text()
        self.assertIn('"second_fit_matched": ctx["second_fit_matched"]', source)
        self.assertNotIn('"second_fit_matched": True', source)


def _unique_payloads(count: int, mark: int) -> list[bytes]:
    return [bytes((index & 0xFF, mark, (index * 17 + mark) & 0xFF)) for index in range(count)]


class CaptureMembershipTests(unittest.TestCase):
    def test_uplink_pcap_bytes_stay_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "up.pcap"
            pcapio.write_uplink_pcap(str(path), [b"\x01\x02", b"\x03", b"abcd"])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(digest, "137c40d921b4fa58e66283464a87a10ff2224c37404eb23ef6d35254ef7f281e")

    def test_every_sixteenth_and_gapped_subsequence_stays_valid(self) -> None:
        packets = _unique_payloads(80, 9)
        every16 = packets[3::16]
        irregular = [packets[3], packets[20], packets[36], packets[52]]
        self.assertGreater(len(every16), 2)
        self.assertNotEqual(every16, packets[: len(every16)])
        self.assertNotEqual([packets.index(item) for item in irregular], list(range(len(irregular))))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "up.pcap"
            pcapio.write_uplink_pcap(str(path), packets)
            self.assertTrue(train_gbdt.verified_upstream_ok(every16, path))
            self.assertTrue(train_gbdt.verified_upstream_ok(irregular, path))
            self.assertTrue(train_gbdt.verified_upstream_ok(packets[4:12], path))
            wire = set(pcapio.read_udp_payloads(str(path)))
            self.assertTrue(all(item in wire for item in every16))

    def test_upstream_direction_does_not_depend_on_port_order(self) -> None:
        packets = _unique_payloads(40, 9)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "high-server-port.pcap"
            frames = [(bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2)), 40000, 60000, payload) for payload in packets]
            pcapio.write_directed_udp_pcap(str(path), frames)
            self.assertTrue(train_gbdt.verified_upstream_ok(packets[::16], path))

    def test_order_multiplicity_mix_and_downlink_are_rejected(self) -> None:
        packets = _unique_payloads(40, 9)
        sampled = packets[1::16]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            uplink = root / "up.pcap"
            pcapio.write_uplink_pcap(str(uplink), packets)
            self.assertFalse(train_gbdt.verified_upstream_ok(list(reversed(sampled)), uplink))
            self.assertFalse(train_gbdt.verified_upstream_ok(sampled + sampled[:1], uplink))

            other = _unique_payloads(8, 4)
            mixed = [packets[0], other[0]]
            frames = [
                (bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2)), 50000, 443, payload)
                for payload in packets[:4]
            ]
            frames.extend(
                (bytes((192, 0, 2, 1)), bytes((192, 0, 2, 3)), 50001, 443, payload)
                for payload in other[:4]
            )
            mix_path = root / "mix.pcap"
            pcapio.write_directed_udp_pcap(str(mix_path), frames)
            wire = set(pcapio.read_udp_payloads(str(mix_path)))
            self.assertTrue(all(item in wire for item in mixed))
            self.assertFalse(train_gbdt.verified_upstream_ok(mixed, mix_path))

            duplicated = [
                (bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2)), 50000, 443, payload)
                for payload in sampled
            ]
            duplicated.extend(
                (bytes((192, 0, 2, 10)), bytes((192, 0, 2, 2)), 50010, 443, payload)
                for payload in sampled
            )
            dup_path = root / "dup.pcap"
            pcapio.write_directed_udp_pcap(str(dup_path), duplicated)
            self.assertFalse(train_gbdt.verified_upstream_ok(sampled, dup_path))

            downlink = [
                (bytes((192, 0, 2, 2)), bytes((192, 0, 2, 1)), 443, 50000, payload)
                for payload in sampled
            ]
            down_path = root / "down.pcap"
            bootstrap = (bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2)), 50000, 443, b"bootstrap")
            pcapio.write_directed_udp_pcap(str(down_path), [bootstrap] + downlink)
            self.assertEqual(pcapio.read_udp_payloads(str(down_path)), [b"bootstrap"] + sampled)
            self.assertFalse(train_gbdt.verified_upstream_ok(sampled, down_path))


class PopulationTests(unittest.TestCase):
    def test_weights_reject_empty_one_class_and_nontrain_input(self) -> None:
        for rows in ([], [{"mask_id": "quic_https_v2", "capture_id": "train/a", "y": 0}], [{"partition": "test", "mask_id": "quic_https_v2", "capture_id": "test/a", "y": 0}]):
            with self.assertRaises(ValueError):
                train_gbdt.population_weights(rows)

    def test_perfect_model_beats_both_constant_majorities(self) -> None:
        for labels in ([0, 0, 0, 1], [0, 1, 1, 1]):
            rows = [{"y": label} for label in labels]
            perfect = train_gbdt.confusion(rows, [float(label) for label in labels])
            for majority in (0, 1):
                constant = train_gbdt.majority_metrics(rows, majority)
                self.assertTrue(train_gbdt.beats_constant(perfect, constant))
                self.assertEqual(constant["balanced_accuracy"], 0.5)
            self.assertEqual(perfect["balanced_accuracy"], 1.0)

    def test_one_class_model_cannot_beat_a_constant(self) -> None:
        rows = [{"y": label} for label in [0, 0, 0, 1]]
        for label in (0, 1):
            constant = train_gbdt.majority_metrics(rows, label)
            self.assertFalse(train_gbdt.beats_constant(constant, constant))
        one_class = train_gbdt.confusion([{"y": 0}], [0.0])
        self.assertIsNone(one_class["balanced_accuracy"])
        self.assertFalse(train_gbdt.beats_constant(one_class, one_class))

    def test_class_family_weights_keep_all_rows_and_equal_group_mass(self) -> None:
        rows = []
        for mask in train_gbdt.MASKS:
            for label in (0, 1):
                count = 100 if mask == "quic_https_v2" else 2
                rows.extend({"mask_id": mask, "capture_id": f"train/{mask}", "y": label} for _ in range(count))
        weights = train_gbdt.population_weights(rows)
        self.assertEqual(len(weights), len(rows))
        self.assertTrue(all(weight > 0 for weight in weights))
        self.assertAlmostEqual(sum(weights), len(rows))
        for label in (0, 1):
            mass = sum(weight for row, weight in zip(rows, weights) if row["y"] == label)
            self.assertAlmostEqual(mass, len(rows) / 2)
            for mask in train_gbdt.MASKS:
                group = sum(weight for row, weight in zip(rows, weights) if row["y"] == label and row["mask_id"] == mask)
                self.assertAlmostEqual(group, len(rows) / 20)
        shuffled = list(reversed(rows))
        self.assertEqual(list(train_gbdt.population_weights(shuffled)), list(reversed(weights)))

    def test_original_capture_mass_does_not_depend_on_windows_or_negative_variants(self) -> None:
        rows = []
        for label in (0, 1):
            for capture, count in (("train/short", 2), ("train/long", 100)):
                rows.extend({"mask_id": "quic_https_v2", "capture_id": capture, "y": label, "variant": f"variant{index % 4}"} for index in range(count))
        weights = train_gbdt.population_weights(rows)
        for label in (0, 1):
            for capture in ("train/short", "train/long"):
                mass = sum(weight for row, weight in zip(rows, weights) if row["y"] == label and row["capture_id"] == capture)
                self.assertAlmostEqual(mass, len(rows) / 4)


class ShippedAssetTests(unittest.TestCase):
    def test_final_control_is_disjoint_and_matches_frozen_model_per_capture(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        assets = repo / "assets/dpi"
        model = repo / "crates/aivpn-common/src/dpi_gate/model.rs"
        final = json.loads((assets / "heldout_fixtures.json").read_text())["final_control"]
        provenance = json.loads((assets / "provenance.json").read_text())
        self.assertFalse(final["training_use"])
        self.assertTrue(final["evaluated_after_model_freeze"])
        self.assertEqual(final["model_sha256"], train_gbdt.sha256_file(model))
        self.assertEqual(final["feature_schema_version"], features.FEATURE_SCHEMA_VERSION)
        self.assertEqual(len(provenance["final_control_sources"]), 42)
        original = {item[key] for item in provenance["masks"] for key in ("pcap_sha256", "verified_sha256")}
        fresh = [item[key] for item in provenance["final_control_sources"] for key in ("pcap_sha256", "verified_sha256")]
        self.assertEqual(len(set(fresh)), 84)
        self.assertFalse(original.intersection(fresh))
        parsed = train_gbdt.parse_old_model(model)
        rows = final["rows"]
        probabilities = [train_gbdt.walk_prob(*parsed, row["x"]) for row in rows]
        for row, probability in zip(rows, probabilities):
            self.assertAlmostEqual(probability, row["p"], places=6)
            self.assertEqual(probability > 0.5, row["y"] == 1)
        self.assertEqual({row["mask_id"] for row in rows}, set(train_gbdt.MASKS))
        self.assertEqual(len({row["capture_id"] for row in rows}), 42)
        self.assertEqual(train_gbdt.confusion(rows, probabilities), final["metrics"]["raw"])
        for cohort in final["cohorts"].values():
            self.assertEqual(cohort["raw"]["fp"], 0)
            self.assertEqual(cohort["raw"]["fn"], 0)
            self.assertTrue(cohort["material_met"])
            self.assertEqual(cohort["macro"]["equal_family_balanced_accuracy"], 1.0)

    def test_shipped_windows_match_model_and_beat_constant(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        model_path = repo / "crates/aivpn-common/src/dpi_gate/model.rs"
        asset_dir = repo / "assets/dpi"
        parsed = train_gbdt.parse_old_model(model_path)
        self.assertIsNotNone(parsed)
        nodes, offsets, init, lr = parsed
        self.assertEqual(lr, float(np.float32(train_gbdt.LEARNING_RATE)))
        windows = [
            json.loads(line)
            for line in (asset_dir / "windows.jsonl").read_text().splitlines()
            if line.strip()
        ]
        heldout = json.loads((asset_dir / "heldout_fixtures.json").read_text())
        metrics = json.loads((asset_dir / "metrics.json").read_text())
        provenance = json.loads((asset_dir / "provenance.json").read_text())
        self.assertEqual(heldout["schema"], 2)
        self.assertEqual(metrics["schema"], 2)
        self.assertEqual(provenance["anchors"], 0)
        self.assertGreaterEqual(provenance["n_captures"], 30)
        self.assertEqual(len(provenance["masks"]), provenance["n_captures"])
        self.assertEqual(provenance["feature_schema"]["version"], features.FEATURE_SCHEMA_VERSION)
        hashes = {(item["verified_sha256"], item["pcap_sha256"]) for item in provenance["masks"]}
        self.assertEqual(len(hashes), provenance["n_captures"])
        pairs = {(item["partition"], item["mask_id"]) for item in provenance["masks"]}
        self.assertEqual(pairs, train_gbdt.expected_pairs())
        self.assertEqual({row["stride"] for row in windows}, {train_gbdt.PRIMARY_STRIDE})
        identities = {item["capture_id"]: (item["partition"], item["mask_id"]) for item in provenance["masks"]}
        for row in windows:
            self.assertNotIn("payload", json.dumps(row))
            self.assertEqual(identities[row["capture_id"]], (row["partition"], row["mask_id"]))
        blob = "\n".join(path.read_text(errors="ignore") for path in asset_dir.iterdir() if path.is_file())
        blob += model_path.read_text(errors="ignore")
        for code in train_gbdt.FORBIDDEN_CODEPOINTS:
            self.assertNotIn(chr(code), blob)
        self.assertNotIn("/tmp/", blob)
        self.assertNotIn("anchor_rounds", blob)
        train_rows = [row for row in windows if row["partition"] == "train"]
        test_rows = [row for row in windows if row["partition"] == "test"]
        self.assertEqual(len(train_rows), heldout["train_count"])
        self.assertEqual(sum(row["y"] for row in train_rows), heldout["train_tunnel_count"])
        self.assertEqual(len(test_rows), len(heldout["rows"]))
        by_key = {
            (row["capture_id"], row["role"], row["variant"], row["start"]): row for row in heldout["rows"]
        }
        probs = []
        for row in test_rows:
            key = (row["capture_id"], row["role"], row["variant"], row["start"])
            shipped = by_key[key]
            self.assertEqual(shipped["x"], row["x"])
            prob = train_gbdt.walk_prob(nodes, offsets, init, lr, row["x"])
            self.assertAlmostEqual(prob, shipped["p"], places=5)
            self.assertEqual(prob > train_gbdt.THRESHOLD, shipped["p"] > train_gbdt.THRESHOLD)
            probs.append(prob)
        got = train_gbdt.confusion(test_rows, probs)
        majority = train_gbdt.majority_label(train_rows)
        baseline = train_gbdt.majority_metrics(test_rows, majority)
        self.assertAlmostEqual(got["accuracy"], metrics["metrics"]["test"]["accuracy"], places=6)
        self.assertAlmostEqual(got["false_tunnel_rate"], metrics["metrics"]["test"]["false_tunnel_rate"], places=6)
        self.assertTrue(train_gbdt.beats_constant(got, baseline))
        self.assertTrue(metrics["material_met"])
        masks = {item["mask_id"] for item in metrics["per_mask_test"]}
        self.assertEqual(masks, set(train_gbdt.MASKS))


if __name__ == "__main__":
    unittest.main()
