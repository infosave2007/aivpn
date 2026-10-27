"""Проверяет границу независимой оценки, без сети и обучения."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate_vpn as E
import pcapio
import teacher


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.model = Path(__file__).resolve().parents[2] / "crates/aivpn-common/src/dpi_gate/model.rs"
        session = self.root / "captures/session"
        session.mkdir(parents=True)
        self.packets = [bytes([4, 0, 0, 0, index]) + bytes(95) for index in range(24)]
        self.verified = session / "vpn.verified.json"
        self.verified.write_text(json.dumps([packet.hex() for packet in self.packets]))
        pcapio.write_uplink_pcap(str(session / "vpn.pcap"), self.packets)
        self.provenance = self.root / "provenance.json"
        self.sources = {"model_sha256": E.T.sha256_file(self.model),
                        "masks": [{"pcap_sha256": "a" * 64, "verified_sha256": "b" * 64}]}
        self.provenance.write_text(json.dumps(self.sources))
        self.label = ([teacher.FlowLabel("WireGuard", "WireGuard", "DPI", [])], ["WireGuard"], 0)

    def evaluate(self):
        return E.evaluate(self.root / "captures", self.model, "unused", self.provenance)

    def test_matching_sources_are_required_before_labeling(self):
        for change in ["wrong_model", "same_capture"]:
            with self.subTest(change=change), mock.patch.object(teacher, "label_pcap") as label:
                sources = json.loads(json.dumps(self.sources))
                if change == "wrong_model":
                    sources["model_sha256"] = "0" * 64
                else:
                    sources["masks"][0]["verified_sha256"] = E.T.sha256_file(self.verified)
                self.provenance.write_text(json.dumps(sources))
                with self.assertRaises(ValueError):
                    self.evaluate()
                label.assert_not_called()

    def test_failed_teacher_cannot_produce_a_report(self):
        with mock.patch.object(teacher, "label_pcap", return_value=(*self.label[:2], 1)):
            with self.assertRaises(ValueError):
                self.evaluate()

    def test_result_contains_bindings_and_features_without_packets_or_paths(self):
        with mock.patch.object(teacher, "label_pcap", return_value=self.label):
            result = self.evaluate()
        self.assertTrue(result["training_overlap_checked"])
        self.assertFalse(result["training_use"])
        self.assertEqual(result["model_sha256"], E.T.sha256_file(self.model))
        self.assertEqual(result["training_provenance_sha256"], E.T.sha256_file(self.provenance))
        self.assertEqual(result["windows"], 1)
        public = json.dumps(result)
        self.assertNotIn(str(self.root), public)
        self.assertNotIn(self.packets[0].hex(), public)


if __name__ == "__main__":
    unittest.main()
