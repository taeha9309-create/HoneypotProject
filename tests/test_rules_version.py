"""Synthetic approval, output, and regression tests."""
import tempfile
import unittest
from pathlib import Path

from ml.analysis import rules_version, splits


class RulesVersionTests(unittest.TestCase):
    def test_only_approved_candidate_can_make_version_and_baseline_is_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            baseline = Path(folder) / "rules.yaml"
            baseline.write_text("- id: B19\n", encoding="utf-8")
            original = baseline.read_bytes()
            candidate = {
                "id": "X06", "status": "proposed", "name": "Probe",
                "protocol": "telnet", "normalized_sequence_patterns": ["safe"],
                "reviewer": "test", "decided_utc": "test", "reason": "synthetic",
                "baseline_rules_sha256": splits.sha256_file(baseline),
                "freeze_sha256": "synthetic", "normalizer": {}, "development_input_sha256": {},
            }
            for status in ("proposed", "rejected"):
                candidate["status"] = status
                with self.assertRaises(ValueError):
                    rules_version.approved_version(candidate, baseline, "v001")
            candidate["status"] = "approved"
            result = rules_version.approved_version(candidate, baseline, "v001")
            self.assertEqual(result["added_rule"]["id"], "X06")
            self.assertEqual(result["baseline_rules"], [{"id": "B19"}])
            self.assertEqual(baseline.read_bytes(), original)

    def test_report_counts_lost_hits_and_incremental_specificity(self):
        scores = rules_version.comparison([
            ({"B19"}, {"B19", "X06"}), ({"B01"}, set()), (set(), {"X06"}),
        ], "X06")
        self.assertEqual(scores["lost_rule_hits"], 1)
        self.assertEqual(scores["candidate"]["new_coverage"], 1)
        self.assertEqual(scores["candidate"]["b19_only_refined"], 1)

    def test_version_output_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules_v001.yaml"
            rules_version.write_new(path, "old")
            with self.assertRaises(FileExistsError):
                rules_version.write_new(path, "new")
            self.assertEqual(path.read_text(), "old")

    def test_masks_whole_non_ipv4_values(self):
        self.assertEqual(rules_version.mask_ip("192.0.2.1"), "192.0.x.x")
        self.assertEqual(rules_version.mask_ip("2001:db8::1"), "[가림]")
