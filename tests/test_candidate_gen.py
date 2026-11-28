"""Synthetic fixtures for T3 candidate drafting."""
import re
import unittest

from ml.analysis.candidate_gen import TrainingSession, draft_candidates


class CandidateTests(unittest.TestCase):
    def setUp(self):
        menu = ("enable", "linuxshell", "system", "shell", "sh")
        self.rows = [
            TrainingSession(("seoul", "one"), "192.0.2.1", ("2026-11-01",), menu, 3),
            TrainingSession(("seoul", "two"), "192.0.2.2", ("2026-11-02",), menu, 3),
            TrainingSession(("seoul", "three"), "192.0.2.1", ("2026-11-02",),
                            ("sh", "/bin/busybox UNSTABLE"), 7),
            TrainingSession(("seoul", "noise"), None, ("2026-11-03",),
                            ("sh", "/bin/busybox UNSTABLE"), -1),
            TrainingSession(("seoul", "benign"), None, ("2026-11-02",),
                            ("sh", "/bin/busybox echo"), 7),
            TrainingSession(("seoul", "unassigned"), None, ("2026-11-02",),
                            ("sh",), None),
        ]

    def test_shared_review_pool_and_denominator(self):
        report = draft_candidates(self.rows, 0.5)
        for arm in report.values():
            self.assertEqual({candidate["family"] for candidate in arm}, {"X04", "X06"})
            self.assertTrue(all(c["training_matches"]["total"] == 6 for c in arm))
        draft = next(c for c in report["D_ml_cluster"] if c["family"] == "X06")
        self.assertEqual(draft["support"]["session_keys"], [["seoul", "three"]])
        self.assertEqual(draft["training_matches"]["matched"], 2)
        self.assertEqual(draft["status"], "proposed")
        self.assertNotIn("192.0.2.1", str(report))

    def test_patterns_require_order_and_context(self):
        report = draft_candidates(self.rows, 0.5)
        patterns = {c["family"]: c["regex"] for c in report["D_ml_cluster"]}
        self.assertTrue(re.fullmatch(patterns["X04"], "\n".join(self.rows[0].sequence)))
        self.assertFalse(re.fullmatch(patterns["X04"], "\n".join(reversed(self.rows[0].sequence))))
        self.assertFalse(re.fullmatch(patterns["X06"], "sh\n/bin/busybox echo"))
        self.assertFalse(re.fullmatch(patterns["X06"], "/bin/busybox UNSTABLE"))

    def test_order_does_not_change_drafts(self):
        self.assertEqual(draft_candidates(self.rows, 0.5),
                         draft_candidates(list(reversed(self.rows)), 0.5))
