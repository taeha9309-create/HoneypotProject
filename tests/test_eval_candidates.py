"""Synthetic E3 scoring fixtures."""
import unittest

from ml.analysis.eval_candidates import candidate_metrics


class CandidateMetricsTests(unittest.TestCase):
    def test_match_breadth_separates_new_coverage_and_incremental_specificity(self):
        result = candidate_metrics([
            ({"B19"}, True), ({"B19"}, False),
            ({"B19", "B01"}, True), (set(), True),
        ])
        self.assertEqual(result["match_rate"], 0.75)
        self.assertEqual(result["new_coverage"], 1)
        self.assertEqual(result["b19_only_refined"], 1)
        self.assertEqual(result["b19_only_refined_rate"], 0.5)
        self.assertEqual(result["already_specific"], 1)
        self.assertEqual(result["overlap_by_rule"], {"B19": 2, "B01": 1})

    def test_empty_denominators_are_undefined(self):
        result = candidate_metrics([])
        self.assertIsNone(result["match_rate"])
        self.assertIsNone(result["b19_only_refined_rate"])
