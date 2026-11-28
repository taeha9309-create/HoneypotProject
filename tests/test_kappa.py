"""Synthetic inter-rater agreement tests."""
import unittest

from ml.analysis.kappa import score


class KappaTests(unittest.TestCase):
    def test_scores_agreement_and_confusion_matrix(self):
        report = score([("1", "1"), ("1", "2"), ("2", "2"), ("2", "2")])
        self.assertEqual(report["agreement"], 0.75)
        self.assertEqual(report["cohens_kappa"], 0.5)
        self.assertEqual(report["rows_rater_A_columns_rater_B"][0][:2], [1, 1])

    def test_unused_variation_makes_kappa_undefined(self):
        self.assertIsNone(score([("1", "1")])["cohens_kappa"])
