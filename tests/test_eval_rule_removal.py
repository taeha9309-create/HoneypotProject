"""Synthetic rule restoration fixtures, with no external data."""
import unittest

from ml.analysis import eval_rule_removal as experiment


def sample(sequence, ip="192.0.2.1", cluster=1, rules=(), protocol="telnet"):
    return experiment.Sample(protocol, tuple(sequence), ip, cluster, frozenset(rules))


class RuleRemovalTests(unittest.TestCase):
    def test_hidden_evaluation_labels_do_not_change_predictions(self):
        train = [sample(("alpha", "beta"), rules=("B11",))]
        held = [sample(("alpha", "gamma"), rules=("B11",))]
        result = experiment.predictions(train, held, 0.5)
        self.assertEqual(result, experiment.predictions(
            train, [sample(("alpha", "gamma"), rules=("B01",))], 0.5))
        self.assertEqual(result["B_exact"], [frozenset()])
        self.assertEqual(result["C_edit"], [frozenset({"B11"})])
        self.assertEqual(result["D_ml_cluster"], [frozenset({"B11"})])

    def test_ml_noise_and_cross_protocol_ids_do_not_restore(self):
        train = [sample(("alpha",), rules=("B11",))]
        held = [sample(("alpha",), cluster=-1, rules=("B11",)),
                sample(("alpha",), protocol="ssh", rules=("B11",))]
        result = experiment.evaluate(train, held, 0.5, 20, 7)
        group = result["session"]["D_ml_cluster"]["rules"]["B11"]
        self.assertEqual(group["recall"]["value"], 0)
        self.assertEqual(group["counts"]["positive"], 2)
        self.assertIsNone(group["precision"]["value"])
        self.assertEqual(group["recall"]["ci95"]["defined_resamples"], 20)

    def test_units_and_bootstrap_are_reproducible(self):
        train = [sample(("alpha",), rules=("B11",))]
        held = [sample(("alpha",), rules=("B11",)),
                sample(("alpha",), rules=("B11",)),
                sample(("delta",), ip="192.0.2.2", cluster=-1, rules=("B11",))]
        result = experiment.evaluate(train, held, 0.5, 20, 7)
        self.assertEqual(result, experiment.evaluate(train, held, 0.5, 20, 7))
        self.assertEqual(result["session"]["B_exact"]["rules"]["B11"]["recall"]["value"], 2 / 3)
        self.assertEqual(result["unique_seq"]["B_exact"]["rules"]["B11"]["recall"]["value"], 1 / 2)
        self.assertEqual(result["ip"]["B_exact"]["rules"]["B11"]["unseen_recall"]["value"], 0)
