"""ml/analysis/gap_baseline.py 테스트. 모든 행은 테스트용 합성 값이다(실제 로그 아님)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.analysis import gap_baseline as g  # noqa: E402


def row(i, seq, ip, rules, source="seoul", protocol="telnet"):
    return {"key": (source, str(i)), "source": source, "protocol": protocol, "ip": ip, "seq": tuple(seq),
            "rules": set(rules)}


class ClassifyTests(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(g.classify(set()), "none")
        self.assertEqual(g.classify({"B19"}), "weak_only")
        self.assertEqual(g.classify({"B19", "B11"}), "specific")
        self.assertEqual(g.classify({"B11"}, weak=("B19", "B11")), "weak_only")


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            row(1, ["sh"], "1.1.1.1", {"B19"}),
            row(2, ["sh"], "1.1.1.1", {"B19"}),
            row(3, ["sh"], "2.2.2.2", {"B19"}),
            row(4, ["a", "chmod"], "3.3.3.3", {"B19", "B11"}),
            row(5, ["zzz"], "4.4.4.4", set()),
        ]
        self.m = g.metrics(self.rows)

    def test_session_unit(self):
        s = self.m["session"]
        self.assertEqual((s["total"], s["none"], s["weak_only"], s["specific"]), (5, 1, 3, 1))
        self.assertEqual(s["coverage_pct"], 80.0)
        self.assertEqual(s["specificity_pct"], 20.0)

    def test_unique_seq_unit_weights_each_sequence_once(self):
        u = self.m["unique_seq"]  # 순서 3개: sh(weak_only), a+chmod(specific), zzz(none)
        self.assertEqual((u["total"], u["none"], u["weak_only"], u["specific"]), (3, 1, 1, 1))
        self.assertEqual(u["specificity_pct"], 33.3)

    def test_ip_unit(self):
        i = self.m["ip"]  # IP 4개: 1.1.1.1/2.2.2.2 weak_only, 3.3.3.3 specific, 4.4.4.4 none
        self.assertEqual((i["total"], i["none"], i["weak_only"], i["specific"]), (4, 1, 2, 1))

    def test_coverage_saturates_but_specificity_does_not(self):
        rows = [row(n, ["sh"], f"9.9.9.{n}", {"B19"}) for n in range(10)] + [row(99, ["x"], "8.8.8.8", {"B11"})]
        m = g.metrics(rows)
        self.assertEqual(m["session"]["coverage_pct"], 100.0)
        self.assertLess(m["session"]["specificity_pct"], 10.0)

    def test_empty(self):
        m = g.metrics([])
        self.assertIsNone(m["session"]["coverage_pct"])


if __name__ == "__main__":
    unittest.main()
