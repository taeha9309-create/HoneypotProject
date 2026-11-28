"""ml/analysis/splits.py 순수 함수 테스트. 모든 데이터는 테스트용 합성 값이다(실제 로그 아님)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.analysis import splits  # noqa: E402

ROWS = [  # (source, session_id, start_ts) - 합성
    ("seoul", "a", "2026-11-01T00:00:00Z"), ("seoul", "b", "2026-11-18T00:00:00Z"),
    ("syd", "c", "2026-11-10T00:00:00Z"), ("syd", "d", "2026-11-20T00:00:00Z"),
]


class SelectTests(unittest.TestCase):
    def test_time_split_boundary_is_eval(self):
        train, held = splits.select(ROWS, "time")
        self.assertEqual(train, {("seoul", "a"), ("syd", "c")})
        self.assertEqual(held, {("seoul", "b"), ("syd", "d")})

    def test_cross_honeypot(self):
        train, held = splits.select(ROWS, "syd_to_seoul")
        self.assertEqual({k[0] for k in train}, {"syd"})
        self.assertEqual({k[0] for k in held}, {"seoul"})
        train, held = splits.select(ROWS, "seoul_to_syd")
        self.assertEqual({k[0] for k in train}, {"seoul"})

    def test_overlapping_parts_rejected(self):
        bad = {"train": {"source": "seoul"}, "eval": {"source": "seoul"}}
        with self.assertRaises(ValueError):
            splits.select(ROWS, bad)


class OverlapTests(unittest.TestCase):
    def test_overlap_counts(self):
        train = {("s", "1"): (("sh",), "1.1.1.1"), ("s", "2"): (("sh", "x"), "2.2.2.2")}
        held = {("s", "3"): (("sh",), "1.1.1.1"),      # 같은 IP + 같은 순서(같은 캠페인)
                ("s", "4"): (("sh",), "9.9.9.9"),      # 순서만 같음
                ("s", "5"): (("new",), "1.1.1.1"),     # IP만 같음, 순서 미관측
                ("s", "6"): (("new",), "8.8.8.8")}     # 순서·IP 모두 미관측
        o = splits.overlap(train, held)
        self.assertEqual(o["eval_unseen_unique_seqs"], 1)
        self.assertEqual(o["eval_unseen_sessions"], 2)
        self.assertEqual(o["eval_unseen_ips"], 2)
        self.assertEqual(o["eval_sessions_seq_seen_pct"], 50.0)
        self.assertEqual(o["eval_sessions_ip_seen_pct"], 50.0)
        self.assertEqual(o["eval_sessions_same_ip_and_seq_seen_pct"], 25.0)

    def test_empty_eval(self):
        o = splits.overlap({("s", "1"): (("sh",), "1.1.1.1")}, {})
        self.assertIsNone(o["eval_sessions_seq_seen_pct"])


class PartitionTests(unittest.TestCase):
    def test_diff(self):
        a = {("s", "1"): ("telnet", 0), ("s", "2"): ("telnet", 1)}
        self.assertEqual(splits.partition_diff(a, dict(a)), 0)
        self.assertEqual(splits.partition_diff(a, {**a, ("s", "2"): ("telnet", -1)}), 1)
        with self.assertRaises(ValueError):
            splits.partition_diff(a, {("s", "1"): ("telnet", 0)})

    def test_top_share(self):
        from collections import Counter
        self.assertEqual(splits.top_share(Counter({"a": 3, "b": 1})), 0.75)
        self.assertIsNone(splits.top_share(Counter()))


if __name__ == "__main__":
    unittest.main()
