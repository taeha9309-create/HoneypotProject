"""Synthetic T6 sampling and sheet safety tests."""
import unittest

from ml.analysis.label_sample import allocate, blind, safe_observation


class LabelSampleTests(unittest.TestCase):
    def test_blind_sheets_have_only_the_shared_items_in_common(self):
        groups = {(f"cmd{i}",): [(("src", str(i)), "192.0.2.1", i % 2 == 0)]
                  for i in range(12)}
        assigned = allocate(groups, 12, 4, 42)
        sheets, crosswalk = blind(assigned, 42)
        self.assertEqual({key: len(rows) for key, rows in sheets.items()}, {"A": 8, "B": 8})
        shared = [[tuple(row["source_session"]) for row in crosswalk
                   if row["rater"] == rater and row["shared"]] for rater in ("A", "B")]
        self.assertEqual(set(shared[0]), set(shared[1]))
        self.assertNotEqual(shared[0], shared[1])
        self.assertTrue(all(set(row) == {"sample_id", "observed_input", "label", "notes"}
                            for rows in sheets.values() for row in rows))

    def test_uncontrolled_arguments_are_not_exported(self):
        raw = ("wget https://host.example/private", "=1+7", "/bin/busybox UNSTABLE")
        self.assertEqual(safe_observation(raw), "wget [인수 생략]\n[기타 입력 생략]\nbusybox [탐침 토큰]")
