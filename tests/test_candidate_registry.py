"""Synthetic registry lifecycle tests."""
import unittest

from ml.analysis.candidate_registry import decide, open_registry, read_candidate


class RegistryTests(unittest.TestCase):
    def test_decision_requires_reason_and_is_terminal(self):
        with open_registry(":memory:") as conn:
            conn.execute("INSERT INTO candidates(id,payload,status) VALUES ('X06','{}','proposed')")
            conn.commit()
            with self.assertRaises(ValueError):
                decide(conn, "X06", "approved", "reviewer", "")
            decide(conn, "X06", "rejected", "reviewer", "Needs supporting evidence")
            item = read_candidate(conn, "X06")
            self.assertEqual(item["status"], "rejected")
            self.assertEqual(item["reviewer"], "reviewer")
            self.assertTrue(item["decided_utc"])
            with self.assertRaises(ValueError):
                decide(conn, "X06", "approved", "reviewer", "Cannot override a decision")
