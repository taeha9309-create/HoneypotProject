"""Synthetic selection cases for signature review triage."""
import json
import unittest

from ml.analysis.signature_review_groups import scan


def member(sequence, *, protocol="telnet", group=2, rules=(), ip="192.0.2.1"):
    return {"source": "seoul", "protocol": protocol, "cluster_id": group, "is_noise": group < 0,
            "seq": tuple(sequence), "rules": set(rules), "ip": ip}


class SignatureReviewTests(unittest.TestCase):
    def test_selects_repeated_underexplained_flow_and_redacts_arguments(self):
        flow = ("sh", "cat secret.example/path")
        rows = [member(flow, rules=("B19",)), member(flow, ip="192.0.2.2"),
                member(("uname",), rules=("B19",)), member(flow, rules=("B01",)),
                member(flow, protocol="ssh"), member(flow, protocol="ssh"),
                member(flow, group=-1)]
        groups, excluded = scan(rows)
        self.assertEqual([(g["protocol"], g["cluster_id"]) for g in groups], [("telnet", 2)])
        target = groups[0]
        self.assertEqual((target["cluster_sessions"], target["gap_sessions"], target["gap_share"]), (4, 3, .75))
        self.assertEqual(target["recurrent_gap_sessions"], 2)
        self.assertEqual(target["recurrent_ips"], 2)
        self.assertEqual(excluded["noise_gap_sessions"], 1)
        self.assertNotIn("secret.example", json.dumps(groups))
        self.assertNotIn("192.0.2.1", json.dumps(groups))

    def test_shell_entry_alone_and_small_gap_share_are_not_review_targets(self):
        shell_only = [member(("shell", "sh"))] * 5
        small_gap = [member(("uname",), group=3)] * 3
        specific = [member(("uname",), group=3, rules=("B01",))] * 4
        groups, excluded = scan(shell_only + small_gap + specific)
        self.assertEqual(groups, [])
        self.assertEqual(excluded["no_repeated_non_shell_flow_clusters"], 1)
        self.assertEqual(excluded["below_gap_support_clusters"], 1)
