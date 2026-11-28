"""Synthetic proposal breadth and disclosure tests."""
import json
import unittest
from unittest.mock import patch

from ml.analysis import signature_validation as check


def row(flow, *, cluster=5, protocol="telnet", source="seoul", ip="192.0.2.1", rules=()):
    return check.Session(source, protocol, cluster, ip, tuple(flow), frozenset(rules))


def group(cluster_id=5, flow="sh\nbusybox [탐침 토큰]"):
    return {
        "protocol": "telnet", "cluster_id": cluster_id, "cluster_sessions": 5,
        "gap_sessions": 4, "recurrent_gap_sessions": 4,
        "representative_flows": [{"observed_flow": flow, "sessions": 4, "ips": 2, "steps_omitted": 0}],
    }


class SignatureValidationTests(unittest.TestCase):
    def test_reports_breadth_and_overlap_without_leaking_session_data(self):
        flow = ["sh", "busybox [탐침 토큰]"]
        sessions = [
            row(flow, rules=["B19"]),
            row(["cd", *flow, "exit"], cluster=None, source="syd", ip="192.0.2.2", rules=["B01", "B19"]),
            row(flow, cluster=-1),
            row(["sh", "[기타 입력 생략]", flow[1]], cluster=7),
            row(flow, protocol="ssh", rules=["B01"]),
        ]
        report = check.evaluate(flow, group(), sessions)
        self.assertEqual(report["all"]["population"], 4)
        self.assertEqual(report["all"]["matches"], 3)
        self.assertEqual(report["origin_cluster"]["matches"], 1)
        self.assertEqual(report["outside_cluster"]["matches"], 2)
        self.assertEqual(report["outside_cluster"]["already_specific"], 1)
        self.assertEqual(report["all"]["b19_only_refined"], 1)
        self.assertEqual(report["all"]["new_coverage"], 1)
        self.assertEqual(report["all"]["overlap_by_rule"]["B01"], 1)
        self.assertEqual(report["distinct_matched_ips"], 2)
        self.assertNotIn("192.0.2", json.dumps(report))

    def test_bare_regex_masked_arguments_and_unknown_origin_are_rejected(self):
        for unsafe in (["sh", ".*"], ["sh", "cat [인수 생략]"]):
            with self.assertRaisesRegex(ValueError, "fully observed steps"):
                check.evaluate(unsafe, group(), [])
        with self.assertRaisesRegex(ValueError, "origin cluster is absent"):
            check.evaluate(["sh", "uname"], group(), [row(["sh"], cluster=7)])

    def test_duplicate_drafts_and_abstention_are_reported(self):
        sessions = [row(["sh", "busybox [탐침 토큰]"], cluster=i) for i in (5, 7)]
        identity = {key: key for key in check.SNAPSHOT_KEYS}
        with patch.object(check, "load_snapshot", return_value=(sessions, identity)):
            report = check.build(None, None, {"groups": [group(), group(7), group(9, "sh\ncat [인수 생략]")]})
        self.assertEqual((report["proposed_groups"], report["distinct_drafts"]), (2, 1))
        self.assertEqual(report["groups"][0]["same_draft_other_clusters"], [7])
        self.assertIsNone(report["groups"][2]["validation"])
