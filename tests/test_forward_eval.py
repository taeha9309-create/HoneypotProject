"""Synthetic post-freeze candidate data and provenance tests."""
from argparse import Namespace
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from ml import cluster
from ml.analysis import forward_eval, splits


def json_file(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


class ForwardTests(unittest.TestCase):
    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix="forward#test-")
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name)
        self.now = datetime(2026, 12, 10, tzinfo=timezone.utc)
        self.plan = {"status": "confirmed", "frozen_at_utc": "2026-12-01T00:00:00Z",
                     "min_days": 3, "min_telnet_sessions": 2}
        self.receipt = {
            "collection_start_utc": "2026-12-01T00:00:00Z",
            "collection_end_exclusive_utc": "2026-12-03T00:00:00Z",
            "received_at_utc": "2026-12-03T00:00:00Z",
            "previously_accessed": False, "sources": ["seoul", "syd"],
        }

    def test_unconfirmed_or_prior_receipt_is_rejected_before_db_access(self):
        with self.assertRaisesRegex(ValueError, "confirmed"):
            forward_eval.evaluate(Namespace(
                freeze=json_file(self.root / "freeze.json", {"status": "draft"}),
                receipt=json_file(self.root / "receipt.json", self.receipt)), now=self.now)
        with self.assertRaisesRegex(ValueError, "follow"):
            forward_eval.check_window(self.plan, {
                **self.receipt, "received_at_utc": "2026-11-30T00:00:00Z",
            }, self.now)
        with self.assertRaisesRegex(ValueError, "development boundary"):
            forward_eval.check_window({**self.plan, "frozen_at_utc": "2026-11-25T00:00:00Z"},
                                      self.receipt, self.now)
        with self.assertRaisesRegex(ValueError, "previously accessed"):
            forward_eval.check_window(self.plan, {**self.receipt, "previously_accessed": True}, self.now)

    def database(self, name, rows):
        path = self.root / name
        with closing(sqlite3.connect(path)) as con, con:
            con.executescript("""
                CREATE TABLE sessions(source,session_id,src_ip,protocol,excluded,start_ts,end_ts,n_commands);
                CREATE TABLE commands(source,session_id,ts,command);
            """)
            for source, sid, start, end, command_time in rows:
                con.execute("INSERT INTO sessions VALUES (?,?,'192.0.2.1','telnet',0,?,?,1)",
                            (source, sid, start, end))
                con.execute("INSERT INTO commands VALUES (?,?,?,'sh')", (source, sid, command_time))
        return path

    def test_forward_run_excludes_old_duplicate_and_incomplete_sessions(self):
        begin = "2026-12-01T09:00:00+09:00"
        end = "2026-12-01T09:02:00+09:00"
        old = "2026-11-30T23:59:59Z"
        development = self.database("dev.db", [("seoul", "duplicate", old, old, old)])
        new = self.database("new.db", [
            ("seoul", "valid", begin, end, begin),
            ("syd", "duplicate", begin, end, begin),
            ("seoul", "duplicate", begin, end, begin),
            ("seoul", "pre-freeze", old, old, old),
            ("seoul", "partial", begin, end, "2026-12-01T00:03:00Z"),
            ("seoul", "exclusive-end", "2026-12-03T00:00:00Z", "2026-12-03T00:00:00Z",
             "2026-12-03T00:00:00Z"),
        ])
        baseline = self.root / "base.yaml"
        baseline.write_text("- id: B19\n  type: behavior\n  patterns: ['^sh$']\n", encoding="utf-8")
        x04 = self.root / "x04.yaml"
        x04.write_text("- id: X04\n  type: behavior\n  patterns: ['^shell$']\n", encoding="utf-8")
        candidates = json_file(self.root / "candidates.json", {
            "frozen_at_utc": "2026-11-28T05:00:00Z",
            "X04": {"sha256": splits.sha256_file(x04)},
            "X06": {"regexes": ["sh"], "protocol": "telnet"},
            "baseline_rules_sha256": splits.sha256_file(baseline),
            "development_input_sha256": {"ml.db": splits.sha256_file(development)},
            "normalizer": {"cluster_py_sha256": splits.sha256_file(Path(cluster.__file__)),
                           "normalize_version": cluster.NORMALIZE_VERSION},
        })
        args = Namespace(
            development_db=development, new_db=new, baseline=baseline, x04=x04, candidates=candidates,
            freeze=json_file(self.root / "freeze.json", {
                **self.plan, "candidate_manifest_sha256": splits.sha256_file(candidates),
            }),
            receipt=json_file(self.root / "receipt.json", {
                **self.receipt, "database_sha256": splits.sha256_file(new),
            }),
        )
        report = forward_eval.evaluate(args, now=self.now)
        self.assertEqual(report["status"], "pilot")
        self.assertEqual(report["exclusions"], {"seen_development_session": 1,
                         "outside_collection_window": 2, "incomplete_or_outside_session_commands": 1})
        self.assertEqual(report["results"]["all"]["session"]["X06"]["b19_only_refined"], 2)
        self.assertEqual(report["results"]["all"]["unique_seq"]["X06"]["matches"], 1)
        self.assertEqual(report["results"]["syd"]["session"]["X06"]["matches"], 1)
        self.assertEqual(report["database_sha256"], splits.sha256_file(new))
        self.assertNotIn("192.0.2.1", json.dumps(report))
        self.assertNotIn("valid", json.dumps(report))
        args.receipt = json_file(args.receipt, {
            **self.receipt, "database_sha256": splits.sha256_file(development),
        })
        with self.assertRaisesRegex(ValueError, "archived development database"):
            forward_eval.evaluate(args, now=self.now)
