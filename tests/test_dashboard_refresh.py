"""Synthetic dashboard refresh checks using a small Sydney database copy."""
from contextlib import closing
import json
import sys
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import ingest
from streamlit_app import refresh_dashboard as tool, slack_delivery


class RefreshTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dash-refresh-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source.db"
        self.rules = tool.build_db.ROOT / "signatures/rules.yaml"
        with closing(sqlite3.connect(self.source)) as con, con:
            con.executescript(ingest.SCHEMA)
            con.execute("""INSERT INTO sessions
                (source,session_id,src_ip,protocol,start_ts,end_ts,n_commands)
                VALUES ('syd','test','192.0.2.1','telnet','2026-11-01T00:00:00Z',
                        '2026-11-01T00:00:02Z',1)""")
            con.execute("INSERT INTO commands VALUES ('syd','test','2026-11-01T00:00:01Z','sh')")

    def refresh(self, output):
        return tool.refresh(output, None, self.source, None, self.rules, log=lambda _: None)

    def test_publishes_verified_snapshot_and_preserves_inputs(self):
        before = self.source.read_bytes()
        output = self.root / "next"
        report = self.refresh(output)
        self.assertEqual(report, json.loads((output / "refresh_summary.json").read_text(encoding="utf-8")))
        self.assertEqual(report["sources"]["syd"]["sessions"], 1)
        self.assertTrue((output / "ml.db").exists())
        review = json.loads((output / "signature_review_groups.json").read_text(encoding="utf-8"))
        self.assertEqual(report["signature_review_groups"], len(review["groups"]))
        drafts = json.loads((output / "signature_proposal_validation.json").read_text(encoding="utf-8"))
        self.assertEqual(report["signature_review_drafts"], drafts["distinct_drafts"])
        self.assertEqual(self.source.read_bytes(), before)
        with self.assertRaises(FileExistsError):
            self.refresh(output)

    def test_slack_send_runs_only_after_the_snapshot_is_ready(self):
        output = self.root / "notify"
        ledger = self.root / "notifications.db"
        seen = []

        def transport(webhook, text):
            self.assertTrue((output / "refresh_summary.json").exists())
            self.assertTrue((output / "signature_review_groups.json").exists())
            seen.append(text)

        command = ["refresh_dashboard", "--syd-db", str(self.source), "--out", str(output),
                   "--slack-send", "--slack-state", str(ledger), "--slack-destination", "ops-test"]
        with (patch.object(sys, "argv", command),
              patch.dict("os.environ", {"HONEYPOT_SLACK_WEBHOOK": "https://hooks.slack.com/services/T/B/test"}),
              patch.object(slack_delivery, "post", side_effect=transport)):
            tool.main()
        self.assertEqual(len(seen), 1)
        self.assertIn("허니팟 요약", seen[0])

    def test_slack_failure_keeps_the_completed_snapshot(self):
        output = self.root / "send-failed"
        command = ["refresh_dashboard", "--syd-db", str(self.source), "--out", str(output),
                   "--slack-send", "--slack-state", str(self.root / "delivery.db"), "--slack-destination", "ops-test"]
        with (patch.object(sys, "argv", command),
              patch.dict("os.environ", {"HONEYPOT_SLACK_WEBHOOK": "https://hooks.slack.com/services/T/B/test"}),
              patch.object(slack_delivery, "post", side_effect=slack_delivery.DeliveryError("test timeout"))):
            with self.assertRaises(SystemExit) as raised:
                tool.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertTrue((output / "refresh_summary.json").is_file())

    def test_failed_build_never_calls_slack(self):
        output = self.root / "failed"
        command = ["refresh_dashboard", "--syd-db", str(self.source), "--out", str(output),
                   "--slack-send", "--slack-state", str(self.root / "alert.db"), "--slack-destination", "ops-test"]
        with (patch.object(sys, "argv", command),
              patch.dict("os.environ", {"HONEYPOT_SLACK_WEBHOOK": "https://hooks.slack.com/services/T/B/test"}),
              patch.object(tool.build_ml, "build", side_effect=ValueError("build failed")),
              patch.object(slack_delivery, "post") as transport):
            with self.assertRaises(SystemExit) as raised:
                tool.main()
            self.assertEqual(raised.exception.code, 1)
        transport.assert_not_called()
        self.assertFalse(output.exists())

    def test_failed_build_cleans_stage_and_keeps_active_snapshot(self):
        active = self.root / "active"
        active.mkdir()
        original = active / "dashboard.db"
        original.write_bytes(b"active snapshot")
        output = self.root / "next"
        with patch.object(tool.build_ml, "build", side_effect=ValueError("failed validation")):
            with self.assertRaisesRegex(ValueError, "failed validation"):
                self.refresh(output)
        self.assertEqual(original.read_bytes(), b"active snapshot")
        self.assertFalse(output.exists())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["active", "source.db"])
