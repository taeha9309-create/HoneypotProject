"""Synthetic local Slack preview and suppression tests."""
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing

from streamlit_app.slack_preview import Snapshot, preview, simulate


def snapshot(level="위험"):
    return Snapshot("seoul+syd", date(2026, 11, 25),
                    datetime(2026, 11, 28, tzinfo=timezone.utc),
                    level, "안정", 120, 50.0, 2, 1, 3, 4, 5, 2)


class SlackPreviewTests(unittest.TestCase):
    def test_pure_preview_contains_counts_and_transition(self):
        messages = preview(snapshot())
        self.assertEqual([item["kind"] for item in messages], ["daily", "risk_transition"])
        self.assertIn("전날 대비 +50.0%", messages[0]["text"])
        self.assertIn("새 다운로드 서버 2개", messages[1]["text"])
        self.assertNotIn("http", messages[1]["text"])
        self.assertEqual([item["kind"] for item in preview(
            replace(snapshot(), previous_level=None))], ["daily"])

    def test_state_suppresses_repeat_and_allows_a_new_risk_transition(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "preview.db"
            first = snapshot()
            self.assertEqual([m["kind"] for m in simulate(first, path)], ["daily", "risk_transition"])
            self.assertEqual(simulate(first, path), [])
            later = replace(first, revision=first.revision + timedelta(minutes=1))
            self.assertEqual(simulate(later, path), [])
            recovered = replace(first, level="주의", revision=first.revision + timedelta(minutes=2))
            self.assertEqual(simulate(recovered, path), [])
            self.assertEqual(simulate(later, path), [])
            new = replace(first, revision=first.revision + timedelta(minutes=3))
            self.assertEqual([m["kind"] for m in simulate(new, path)], ["risk_transition"])
            following = replace(new, revision=new.revision + timedelta(days=1), day=new.day + timedelta(days=1))
            self.assertEqual([m["kind"] for m in simulate(following, path)], ["daily"])

    def test_will_not_use_an_existing_unrelated_database_as_ledger(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dashboard.db"
            with closing(sqlite3.connect(path)) as con, con:
                con.execute("CREATE TABLE sessions (id INTEGER)")
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "dedicated preview state"):
                simulate(snapshot(), path)
            self.assertEqual(path.read_bytes(), before)
