"""Synthetic Slack delivery tests. No real Slack endpoint is contacted."""
from contextlib import closing
from datetime import date, datetime, timezone
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from streamlit_app import slack_delivery as delivery
from streamlit_app.slack_preview import Snapshot

WEBHOOK = "https://hooks.slack.com/services/TTEST/BTEST/test_only"


def snapshot():
    return Snapshot("seoul+syd", date(2026, 11, 25),
                    datetime(2026, 11, 28, tzinfo=timezone.utc),
                    "위험", "안정", 120, 50.0, 2, 1, 3, 4, 5, 2)


class DeliveryTests(unittest.TestCase):
    def test_no_duplicate_after_confirmed_delivery(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "delivery.db"
            received = []
            self.assertEqual(delivery.deliver(snapshot(), state, "ops", received.append), (2, 0))
            self.assertEqual(delivery.deliver(snapshot(), state, "ops", received.append), (0, 0))
            self.assertEqual(len(received), 2)

    def test_ambiguous_delivery_never_retries_that_message(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "delivery.db"
            def failed(message):
                self.assertIn("위험 전환", message)
                raise delivery.DeliveryError("timeout")

            with self.assertRaisesRegex(delivery.DeliveryError, "timeout"):
                delivery.deliver(snapshot(), state, "ops", failed)
            sent = []
            self.assertEqual(delivery.deliver(snapshot(), state, "ops", sent.append), (1, 1))
            self.assertEqual(delivery.deliver(snapshot(), state, "ops", sent.append), (0, 1))
            self.assertIn("허니팟 요약", sent[0])
            with closing(sqlite3.connect(state)) as con:
                row = con.execute("SELECT status FROM outbox WHERE kind='risk_transition'").fetchone()
            self.assertEqual(row, ("uncertain",))

    def test_confirmed_rejection_can_retry_without_repeating_successful_alert(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "delivery.db"
            sent = []

            def reject_daily(message):
                if "허니팟 요약" in message:
                    raise delivery.DeliveryError("rejected", rejected=True)
                sent.append(message)

            with self.assertRaisesRegex(delivery.DeliveryError, "rejected"):
                delivery.deliver(snapshot(), state, "ops", reject_daily)
            self.assertEqual(delivery.deliver(snapshot(), state, "ops", sent.append), (1, 0))
            self.assertEqual(len(sent), 2)
            self.assertIn("위험 전환", sent[0])
            self.assertIn("허니팟 요약", sent[1])

    def test_http_body_and_no_secret_in_errors(self):
        with patch.object(delivery, "build_opener") as make:
            response = make.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b"ok"
            delivery.post(WEBHOOK, "요약")
            request = make.return_value.open.call_args.args[0]
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(json.loads(request.data)["text"], "요약")
            make.return_value.open.side_effect = HTTPError(WEBHOOK, 429, "rate limit", {}, BytesIO())
            with self.assertRaises(delivery.DeliveryError) as raised:
                delivery.post(WEBHOOK, "요약")
            self.assertTrue(raised.exception.rejected)
            self.assertNotIn("test_only", str(raised.exception))
        with self.assertRaises(ValueError):
            delivery.webhook_url("https://hooks.slack.com.example.test/services/T/B/S")
