"""Prepare or explicitly deliver aggregate dashboard alerts through Slack."""
import argparse
from contextlib import closing
from datetime import datetime
import json
import os
from pathlib import Path
import re
import sqlite3
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from streamlit_app import slack_preview

WEBHOOK = re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+")
DESTINATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
APP_ID = 0x484F4E53


class DeliveryError(Exception):
    def __init__(self, message, *, rejected=False):
        super().__init__(message)
        self.rejected = rejected


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def webhook_url(value):
    if not value or WEBHOOK.fullmatch(value) is None:
        raise ValueError("set HONEYPOT_SLACK_WEBHOOK to a Slack incoming webhook before sending")
    return value


def post(webhook, text):
    endpoint = webhook_url(webhook)
    body = json.dumps({"text": text, "unfurl_links": False, "unfurl_media": False},
                      ensure_ascii=False).encode("utf-8")
    request = Request(endpoint, data=body, method="POST",
                      headers={"Content-Type": "application/json; charset=utf-8"})
    try:
        with build_opener(NoRedirect()).open(request, timeout=8) as reply:
            if reply.status != 200 or reply.read(16).strip() != b"ok":
                raise DeliveryError("Slack did not confirm delivery")
    except HTTPError as error:
        status = error.code
        error.close()
        raise DeliveryError(f"Slack returned HTTP {status}",
                            rejected=300 <= status < 500 and status != 408) from None
    except (URLError, TimeoutError, OSError, ValueError):
        raise DeliveryError("connection ended without confirmed Slack delivery") from None


def initialize(con):
    con.execute("BEGIN IMMEDIATE")
    app_id = con.execute("PRAGMA application_id").fetchone()[0]
    tables = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()
    if app_id != APP_ID and (app_id != 0 or tables):
        raise ValueError("choose a dedicated Slack delivery state file")
    con.execute(f"PRAGMA application_id={APP_ID}")
    con.execute("""CREATE TABLE IF NOT EXISTS observed (
        scope TEXT PRIMARY KEY, revision TEXT NOT NULL, day TEXT NOT NULL, level TEXT NOT NULL
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS outbox (
        scope TEXT NOT NULL, event_key TEXT NOT NULL, revision TEXT NOT NULL,
        kind TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL
        CHECK(status IN ('queued', 'sending', 'sent', 'uncertain')),
        PRIMARY KEY (scope,event_key)
    )""")
    con.execute("COMMIT")


def enqueue(con, scope, snapshot, candidate_items=()):
    con.execute("BEGIN IMMEDIATE")
    prior = con.execute("SELECT revision, day, level FROM observed WHERE scope=?", (scope,)).fetchone()
    day = snapshot.day.isoformat()
    revision = snapshot.revision.isoformat()
    for item in slack_preview.preview(snapshot, prior):
        key = ("daily/" + day) if item["kind"] == "daily" else ("risk/" + revision)
        con.execute("""INSERT OR IGNORE INTO outbox VALUES (?, ?, ?, ?, ?, 'queued')""",
                    (scope, key, revision, item["kind"], item["text"]))
    for item in candidate_items:
        con.execute("INSERT OR IGNORE INTO outbox VALUES (?, ?, ?, ?, ?, 'queued')",
                    (scope, item["event_key"], revision, item["kind"], item["text"]))
    if prior is None or (snapshot.revision > datetime.fromisoformat(prior[0]) and day >= prior[1]):
        con.execute("INSERT OR REPLACE INTO observed VALUES (?, ?, ?, ?)",
                    (scope, revision, day, snapshot.level))
    con.execute("COMMIT")


def claim(con, scope):
    con.execute("BEGIN IMMEDIATE")
    row = con.execute("""SELECT event_key, message FROM outbox WHERE scope=? AND status='queued'
                         ORDER BY revision, CASE kind WHEN 'risk_transition' THEN 0 ELSE 1 END
                         LIMIT 1""", (scope,)).fetchone()
    if row:
        con.execute("UPDATE outbox SET status='sending' WHERE scope=? AND event_key=?",
                    (scope, row[0]))
    con.execute("COMMIT")
    return row


def deliver(snapshot, state_path, destination, transport, candidate_items=()):
    if not DESTINATION.fullmatch(destination):
        raise ValueError("destination must be a short ASCII name for the Slack channel")
    scope = json.dumps([destination, snapshot.scope], ensure_ascii=True)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    sent = 0
    with closing(sqlite3.connect(state_path, isolation_level=None)) as con:
        initialize(con)
        enqueue(con, scope, snapshot, candidate_items)
        while (item := claim(con, scope)) is not None:
            key, message = item
            try:
                transport(message)
            except DeliveryError as error:
                status = "queued" if error.rejected else "uncertain"
                con.execute("UPDATE outbox SET status=? WHERE scope=? AND event_key=?",
                            (status, scope, key))
                raise
            con.execute("UPDATE outbox SET status='sent' WHERE scope=? AND event_key=?", (scope, key))
            sent += 1
        uncertain = con.execute("""SELECT count(*) FROM outbox
                                   WHERE scope=? AND status IN ('uncertain', 'sending')""",
                                (scope,)).fetchone()[0]
    return sent, uncertain


def prepare_destination(data_dir, rules, state, destination, webhook):
    if state is None or not destination or not DESTINATION.fullmatch(destination):
        raise ValueError("provide a delivery state file and a short Slack destination name")
    path = Path(state).resolve()
    if path.is_relative_to(Path(data_dir).resolve()) or path == Path(rules).resolve():
        raise ValueError("use a delivery state file outside the dashboard and rules file")
    return path, destination, webhook_url(webhook)


def send_snapshot(data_dir, rules, destination, include_candidates=False):
    path, name, endpoint = destination
    snapshot = slack_preview.read_snapshot(data_dir, rules)
    items = []
    if include_candidates:
        from streamlit_app import candidate_alerts
        from ml.analysis import proposal_registry

        items = candidate_alerts.messages(proposal_registry.DEFAULT_REGISTRY)
    return deliver(snapshot, path, name, lambda text: post(endpoint, text), items)


def print_delivery_summary(sent, uncertain):
    print(f"Slack 전송 확인 {sent}건")
    if uncertain:
        print(f"전송 여부 미확인 {uncertain}건. 채널에서 확인하세요. 이 항목은 자동으로 다시 보내지 않습니다.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--rules", type=Path, default=Path("signatures/rules.yaml"))
    parser.add_argument("--include-candidates", action="store_true", help="include pending candidate review alerts")
    parser.add_argument("--send", action="store_true", help="actually post to the configured Slack channel")
    parser.add_argument("--state", type=Path, help="dedicated SQLite state for live delivery")
    parser.add_argument("--destination", help="stable local name of the Slack destination")
    args = parser.parse_args()
    try:
        if not args.send:
            snapshot = slack_preview.read_snapshot(args.data_dir, args.rules)
            messages = slack_preview.preview(snapshot)
            if args.include_candidates:
                from streamlit_app import candidate_alerts
                from ml.analysis import proposal_registry

                messages += candidate_alerts.messages(proposal_registry.DEFAULT_REGISTRY)
            slack_preview.print_preview(messages)
            return
        destination = prepare_destination(args.data_dir, args.rules, args.state, args.destination,
                                          os.environ.get("HONEYPOT_SLACK_WEBHOOK"))
        sent, uncertain = send_snapshot(args.data_dir, args.rules, destination, args.include_candidates)
    except (DeliveryError, ValueError, OSError, sqlite3.Error) as error:
        parser.exit(1, f"Slack 전송을 완료하지 못했습니다. {error}\n")
    print_delivery_summary(sent, uncertain)


if __name__ == "__main__":
    main()
