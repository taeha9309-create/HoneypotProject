"""Register and review detection candidates in a local SQLite file."""
import argparse
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from ml.analysis import splits


def open_registry(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS candidates (
        id TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL
        CHECK(status IN ('proposed', 'approved', 'rejected')),
        reviewer TEXT, decided_utc TEXT, reason TEXT
    )""")
    return conn


def register_x06(conn, freeze_path, t3_path):
    manifest = json.loads(freeze_path.read_text(encoding="utf-8"))
    t3 = json.loads(t3_path.read_text(encoding="utf-8"))
    if manifest["t3_report_sha256"] != splits.sha256_file(t3_path):
        raise ValueError("T3 report does not match the X06 freeze")
    drafts = [item for item in t3["candidates"]["D_ml_cluster"] if item["family"] == "X06"]
    patterns = sorted({draft["regex"] for draft in drafts})
    if not patterns or patterns != manifest["X06"]["regexes"]:
        raise ValueError("X06 patterns do not match the frozen D-arm drafts")
    if manifest["X06"]["protocol"] != "telnet":
        raise ValueError("X06 must be scoped to Telnet")
    keys = sorted({tuple(key) for item in drafts for key in item["support"]["session_keys"]})
    candidate = {
        "id": "X06",
        "name": manifest["X06"]["name"],
        "generation_arm": "D_ml_cluster",
        "protocol": "telnet",
        "normalized_sequence_patterns": patterns,
        "evidence_session_keys": keys,
        "evidence_ip_counts_by_group": {str(item["group"]): item["support"]["ips"] for item in drafts},
        "activity_days_utc": sorted({day for item in drafts for day in item["support"]["activity_days_utc"]}),
        "normalizer": manifest["normalizer"],
        "baseline_rules_sha256": manifest["baseline_rules_sha256"],
        "development_input_sha256": manifest["development_input_sha256"],
        "freeze_sha256": splits.sha256_file(freeze_path),
    }
    payload = json.dumps(candidate, ensure_ascii=False, sort_keys=True)
    with conn:
        conn.execute("INSERT INTO candidates(id,payload,status) VALUES (?,?, 'proposed') ON CONFLICT(id) DO NOTHING",
                     ("X06", payload))
        if conn.execute("SELECT payload FROM candidates WHERE id='X06'").fetchone()[0] != payload:
            raise ValueError("X06 already exists with different contents")


def read_candidate(conn, candidate_id):
    row = conn.execute("SELECT * FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
    if row is None:
        raise ValueError(f"unknown candidate: {candidate_id}")
    result = json.loads(row["payload"])
    result.update({key: row[key] for key in ("status", "reviewer", "decided_utc", "reason")})
    return result


def decide(conn, candidate_id, status, reviewer, reason):
    if status not in {"approved", "rejected"} or not reviewer.strip() or not reason.strip():
        raise ValueError("a decision requires a reviewer and a reason")
    with conn:
        cursor = conn.execute("""UPDATE candidates
            SET status=?, reviewer=?, decided_utc=?, reason=?
            WHERE id=? AND status='proposed'""",
            (status, reviewer.strip(), datetime.now(timezone.utc).isoformat(timespec="seconds"),
             reason.strip(), candidate_id))
        if cursor.rowcount != 1:
            raise ValueError("candidate missing or already decided")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    add = commands.add_parser("register")
    add.add_argument("--freeze", type=Path, required=True)
    add.add_argument("--t3", type=Path, required=True)
    show = commands.add_parser("show")
    show.add_argument("id")
    for name in ("approve", "reject"):
        command = commands.add_parser(name)
        command.add_argument("id")
        command.add_argument("--reviewer", required=True)
        command.add_argument("--reason", required=True)
    args = parser.parse_args()
    if args.action == "register":
        args.registry.parent.mkdir(parents=True, exist_ok=True)
    elif not args.registry.is_file():
        parser.error("registry does not exist")
    try:
        with closing(open_registry(args.registry)) as conn:
            if args.action == "register":
                register_x06(conn, args.freeze, args.t3)
                print("X06 registered")
            elif args.action == "show":
                print(json.dumps(read_candidate(conn, args.id), ensure_ascii=True, indent=2))
            else:
                status = "approved" if args.action == "approve" else "rejected"
                decide(conn, args.id, status, args.reviewer, args.reason)
                print(f"{args.id}: {status}")
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
