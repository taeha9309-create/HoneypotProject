"""Build and verify a fresh dashboard snapshot without replacing the active one."""
import argparse
from hashlib import sha256
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory

from ml.analysis import signature_review_groups, signature_validation
from streamlit_app import build_db, build_ml


def check_database(path):
    with closing(build_db.ro(path)) as con:
        if con.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise ValueError(f"database check failed: {path.name}")


def summarize(bundle, requested_sources, rules_path):
    dashboard = bundle / "dashboard.db"
    ml = bundle / "ml.db"
    for path in (dashboard, ml, *(bundle / f"{source}.db" for source in requested_sources)):
        check_database(path)
    with closing(build_db.ro(dashboard)) as con:
        sources = con.execute("""
            SELECT source, db, first_event, last_event, has_raw_logs
            FROM sources ORDER BY source
        """).fetchall()
        hashes = dict(con.execute("SELECT key, value FROM meta WHERE key IN ('built_at','rules_sha256')"))
        hits = dict(con.execute("SELECT source, count(*) FROM hits GROUP BY source"))
    if {source for source, *_ in sources} != requested_sources:
        raise ValueError("built sources differ from the supplied inputs")
    current_hash = sha256(rules_path.read_bytes()).hexdigest()
    if hashes.get("rules_sha256") != current_hash:
        raise ValueError("the rules file changed during the refresh; build again")
    with closing(build_db.ro(ml)) as con:
        cluster_counts = dict(con.execute("SELECT source, count(*) FROM ml_clusters GROUP BY source"))
        ml_command_sessions = dict(con.execute(
            "SELECT source, count(*) FROM sessions WHERE excluded=0 AND n_commands>0 GROUP BY source"))
    report = {}
    for source, name, first, last, raw in sources:
        if name != f"{source}.db":
            raise ValueError("unexpected source database in the built snapshot")
        with closing(build_db.ro(bundle / name)) as con:
            sessions, command_sessions = con.execute("""
                SELECT count(*), coalesce(sum(n_commands>0),0)
                FROM sessions WHERE source=? AND excluded=0
            """, (source,)).fetchone()
        if not sessions or not first or not last:
            raise ValueError(f"no usable session coverage for {source}")
        assigned = cluster_counts.get(source, 0)
        if (command_sessions != ml_command_sessions.get(source, 0)
                or assigned > command_sessions):
            raise ValueError(f"ML session counts do not match the refreshed data for {source}")
        report[source] = {
            "first_observation_utc": first,
            "last_observation_utc": last,
            "has_raw_logs": bool(raw),
            "sessions": sessions,
            "command_sessions": command_sessions,
            "rule_hits": hits.get(source, 0),
            "ml_assignments": assigned,
        }
    return {"built_at_utc": hashes["built_at"], "rules_sha256": current_hash, "sources": report}


def refresh(output, seoul_logs, syd_db, geo, rules, log=print):
    output = Path(output).resolve()
    rules = Path(rules).resolve()
    logs = Path(seoul_logs).resolve() if seoul_logs else None
    sydney = Path(syd_db).resolve() if syd_db else None
    geo = Path(geo).resolve() if geo else None
    requested = {name for name, path in (("seoul", logs), ("syd", sydney)) if path}
    if not requested:
        raise ValueError("provide at least one source")
    if logs and not logs.is_dir():
        raise ValueError("Seoul log directory does not exist")
    for path in (sydney, geo, rules):
        if path and not path.is_file():
            raise ValueError(f"input file does not exist: {path}")
    if logs and output.is_relative_to(logs):
        raise ValueError("the output folder must be outside the Seoul log directory")
    if output.exists():
        raise FileExistsError(f"choose a new output folder: {output}")
    original_rules_hash = sha256(rules.read_bytes()).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = output.with_name(f".{output.name}.refresh.lock")
    with lock.open("x", encoding="utf-8"):
        pass
    try:
        if output.exists():
            raise FileExistsError(f"choose a new output folder: {output}")
        with TemporaryDirectory(prefix=f".{output.name}-", dir=output.parent) as temp:
            stage = (Path(temp) / "snapshot").resolve()
            if not stage.is_relative_to(output.parent):
                raise ValueError("temporary build folder must be beside the requested output")
            log("별도 갱신본을 만드는 중입니다.")
            build_db.build(stage, logs, sydney, geo, rules, log=log)
            build_ml.build(stage, log=log)
            result = summarize(stage, requested, rules)
            if result['rules_sha256'] != original_rules_hash:
                raise ValueError("the rules file changed during the refresh; build again")
            review = signature_review_groups.build(stage, rules)
            (stage / signature_review_groups.REPORT_NAME).write_text(
                json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            result['signature_review_groups'] = len(review['groups'])
            checked = signature_validation.build(stage, rules, review)
            (stage / signature_validation.REPORT_NAME).write_text(
                json.dumps(checked, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            result['signature_review_drafts'] = checked['distinct_drafts']
            (stage / "refresh_summary.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            if output.exists():
                raise FileExistsError(f"output folder appeared during build: {output}")
            os.rename(stage, output)
    finally:
        lock.unlink()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new snapshot folder")
    parser.add_argument("--seoul-logs", type=Path)
    parser.add_argument("--syd-db", type=Path)
    parser.add_argument("--geo", type=Path)
    slack_mode = parser.add_mutually_exclusive_group()
    slack_mode.add_argument("--slack-preview", action="store_true", help="print a local Slack preview without sending")
    slack_mode.add_argument("--slack-send", action="store_true", help="send to the configured Slack channel after validation")
    parser.add_argument("--slack-state", type=Path, help="dedicated delivery state file")
    parser.add_argument("--slack-destination", help="stable local name of the Slack destination")
    parser.add_argument("--rules", type=Path, default=build_db.ROOT / "signatures/rules.yaml")
    args = parser.parse_args()
    if args.slack_send:
        from streamlit_app import slack_delivery

        try:
            destination = slack_delivery.prepare_destination(
                args.out, args.rules, args.slack_state, args.slack_destination, os.environ.get("HONEYPOT_SLACK_WEBHOOK"))
            if ((args.seoul_logs and destination[0].is_relative_to(args.seoul_logs.resolve()))
                    or any(path and destination[0] == path.resolve() for path in (args.syd_db, args.geo))):
                raise ValueError("store Slack delivery state outside the input data")
        except ValueError as error:
            parser.error(str(error))
    elif args.slack_state or args.slack_destination:
        parser.error("--slack-state and --slack-destination require --slack-send")
    try:
        result = refresh(args.out, args.seoul_logs, args.syd_db, args.geo, args.rules)
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(1, f"갱신에 실패했습니다. 기존 대시보드는 계속 사용할 수 있습니다.\n{error}\n")
    print(f"갱신본 준비 완료: {args.out.resolve()}")
    print(f"시그니처 검토 대상 군집: {result['signature_review_groups']}개 · "f"서로 다른 검사 초안 {result['signature_review_drafts']}개")
    for source, item in result["sources"].items():
        print(f"{source}: {item['last_observation_utc']}까지 · {item['sessions']:,}세션 "
              f"· 규칙 적중 {item['rule_hits']:,}건 · ML 배정 {item['ml_assignments']:,}건")
    executable = sys.executable.replace("'", "''")
    folder = str(args.out.resolve()).replace("'", "''")
    if args.slack_send:
        try:
            slack_delivery.print_delivery_summary(*slack_delivery.send_snapshot(args.out, args.rules, destination))
        except (slack_delivery.DeliveryError, ValueError, OSError, sqlite3.Error) as error:
            parser.exit(2, f"갱신본은 준비됐지만 Slack 전송을 완료하지 못했습니다: {error}\n"
                        "갱신본을 다시 만들 필요 없이 slack_delivery에서 확인하세요.\n")
    elif args.slack_preview:
        from streamlit_app import slack_preview

        try:
            snapshot = slack_preview.read_snapshot(args.out, args.rules)
            slack_preview.print_preview(slack_preview.preview(snapshot))
        except (ValueError, OSError, sqlite3.Error) as error:
            print(f"갱신본은 준비됐지만 Slack 미리보기를 만들지 못했습니다: {error}", file=sys.stderr)
    rules_path = str(args.rules.resolve()).replace("'", "''")
    print(f"& '{executable}' -m streamlit run streamlit_app/app.py -- --data '{folder}' --rules '{rules_path}'")


if __name__ == "__main__":
    main()
