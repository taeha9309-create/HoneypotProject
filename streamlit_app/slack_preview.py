"""Preview operation alerts locally using an existing dashboard snapshot."""
import argparse
from contextlib import closing
from dataclasses import dataclass
from datetime import date, datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys

# The dashboard analysis modules also run as top-level imports in Streamlit.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import data as D
import intel as I
from match_signatures import event_time, load_rules

LEVELS = {"안정", "주의", "위험"}
APP_ID = 0x484F4E59


@dataclass(frozen=True)
class Snapshot:
    scope: str
    day: date
    revision: datetime
    level: str
    previous_level: str | None
    sessions: int
    change: float | None
    new_servers: int
    new_hashes: int
    new_risky_ips: int
    new_rules: int
    high_sessions: int
    execution_attempts: int


def read_snapshot(data_dir, rules_path):
    rules = load_rules(rules_path)
    current_hash = sha256(rules_path.read_bytes()).hexdigest()
    ds = D.load(data_dir, rules, rules_sha256=current_hash)
    if ds.warnings:
        raise ValueError("dashboard snapshot has warnings; refresh or repair it before previewing alerts")
    revision = event_time(ds.meta.get("built_at"))
    if revision is None or ds.sessions["start"].dropna().empty:
        raise ValueError("dashboard snapshot needs a build timestamp and observed sessions")
    sources = tuple(sorted(ds.sources["source"].unique()))
    protocols = tuple(sorted(ds.sessions["protocol"].dropna().unique()))
    first, last = D.data_range(ds)
    filters = D.Filters(sources, protocols, last, last)
    current = I.briefing(ds, rules, filters)
    earlier = filters.previous()
    previous = (I.briefing(ds, rules, earlier)["level"]
                if earlier.start >= first and not D.scope(ds, earlier).sessions.empty else None)
    return Snapshot(
        json.dumps(sources, ensure_ascii=True), last, revision.astimezone(timezone.utc),
        current["level"], previous, int(current["sessions"]), current["change"],
        len(current["new_servers"]), len(current["new_hashes"]), len(current["new_danger_ips"]),
        len(current["new_rules"]), current["high"], current["s01"],
    )


def preview(snapshot, prior=None):
    if snapshot.level not in LEVELS or snapshot.previous_level not in LEVELS | {None}:
        raise ValueError("unknown threat level")
    day = snapshot.day.isoformat()
    change = "전날과 비교할 자료 부족" if snapshot.change is None else f"전날 대비 {snapshot.change:+.1f}%"
    counts = (f"새 다운로드 서버 {snapshot.new_servers:,}개 · 새 파일 해시 {snapshot.new_hashes:,}개 · "
              f"내려받아 실행 시도 {snapshot.execution_attempts:,}세션")
    messages = []
    if prior is not None and (snapshot.revision <= datetime.fromisoformat(prior[0]) or day < prior[1]):
        return messages
    if prior is None or day > prior[1]:
        messages.append({
            "kind": "daily",
            "text": (f"[허니팟 요약] {day} KST · {snapshot.level}\n"
                     f"접속 {snapshot.sessions:,}세션 · {change} · 위험도 높은 행동 {snapshot.high_sessions:,}세션\n"
                     f"{counts} · 새 위험 IP {snapshot.new_risky_ips:,}개 · 처음 관측된 규칙 {snapshot.new_rules:,}개\n"
                     "최신 수집일 기준이며 하루치 수집이 진행 중일 수 있습니다."),
        })
    previous_level = prior[2] if prior is not None else snapshot.previous_level
    if previous_level in {"안정", "주의"} and snapshot.level == "위험":
        messages.append({
            "kind": "risk_transition",
            "text": (f"[허니팟 위험 전환] {day} KST · {previous_level} → 위험\n"
                     f"{counts}\n상세 내용은 대시보드에서 확인하세요."),
        })
    return messages


def simulate(snapshot, path):
    """Use a dedicated preview ledger. This ledger never records Slack delivery."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, isolation_level=None)) as con:
        con.execute("BEGIN IMMEDIATE")
        app_id = con.execute("PRAGMA application_id").fetchone()[0]
        tables = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()
        if app_id != APP_ID and (app_id != 0 or tables):
            raise ValueError("choose a dedicated preview state file")
        con.execute(f"PRAGMA application_id={APP_ID}")
        con.execute("""CREATE TABLE IF NOT EXISTS preview_state (
            scope TEXT PRIMARY KEY, revision TEXT NOT NULL, observed_day TEXT NOT NULL,
            level TEXT NOT NULL
        )""")
        prior = con.execute("""SELECT revision, observed_day, level
                             FROM preview_state WHERE scope=?""", (snapshot.scope,)).fetchone()
        messages = preview(snapshot, prior)
        day = snapshot.day.isoformat()
        if prior is None or (snapshot.revision > datetime.fromisoformat(prior[0]) and day >= prior[1]):
            con.execute("""INSERT OR REPLACE INTO preview_state VALUES (?, ?, ?, ?)""",
                        (snapshot.scope, snapshot.revision.isoformat(), day, snapshot.level))
        con.execute("COMMIT")
        return messages


def print_preview(messages):
    print("Slack 알림 미리보기 · 전송 없음")
    if not messages:
        print("새 미리보기 알림이 없습니다.")
    for item in messages:
        print()
        print(item["text"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True, help="built dashboard snapshot")
    parser.add_argument("--rules", type=Path, default=Path("signatures/rules.yaml"))
    parser.add_argument("--simulation-db", type=Path, help="optional local ledger for testing duplicate suppression")
    args = parser.parse_args()
    try:
        snapshot = read_snapshot(args.data_dir, args.rules)
        if args.simulation_db:
            target = args.simulation_db.resolve()
            if target.is_relative_to(args.data_dir.resolve()) or target == args.rules.resolve():
                raise ValueError("put the preview state outside the dashboard snapshot and rule file")
            messages = simulate(snapshot, target)
        else:
            messages = preview(snapshot)
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.error(str(error))
    print_preview(messages)


if __name__ == "__main__":
    main()
