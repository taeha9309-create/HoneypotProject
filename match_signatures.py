"""시그니처 규칙을 DB의 세션 명령어에 적용하고 결과를 signature_hits 표에 저장한다.

사용법:
    python match_signatures.py [--db data/honeypot.db] [--rules signatures/rules.yaml]
                               [--examples B10]

다시 돌리면 signature_hits를 지우고 새로 채운다(규칙을 고친 뒤 다시 돌리면 된다).
요약 비율은 테스트 접속(excluded=1)을 뺀, 명령어가 있는 SSH/Telnet 세션 기준이다.
"""
import argparse
import posixpath
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import groupby

import yaml

from command_behaviors import DETECTORS, observe, without_assignments
from additional_signatures import DETECTORS as ADDITIONAL_DETECTORS, observe_additional
DETECTORS = DETECTORS | ADDITIONAL_DETECTORS
from s01_sequence import actions

SCHEMA = """
CREATE TABLE IF NOT EXISTS signature_hits (
    source     TEXT NOT NULL,
    session_id TEXT NOT NULL,
    rule_id    TEXT NOT NULL,
    first_ts   TEXT NOT NULL,  -- 이 규칙이 처음 걸린 명령어 시각 (단계 순서를 만들 때 쓴다)
    n_hits     INTEGER NOT NULL,  -- 단일 규칙: 명령어 줄 수 / 시퀀스: 완성 경로 수
    PRIMARY KEY (source, session_id, rule_id)
);
"""


def load_rules(path):
    with open(path, encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    ids = [r["id"] for r in rules]
    dupes = [i for i, n in Counter(ids).items() if n > 1]
    if dupes:
        sys.exit(f"규칙 ID 중복: {dupes}")
    for r in rules:
        detector = r.get("detector")
        if detector is not None and detector not in DETECTORS:
            sys.exit(f"{r['id']}: 알 수 없는 detector: {detector}")
        if detector is not None and "sequence" in r:
            sys.exit(f"{r['id']}: detector와 sequence는 함께 쓸 수 없다")
        if r.get("type") not in ("behavior", "campaign"):
            sys.exit(f"{r['id']}: type은 behavior 또는 campaign이어야 한다")
        if "session_detector" in r:
            if r["session_detector"] != "download_chmod_execute" or any(
                field in r for field in ("detector", "patterns", "sequence")
            ):
                sys.exit(f"{r['id']}: invalid session detector configuration")
            continue
        field = "sequence" if "sequence" in r else "patterns"
        if field == "sequence" and "patterns" in r:
            sys.exit(f"{r['id']}: patterns와 sequence는 함께 쓸 수 없다")
        patterns = r.get(field, [] if detector else None)
        if (not isinstance(patterns, list) or (not patterns and not detector)
                or any(not isinstance(p, str) or not p for p in patterns)
                or (field == "sequence" and len(patterns) < 2)):
            sys.exit(f"{r['id']}: {field}에 유효한 정규식 목록이 필요하다")
        r["regex"] = [re.compile(p) for p in patterns]
        if field == "sequence" and any(rx.search("") for rx in r["regex"]):
            sys.exit(f"{r['id']}: sequence 단계는 빈 문자열에 일치할 수 없다")
    return rules


def iter_sessions(con):
    """(source, session_id) 별로 시각 순서대로 정렬된 명령어 목록을 낸다."""
    rows = con.execute(
        "SELECT source, session_id, ts, command FROM commands ORDER BY source, session_id, ts"
    )
    key, cmds = None, []
    for source, sid, ts, cmd in rows:
        if (source, sid) != key:
            if key:
                yield key, cmds
            key, cmds = (source, sid), []
        cmds.append((ts, cmd))
    if key:
        yield key, cmds


def match(rules, cmds):
    """세션 하나에 대해 {rule_id: (first_ts, n_hits)}를 돌려준다."""
    hits = {}
    observations = ({cmd: observe(cmd) | observe_additional(cmd, without_assignments)
                     for _, cmd in cmds}
                    if any(r.get("detector") for r in rules) else {})
    for r in rules:
        if "sequence" in r or "session_detector" in r:
            paths = rule_paths(r, cmds)
            if paths:
                hits[r["id"]] = (paths[0][0][0], len(paths))
            continue
        matched = [ts for ts, cmd in cmds
                   if any(rx.search(cmd) for rx in r["regex"])
                   or r.get("detector") in observations.get(cmd, set())]
        if matched:
            hits[r["id"]] = (matched[0], len(matched))
    return hits


def event_time(ts):
    """Normalize ISO timestamps; ambiguous or invalid times cannot prove order."""
    try:
        value = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if value.tzinfo is None:
            return None
        return value.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return None


def rule_paths(rule, cmds):
    if "session_detector" in rule:
        return download_paths(cmds)
    return sequence_matches(rule["regex"], cmds)


def download_paths(cmds):
    """Preserve the existing path API while sharing its target evidence."""
    return [evidence['steps'] for evidence in download_evidence(cmds)]


def download_evidence(cmds):
    """Return the same-file target and input rows used to complete each path."""
    events = [(event_time(ts), ts, cmd) for ts, cmd in cmds]
    events = sorted((row for row in events if row[0] is not None), key=lambda row: row[0])
    paths, pending = [], {}
    cwd = None
    for _, rows in groupby(events, key=lambda row: row[0]):
        observations = [(ts, cmd, list(actions(cmd))) for _, ts, cmd in rows]
        ambiguous_directory = len(observations) > 1 and any(
            action == 'cd' for _, _, observed in observations for action, _ in observed
        )
        starting_directory = None if ambiguous_directory else cwd
        if ambiguous_directory:
            pending = {path: state for path, state in pending.items() if path.startswith('/')}
        # Equal-time rows can each extend older evidence but cannot extend each other.
        additions = {}
        completed = False
        directories = []
        for ts, cmd, observed in observations:
            current = pending.copy()
            current_directory = starting_directory
            row_completed = False
            for action, target in observed:
                if action == 'cd':
                    current = {path: state for path, state in current.items()
                               if path.startswith('/')}
                    current_directory = (
                        posixpath.join(current_directory, target)
                        if target and current_directory else target
                    )
                    if current_directory and not current_directory.startswith('/'):
                        current_directory = None
                    continue
                if target is None or row_completed:
                    continue
                if current_directory:
                    target = posixpath.join(current_directory, target)
                downloaded, executable = current.get(target, (None, None))
                row = (ts, cmd)
                if action == 'download':
                    current[target] = (row if executable else downloaded or row, None)
                elif action == 'chmod' and downloaded:
                    current[target] = (downloaded, executable or row)
                elif action == 'run' and executable:
                    if not completed:
                        paths.append({'target': target, 'steps': [downloaded, executable, row]})
                    completed = True
                    row_completed = True
            directories.append(current_directory)
            for target, state in current.items():
                previous = additions.get(target)
                if previous is None or (state[1] and not previous[1]):
                    additions[target] = state
        pending = {} if completed else additions
        # Equal-time inputs do not establish which working directory is last.
        cwd = directories[0] if all(d == directories[0] for d in directories) else None
        if len(directories) > 1 and cwd is None:
            pending = {path: state for path, state in pending.items() if path.startswith('/')}
    return paths


def sequence_matches(regexes, cmds):
    """Return non-overlapping complete paths in one session.

    Steps may skip unrelated input. Within one input line, regex spans must
    advance; across input lines timestamps must strictly increase. Equal-time
    rows are never ordered using SQLite rowid or ingestion order.
    """
    events = [(event_time(ts), ts, cmd) for ts, cmd in cmds]
    events = sorted((e for e in events if e[0] is not None), key=lambda e: e[0])
    paths = []
    # Preserve shorter paths as well: a later row with the same timestamp may
    # contain several steps in one line, even when another row advanced a path.
    pending = []
    for time, ts, cmd in events:
        updated = list(pending)
        completed = False
        for step, previous_time, path in pending + [(0, None, [])]:
            if previous_time is not None and time <= previous_time:
                continue
            position = 0
            current_path = list(path)
            while step < len(regexes):
                found = regexes[step].search(cmd, position)
                if found is None or found.end() == found.start():
                    break
                current_path.append((ts, cmd))
                step += 1
                position = found.end()
            if step == len(regexes):
                paths.append(current_path)
                completed = True
                break
            if len(current_path) > len(path):
                updated.append((step, time, current_path))
        # For each progress level, the earliest last timestamp dominates later
        # ones for all future rows. Retain at most one state per rule step.
        unique = {}
        if not completed:
            for candidate in updated:
                existing = unique.get(candidate[0])
                if existing is None or candidate[1] < existing[1]:
                    unique[candidate[0]] = candidate
        pending = list(unique.values())
    return paths


def main():
    parser = argparse.ArgumentParser(description="시그니처 규칙을 세션 명령어에 적용한다.")
    parser.add_argument("--db", default="data/honeypot.db")
    parser.add_argument("--rules", default="signatures/rules.yaml")
    parser.add_argument("--examples", metavar="RULE_ID",
                        help="이 규칙에 걸린 명령어 예시를 서로 다른 것 위주로 보여 준다")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    con = sqlite3.connect(args.db)
    con.executescript(SCHEMA)
    counted = {
        (s, sid) for s, sid in con.execute(
            "SELECT source, session_id FROM sessions "
            "WHERE n_commands > 0 AND excluded = 0 AND protocol IN ('ssh', 'telnet')"
        )
    }

    totals = Counter()  # source별 대상 세션 수
    rule_counts = defaultdict(Counter)  # source -> rule_id -> 세션 수
    no_campaign = Counter()
    any_rule = Counter()
    campaign_ids = {r["id"] for r in rules if r["type"] == "campaign"}
    examples = Counter()
    example_rule = next((r for r in rules if r["id"] == args.examples), None)

    with con:
        con.execute("DELETE FROM signature_hits")
        for (source, sid), cmds in iter_sessions(con):
            hits = match(rules, cmds)
            con.executemany(
                "INSERT INTO signature_hits VALUES (?, ?, ?, ?, ?)",
                [(source, sid, rid, ts, n) for rid, (ts, n) in hits.items()],
            )
            if (source, sid) not in counted:
                continue
            totals[source] += 1
            for rid in hits:
                rule_counts[source][rid] += 1
            any_rule[source] += bool(hits)
            if not campaign_ids.intersection(hits):
                no_campaign[source] += 1
            if example_rule and example_rule["id"] in hits:
                if "sequence" in example_rule or "session_detector" in example_rule:
                    for path in rule_paths(example_rule, cmds):
                        examples[" -> ".join(cmd for _, cmd in path)[:120]] += 1
                    continue
                for _, cmd in cmds:
                    if (any(rx.search(cmd) for rx in example_rule["regex"])
                            or example_rule.get("detector") in observe(cmd)):
                        examples[cmd[:120]] += 1

    for source in sorted(totals):
        n = totals[source]
        print(f"\n[{source}] 명령어가 있는 SSH/Telnet 세션 {n:,}개 (테스트 제외)")
        print(f"  하나 이상 규칙 일치: {any_rule[source]:,} ({any_rule[source] / n:.1%})")
        for r in rules:
            k = rule_counts[source][r["id"]]
            print(f"  {r['id']}  {k:>7,}  {k / n:6.1%}  {r['name']}")
        print(f"  캠페인 시그니처에 안 걸린 세션: {no_campaign[source]:,} ({no_campaign[source] / n:.1%})")

    if example_rule:
        print(f"\n[{example_rule['id']} 예시] 서로 다른 명령어 {len(examples):,}종 중 상위 15개")
        for cmd, k in examples.most_common(15):
            print(f"  {k:>6,}  {cmd}")
    con.close()


if __name__ == "__main__":
    main()

