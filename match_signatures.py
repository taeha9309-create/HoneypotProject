"""시그니처 규칙을 DB의 세션 명령어에 적용하고 결과를 signature_hits 표에 저장한다.

사용법:
    python match_signatures.py [--db data/honeypot.db] [--rules signatures/rules.yaml]
                               [--examples B10]

다시 돌리면 signature_hits를 지우고 새로 채운다(규칙을 고친 뒤 다시 돌리면 된다).
요약 비율은 테스트 접속(excluded=1)을 뺀, 명령어가 있는 SSH 세션 기준이다.
"""
import argparse
import re
import sqlite3
import sys
from collections import Counter, defaultdict

import yaml

SCHEMA = """
CREATE TABLE IF NOT EXISTS signature_hits (
    source     TEXT NOT NULL,
    session_id TEXT NOT NULL,
    rule_id    TEXT NOT NULL,
    first_ts   TEXT NOT NULL,  -- 이 규칙이 처음 걸린 명령어 시각 (단계 순서를 만들 때 쓴다)
    n_hits     INTEGER NOT NULL,  -- 걸린 명령어 줄 수
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
        if r.get("type") not in ("behavior", "campaign"):
            sys.exit(f"{r['id']}: type은 behavior 또는 campaign이어야 한다")
        r["regex"] = [re.compile(p) for p in r["patterns"]]
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
    for r in rules:
        matched = [ts for ts, cmd in cmds if any(rx.search(cmd) for rx in r["regex"])]
        if matched:
            hits[r["id"]] = (matched[0], len(matched))
    return hits


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
            "WHERE n_commands > 0 AND excluded = 0 AND protocol = 'ssh'"
        )
    }

    totals = Counter()  # source별 대상 세션 수
    rule_counts = defaultdict(Counter)  # source -> rule_id -> 세션 수
    no_campaign = Counter()
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
            if not any(rid.startswith("C") for rid in hits):
                no_campaign[source] += 1
            if example_rule and example_rule["id"] in hits:
                for _, cmd in cmds:
                    if any(rx.search(cmd) for rx in example_rule["regex"]):
                        examples[cmd[:120]] += 1

    for source in sorted(totals):
        n = totals[source]
        print(f"\n[{source}] 명령어가 있는 SSH 세션 {n:,}개 (테스트 제외)")
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
