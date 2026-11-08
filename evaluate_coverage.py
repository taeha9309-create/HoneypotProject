"""Compare the original regex/sequence baseline with the added observations.

Reads the input DB in read-only mode. No labels are inferred from signatures.
"""
import argparse
from collections import Counter
import csv
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
import time

from command_behaviors import observe
from match_signatures import iter_sessions, load_rules, match


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True)
    parser.add_argument('--rules', default=str(Path(__file__).parent / 'signatures/rules.yaml'))
    parser.add_argument('--baseline-rules', help='고정된 이전 규칙 YAML. 기존 규칙을 교체한 경우 필수.')
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    rules = load_rules(args.rules)
    # Baseline is the unmodified 18 single rules + S01; only added detectors removed.
    legacy_ids = {f'B{i:02d}' for i in range(1, 14)} | {f'C{i:02d}' for i in range(1, 6)} | {'S01'}
    if args.baseline_rules:
        baseline = load_rules(args.baseline_rules)
    else:
        baseline = [{k: v for k, v in rule.items() if k != 'detector'}
                    for rule in rules if rule['id'] in legacy_ids]
        if any(not rule['regex'] for rule in baseline):
            parser.error('교체된 규칙의 과거 동작을 자동 복원할 수 없습니다. --baseline-rules를 지정하세요.')
    con = sqlite3.connect(Path(args.db).resolve().as_uri() + '?mode=ro', uri=True)
    meta = {(s, sid): (protocol, excluded) for s, sid, protocol, excluded in con.execute(
        'SELECT source, session_id, protocol, excluded FROM sessions')}
    before, after, population, newly = Counter(), Counter(), Counter(), Counter()
    changed, regressions, evidence = [], [], []
    start = time.perf_counter()
    for key, rows in iter_sessions(con):
        protocol, excluded = meta.get(key, (None, 1))
        if excluded or protocol not in ('ssh', 'telnet'):
            continue
        population[protocol] += 1
        old, new = match(baseline, rows), match(rules, rows)
        before.update(old.keys())
        after.update(new.keys())
        before['ANY'] += bool(old)
        after['ANY'] += bool(new)
        if old.get('S01') != new.get('S01'):
            regressions.append('S01 result changed')
        for rid, value in old.items():
            if rid not in new or new[rid][1] < value[1]:
                regressions.append('Lost previous match: ' + rid)
            elif rid not in ('B01', 'B10') and new[rid] != value:
                regressions.append('Unexpected existing result change: ' + rid)
        if not old and new:
            newly[protocol] += 1
            reasons = set()
            sample = {}
            for ts, cmd in rows:
                for tag in observe(cmd):
                    reasons.add(tag)
                    clean = re.sub(r'(?:\d{1,3}\.){3}\d{1,3}', '<IP>', cmd)
                    clean = re.sub(r'https?://[^\s;|&]+', '<URL>', clean)
                    sample.setdefault(tag, clean[:240])
            changed.append(tuple(sorted(reasons)))
            evidence.append({
                'session_alias': sha256(('|'.join(key)).encode()).hexdigest()[:12],
                'protocol': protocol, 'new_rules': ','.join(sorted(new)),
                'observations': ','.join(sorted(reasons)),
                'examples': json.dumps(sample, ensure_ascii=False)})
    elapsed = time.perf_counter() - start
    con.close()
    result = {
        'population': dict(population), 'total_sessions': sum(population.values()),
        'before': dict(before), 'after': dict(after), 'newly_covered': dict(newly),
        'new_observation_groups': {','.join(k): n for k, n in Counter(changed).items()},
        'regressions': regressions, 'comparison_seconds': round(elapsed, 3),
        'rules_sha256': sha256(Path(args.rules).read_bytes()).hexdigest(),
        'baseline_rules_sha256': (sha256(Path(args.baseline_rules).read_bytes()).hexdigest()
                                  if args.baseline_rules else None),
        'baseline_limit': 'Rule-only comparison on the current engine; engine changes need frozen code snapshots.',
        'limits': 'Coverage of observed behavior, not maliciousness accuracy or independent recall.'}
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'coverage.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    with (output / 'newly_covered.csv').open('w', encoding='utf-8-sig', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['session_alias', 'protocol', 'new_rules',
                                                 'observations', 'examples'])
        writer.writeheader()
        writer.writerows(evidence)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if regressions:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
