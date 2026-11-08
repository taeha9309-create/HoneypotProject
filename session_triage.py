"""Read-only session triage using existing behavior rules and S01/S02 evidence.

Input requests are observed, not execution success or maliciousness verdicts.
"""
import argparse
from collections import Counter
from contextlib import closing
import csv
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3

from explain_signatures import explain_session
from match_signatures import iter_sessions, load_rules, match

LABELS = {
    'shell_entry_only': '셸 진입 요청만 탐지',
    'individual_behavior': '개별 행동 탐지',
    'linked_flow': '연결된 명령 흐름',
    'unclassified': '행동 미분류',
}


def classify_session(rules, rows):
    rows = list(rows)
    hits = match(rules, rows)
    behaviors = {r['id'] for r in rules if r['type'] == 'behavior'} & set(hits)
    evidence = []
    if {'S01', 'S02'} & set(hits):
        evidence = explain_session(rules, rows)['matches']
    linked = [item for item in evidence if item['rule_id'] in ('S01', 'S02')
              and any(e.get('relationship') in (
                  'ordered_same_literal_file', 'decoder_stdout_to_interpreter_stdin')
                  for e in item['evidence'])]
    if linked:
        category = 'linked_flow'
    elif behaviors - {'B19'}:
        category = 'individual_behavior'
    elif 'B19' in behaviors:
        category = 'shell_entry_only'
    else:
        category = 'unclassified'
    return {'category': category, 'label': LABELS[category],
            'rule_ids': sorted(hits), 'behavior_rule_ids': sorted(behaviors),
            'linked_evidence': linked, 'command_count': len(rows),
            'execution_status': 'unverified'}


def redact(text):
    text = re.sub(r'https?://[^\s;|&]+', '<URL>', text)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<IP>', text)
    text = re.sub(r'[\w.+-]+@[\w.-]+', '<ADDRESS>', text)
    return text[:300]


def review_unclassified(rows):
    # Candidate review reasons, not additional signatures or ATT&CK verdicts.
    reasons = set()
    for _, command in rows:
        command = command.strip()
        if not command:
            reasons.add('empty_input')
        elif re.match(r'^(?:Max-Forwards|Content-Length|Contact|Accept|From|To|Call-ID|CSeq|Accept-Encoding):', command, re.I):
            reasons.add('protocol_header_candidate')
        elif command in ('shell', 'enable', 'system', 'linuxshell', 'enablelinuxshell'):
            reasons.add('device_cli_entry_candidate')
        elif 'cmdline' in command and ('/proc' in command or 'self/cmdline' in command):
            reasons.add('process_cmdline_read_candidate')
        elif command == 'cat /etc/hostname':
            reasons.add('hostname_read_candidate')
        elif re.fullmatch(r'(?:/bin/)?busybox(?:\s+\S+)?', command):
            reasons.add('busybox_probe_candidate')
        else:
            reasons.add('other_unmodeled_input')
    return sorted(reasons)


def analyze_database(db, rules_path, output):
    db, rules_path, output = Path(db).resolve(), Path(rules_path).resolve(), Path(output).resolve()
    if output == db or db in output.parents:
        raise ValueError('Output must be a separate directory')
    db_hash = sha256(db.read_bytes()).hexdigest()
    rule_hash = sha256(rules_path.read_bytes()).hexdigest()
    rules = load_rules(rules_path)
    categories, rule_counts, linked_counts, reasons = Counter(), Counter(), Counter(), Counter()
    details, unmatched, examples = [], [], []
    excluded, total = 0, 0
    with closing(sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)) as con:
        metadata = {(source, sid): (protocol, skip)
                    for source, sid, protocol, skip in con.execute(
                        'SELECT source, session_id, protocol, excluded FROM sessions')}
        for key, rows in iter_sessions(con):
            protocol, skip = metadata.get(key, (None, 1))
            if skip or protocol not in ('ssh', 'telnet'):
                excluded += 1
                continue
            total += 1
            result = classify_session(rules, rows)
            alias = sha256(json.dumps(key, ensure_ascii=False).encode()).hexdigest()[:16]
            categories[result['category']] += 1
            rule_counts.update(result['rule_ids'])
            linked_counts.update(e['rule_id'] for e in result['linked_evidence'])
            details.append({'session_alias': alias, 'protocol': protocol,
                            'category': result['category'], 'label': result['label'],
                            'rule_ids': ','.join(result['rule_ids']),
                            'command_count': len(rows)})
            if result['category'] == 'unclassified':
                review = review_unclassified(rows)
                reasons.update(review)
                unmatched.append({'session_alias': alias, 'protocol': protocol,
                                  'review_candidates': review,
                                  'rule_ids': result['rule_ids'],
                                  'commands': [{'timestamp': ts, 'input': redact(cmd)} for ts, cmd in rows]})
            if result['linked_evidence']:
                examples.append({'session_alias': alias, 'protocol': protocol,
                                 'execution_status': 'unverified',
                                 'linked_evidence': result['linked_evidence'],
                                 'commands': [{'timestamp': ts, 'input': redact(cmd)} for ts, cmd in rows]})
    if sha256(db.read_bytes()).hexdigest() != db_hash:
        raise RuntimeError('Input DB changed during analysis; rerun on a stable snapshot')
    if sha256(rules_path.read_bytes()).hexdigest() != rule_hash:
        raise RuntimeError('Rules changed during analysis')
    assert sum(categories.values()) == total
    summary = {'database': db.name, 'total_sessions': total,
               'excluded_or_other_protocol_sessions_with_commands': excluded,
               'categories': {k: {'label': label, 'sessions': categories[k],
                                    'percent': round(categories[k] / total * 100, 2) if total else 0}
                              for k, label in LABELS.items()},
               'rule_session_counts_overlapping': dict(sorted(rule_counts.items())),
               'linked_rule_session_counts_overlapping': dict(linked_counts),
               'unclassified_review_candidates_overlapping': dict(reasons),
               'db_sha256': db_hash, 'database_sha256_unchanged': True,
               'rules_sha256': rule_hash,
               'classification_basis': 'Existing behavior rule matches; priority linked > individual > B19 only > unclassified',
               'population': 'excluded=0, ssh/telnet, sessions with command rows',
               'limits': ['Categories describe observed command requests, not maliciousness or execution success.',
                          'Shell-only means only B19 matched among behavior rules; other unmatched input may exist.',
                          'S01 proves the existing detector same-literal-file input relationship; S02 is a direct decode pipe.',
                          'Campaign-only matches remain behavior-unclassified.',
                          'Review reasons are heuristic candidates, may overlap, and are not new detections.',
                          'Evidence commands are redacted and truncated; indexes reference their original row positions.']}
    output.mkdir(parents=True, exist_ok=True)
    for filename, value in [('summary.json', summary), ('unclassified_review.json', unmatched),
                            ('linked_flow_evidence.json', examples)]:
        (output / filename).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    with (output / 'sessions.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['session_alias', 'protocol', 'category', 'label', 'rule_ids', 'command_count'])
        writer.writeheader()
        writer.writerows(details)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True)
    parser.add_argument('--rules', default=str(Path(__file__).parent / 'signatures/rules.yaml'))
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    print(json.dumps(analyze_database(args.db, args.rules, args.output_dir), ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
