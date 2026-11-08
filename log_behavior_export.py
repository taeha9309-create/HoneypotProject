"""Export DB input rows without executing input or changing existing detection.

Only B rules label commands. S/C retain their original session semantics.
"""
import argparse
from collections import Counter
from contextlib import closing
import csv
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

from command_behaviors import observe, without_assignments
from additional_signatures import observe_additional
from match_signatures import load_rules


def packed(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def derived_id(table, values):
    return 'db-row-v1:' + sha256(packed([table, list(values)]).encode('utf-8')).hexdigest()


def label_command(rules, text):
    tags = observe(text) | observe_additional(text, without_assignments)
    labels = []
    for rule in rules:
        if (not rule['id'].startswith('B') or rule['type'] != 'behavior'
                or 'sequence' in rule or 'session_detector' in rule):
            continue
        evidence = []
        for pattern in rule['regex']:
            for found in pattern.finditer(text):
                evidence.append({'kind': 'regex_match', 'pattern': pattern.pattern,
                                 'span': list(found.span()), 'text': found.group(),
                                 'claim': 'literal_pattern_match_only'})
        if rule.get('detector') in tags:
            evidence.append({'kind': 'detector_observation', 'detector': rule['detector'],
                             'scope': 'whole_original_input',
                             'claim': 'existing_detector_returned_tag'})
        if evidence:
            labels.append({'rule_id': rule['id'], 'name': rule['name'], 'evidence': evidence})
    return labels


def iter_records(con, rules):
    metadata = {(s, sid): {'protocol': protocol, 'excluded': excluded}
                for s, sid, protocol, excluded in con.execute(
                    'SELECT source,session_id,protocol,excluded FROM sessions')}
    for table, columns, kind in (
        ('commands', 'source,session_id,ts,command', 'command_input'),
        ('failed_commands', 'source,session_id,ts,command', 'failure_fragment'),
        ('downloads', 'source,session_id,ts,url,shasum', 'download_event'),
    ):
        for values in con.execute('SELECT ' + columns + ' FROM ' + table + ' ORDER BY ' + columns):
            source, sid, timestamp, *payload = values
            labels = label_command(rules, payload[0]) if kind == 'command_input' else []
            yield {'log_id': derived_id(table, values), 'id_basis': 'table_and_all_original_fields_v1',
                   'source_table': table, 'event_kind': kind, 'source': source,
                   'session_id': sid, 'timestamp': timestamp,
                   'raw_command': payload[0] if kind == 'command_input' else None,
                   'event_payload': dict(zip(('url', 'shasum') if table == 'downloads'
                                             else ('command',), payload)),
                   'session_metadata': metadata.get((source, sid)),
                   'behavior_rule_ids': [label['rule_id'] for label in labels],
                   'behavior_names': [label['name'] for label in labels],
                   'labels': labels, 'unclassified': not labels if kind == 'command_input' else None,
                   'execution_status': 'unverified', 'input_trust': 'untrusted'}


def export_database(db, rules_path, output):
    db, rules_path, output = map(lambda p: Path(p).resolve(), (db, rules_path, output))
    # A fresh directory prevents overwriting an input, DB sidecar, or earlier report.
    if output == db or output in db.parents:
        raise ValueError('Output must be a fresh separate directory')
    before = sha256(db.read_bytes()).hexdigest()
    rules_hash = sha256(rules_path.read_bytes()).hexdigest()
    rules = load_rules(rules_path)
    counts, rule_counts = Counter(), Counter()
    output.mkdir(parents=True, exist_ok=False)
    with closing(sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)) as con:
        con.execute('PRAGMA query_only=ON')
        con.execute('BEGIN')
        schema_before = con.execute('SELECT type,name,sql FROM sqlite_master ORDER BY type,name').fetchall()
        hits_before = con.execute('SELECT * FROM signature_hits ORDER BY source,session_id,rule_id').fetchall()
        with (output / 'logs.jsonl').open('x', encoding='utf-8', newline='') as js, (output / 'logs.csv').open('x', encoding='utf-8-sig', newline='') as cs:
            writer = None
            for row in iter_records(con, rules):
                js.write(packed(row) + '\n')
                if writer is None:
                    writer = csv.DictWriter(cs, fieldnames=list(row))
                    writer.writeheader()
                writer.writerow({key: packed(value) if isinstance(value, (list, dict)) or value is None
                                 else value for key, value in row.items()})
                counts[row['event_kind']] += 1
                if row['unclassified']:
                    counts['unclassified_command_input'] += 1
                rule_counts.update(row['behavior_rule_ids'])
        assert schema_before == con.execute('SELECT type,name,sql FROM sqlite_master ORDER BY type,name').fetchall()
        assert hits_before == con.execute('SELECT * FROM signature_hits ORDER BY source,session_id,rule_id').fetchall()
    if sha256(db.read_bytes()).hexdigest() != before:
        raise RuntimeError('Database changed during export; discard this report and use a stable snapshot')
    if sha256(rules_path.read_bytes()).hexdigest() != rules_hash:
        raise RuntimeError('Rules changed during export; discard this report')
    summary = {'database': str(db), 'db_sha256': before, 'database_unchanged': True,
               'schema_and_signature_hits_unchanged': True, 'rules_sha256': rules_hash,
               'counts': dict(counts), 'overlapping_b_command_counts': dict(rule_counts),
               'population': 'all stored rows, including excluded/other protocols; metadata retained',
               'span_unit': 'unicode_codepoints_end_exclusive',
               'limits': ['B labels reproduce existing OR of regex and detector observations; no success or maliciousness verdict.',
                          'Regex evidence proves only the exact substring match, including legacy quoted-example false positives.',
                          'Detector evidence is whole-input tag provenance; no invented subcommand offsets or execution claims.',
                          'Compound inputs remain one original row; label cooccurrence does not prove S flow.',
                          'IDs identify deduplicated DB rows, not original raw-log events; identical rows in different DB snapshots share IDs.',
                          'Failure fragments are not full input commands and are not classified.',
                          'Only stored commands, failure fragments and downloads are exported; login/connect events are not retained as events by this DB.',
                          'CSV preserves raw text and is intended for data import; use JSONL to inspect untrusted input safely.']}
    (output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True)
    parser.add_argument('--rules', default=str(Path(__file__).parent / 'signatures/rules.yaml'))
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    print(json.dumps(export_database(args.db, args.rules, args.output_dir), ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
