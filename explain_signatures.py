"""Read S01/S02 evidence for one source/session without updating its database.

python explain_signatures.py --db data/honeypot.db --source local --session ID
The JSON contains untrusted command input. Execution success is unverified.
"""
import argparse
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

from command_behaviors import without_assignments
from decode_pipelines import decode_pipes
from match_signatures import download_evidence, load_rules, match


def explain_session(rules, cmds):
    """Explain matched behavioral rules using the detectors' original evidence."""
    cmds = [(ts, command) for ts, command in cmds]
    supported = [rule for rule in rules
                 if rule.get('session_detector') == 'download_chmod_execute'
                 or rule.get('detector') == 'decode_pipeline']
    hits = match(supported, cmds)
    indexes = {row: index for index, row in enumerate(cmds)}
    matches = []
    for rule in supported:
        if rule['id'] not in hits:
            continue
        evidence = []
        if rule.get('session_detector') == 'download_chmod_execute':
            for path in download_evidence(cmds):
                evidence.append({
                    'relationship': 'ordered_same_literal_file',
                    'target': path['target'],
                    'target_kind': 'absolute' if path['target'].startswith('/') else 'relative',
                    'steps': [{'action': action, 'command_index': indexes[row]}
                              for action, row in zip(('download', 'chmod', 'execute'), path['steps'])],
                })
        else:
            for index, (_, command) in enumerate(cmds):
                for pair in decode_pipes(command, without_assignments):
                    evidence.append({
                        'relationship': 'decoder_stdout_to_interpreter_stdin',
                        'command_index': index,
                        'decoder_span': [pair.decoder_start, pair.decoder_end],
                        'interpreter_span': [pair.interpreter_start, pair.interpreter_end],
                        'interpreter': pair.interpreter,
                    })
                for regex in rule['regex']:
                    for found in regex.finditer(command):
                        evidence.append({'relationship': 'configured_pattern_match',
                                         'command_index': index,
                                         'span': [found.start(), found.end()]})
        first_ts, n_hits = hits[rule['id']]
        matches.append({'rule_id': rule['id'], 'name': rule.get('name', rule['id']),
                        'first_ts': first_ts, 'n_hits': n_hits, 'evidence': evidence})
    return {
        'schema_version': 1,
        'scope': 'ordered_same_file_and_direct_decode_pipes',
        'evidence_basis': 'observed_command_input',
        'input_trust': 'untrusted',
        'execution_status': 'unverified',
        'span_unit': 'unicode_codepoints_end_exclusive',
        'supported_rule_ids': [rule['id'] for rule in supported],
        'commands': [{'timestamp': ts, 'input': command} for ts, command in cmds],
        'matches': matches,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', default='data/honeypot.db')
    parser.add_argument('--rules', default=str(Path(__file__).parent / 'signatures/rules.yaml'))
    parser.add_argument('--source', required=True)
    parser.add_argument('--session', required=True, dest='session_id')
    args = parser.parse_args()
    rules = load_rules(args.rules)
    with closing(sqlite3.connect(Path(args.db).resolve().as_uri() + '?mode=ro', uri=True)) as con:
        cmds = con.execute(
            'SELECT ts, command FROM commands WHERE source = ? AND session_id = ? ORDER BY ts, command',
            (args.source, args.session_id),
        ).fetchall()
    if not cmds:
        parser.error('No command input found for this source/session')
    report = explain_session(rules, cmds)
    report.update(source=args.source, session_id=args.session_id,
                  rules_sha256=sha256(Path(args.rules).read_bytes()).hexdigest())
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
