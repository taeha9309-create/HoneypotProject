import itertools
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing

import ingest
from command_behaviors import observe
from match_signatures import load_rules, match

ROOT = Path(__file__).resolve().parents[1]


class BehaviorExpansionTests(unittest.TestCase):
    def test_self_executable_observations(self):
        for cmd in ['cat /proc/self/exe', '/bin/busybox cat /proc/self/exe || cat /proc/self/exe',
                    '/bin/cat /proc/self/exe', 'cd /tmp; cat /proc/self/exe']:
            with self.subTest(cmd=cmd):
                self.assertIn('self_exe_read', observe(cmd))

    def test_shell_script_without_extension(self):
        for cmd in ['sh .k', 'sh /tmp/.b', '/bin/sh payload', 'busybox sh .k',
                    '/bin/busybox ash -ex payload', 'bash -- "a b"', 'ping; sh .k']:
            with self.subTest(cmd=cmd):
                self.assertIn('shell_script', observe(cmd))

    def test_hex_file_writes(self):
        for cmd in [r'echo -ne "\x7f\x45\x4c\x46" > .d',
                    r'/bin/busybox echo -ne "\x23\x21\x2f\x62" >> .k',
                    r"printf '\x01\x02\x03\x04'>out",
                    r'printf "\xFF\x00\xAB\xCD" >> "file name"']:
            with self.subTest(cmd=cmd):
                self.assertIn('hex_file_write', observe(cmd))

    def test_firewall_flush(self):
        for cmd in ['iptables -F', 'ip6tables --flush', '/sbin/iptables -t nat -F',
                    '/bin/busybox iptables -F INPUT']:
            with self.subTest(cmd=cmd):
                self.assertIn('firewall_flush', observe(cmd))

    def test_negative_controls(self):
        # Negative for these four observations, not a claim that all are benign.
        commands = ['sh', 'shell', 'enable', 'system', 'linuxshell', 'busybox',
                    'sh -c "echo hello"', 'sh -s', 'sh -n .k', 'sh -o errexit',
                    'sh --help', 'sh < input', 'sh -', 'sh $FILE',
                    'echo "cat /proc/self/exe; sh .k; iptables -F"',
                    '# cat /proc/self/exe; sh .k',
                    'printf "%s" "iptables -F"', 'cat /etc/hostname',
                    'cat --help /proc/self/exe', 'cat --version /proc/self/exe',
                    'iptables -L', 'iptables-save', 'iptables --help -F',
                    r'echo "\x01\x02\x03\x04"',
                    r'echo "\x01\x02\x03" > out',
                    r'echo "\x01\x02\x03\x04 > out"',
                    r'echo "\x01\x02\x03\x04" > /dev/null',
                    r'echo "\x01\x02\x03\x04" 2> error',
                    'echo $(cat /proc/self/exe)', 'echo `cat /proc/self/exe`',
                    "echo 'unterminated; sh .k", 'x' * 131073]
        for cmd in commands:
            with self.subTest(cmd=cmd[:100]):
                self.assertEqual(observe(cmd), set())

    def test_whitespace_and_separator_variants(self):
        for space, separator in itertools.product([' ', '\t', '  '], [';', '&&', '\n']):
            cmd = f'cat{space}/proc/self/exe{separator}sh{space}.k'
            self.assertEqual(observe(cmd), {'self_exe_read', 'shell_script'})

    def test_rule_integration_and_row_counts(self):
        rules = load_rules(ROOT / 'signatures/rules.yaml')
        rows = [('2026-11-02T00:00:00Z', 'cat /proc/self/exe'),
                ('2026-11-02T00:00:01Z', 'sh .k'),
                ('2026-11-02T00:00:02Z', r'echo -ne "\x01\x02\x03\x04" > .k'),
                ('2026-11-02T00:00:03Z', 'iptables -F')]
        hits = match(rules, rows)
        for rid in ['B01', 'B10', 'B14', 'B15']:
            self.assertEqual(hits[rid][1], 1)
        self.assertNotIn('S01', hits)

    def test_invalid_detector_configuration(self):
        for fields in ['detector: unknown', 'detector: shell_script\n  sequence: [x, y]']:
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / 'rules.yaml'
                path.write_text('- id: R\n  type: behavior\n  ' + fields, encoding='utf-8')
                with self.assertRaises(SystemExit):
                    load_rules(path)

    def test_telnet_exclusion_and_cli_repeat(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / 'db.sqlite'
            with closing(sqlite3.connect(db)) as con, con:
                con.executescript(ingest.SCHEMA)
                for sid, protocol, excluded in [('ssh1', 'ssh', 0), ('telnet1', 'telnet', 0),
                                                 ('test1', 'telnet', 1), ('other', None, 0)]:
                    con.execute('INSERT INTO sessions(source,session_id,protocol,excluded,n_commands) '
                                'VALUES (?,?,?,?,1)', ('fixture', sid, protocol, excluded))
                    con.execute('INSERT INTO commands VALUES (?,?,?,?)',
                                ('fixture', sid, '2026-11-02T00:00:00Z', 'iptables -F'))
            args = [sys.executable, str(ROOT / 'match_signatures.py'), '--db', str(db),
                    '--rules', str(ROOT / 'signatures/rules.yaml'), '--examples', 'B15']
            for _ in range(2):
                result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8',
                                        env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('SSH/Telnet', result.stdout)
                self.assertIn('2 (100.0%)', result.stdout)
                self.assertIn('iptables -F', result.stdout)
            with closing(sqlite3.connect(db)) as con:
                # Storage policy remains all sessions; summary filters exclusions/protocol.
                self.assertEqual(con.execute("SELECT COUNT(*) FROM signature_hits WHERE rule_id='B15'")
                                 .fetchone()[0], 4)


if __name__ == '__main__':
    unittest.main()
