from pathlib import Path
from contextlib import closing
from dataclasses import FrozenInstanceError
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import ingest
from command_behaviors import without_assignments
from decode_pipelines import decode_pipes
from match_signatures import load_rules, match

ROOT = Path(__file__).resolve().parents[1]


class DecodePipelineTests(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(ROOT / 'signatures/rules.yaml')

    def hit(self, command):
        return match(self.rules, [('2026-11-02T00:00:00Z', command)]).get('S02')

    def test_development_command_shapes(self):
        for command in ['echo "ZXhhbXBsZQ==" | base64 --decode | bash',
                        'sleep 15s && cd /var/tmp; echo "ZXhhbXBsZQ==" | base64 --decode | bash',
                        'cd /tmp || /var/tmp || /dev/shm; echo "ZXhhbXBsZQ==" | base64 --decode | perl',
                        'echo "ZXhhbXBsZQ==">.payload; base64 --decode .payload | bash']:
            with self.subTest(command=command):
                self.assertIsNotNone(self.hit(command))

    def test_paths_busybox_options_and_assignments(self):
        for command in ['base64 -d | sh', '/usr/bin/base64 -di payload | /bin/bash -s',
                        'busybox base64 -d | busybox sh',
                        'LC_ALL=C /bin/busybox base64 --decode | LANG=C /bin/sh -e',
                        'base64 --ignore-garbage -d -- payload | perl -w',
                        'base64 -d | bash -s -- argument', 'base64 -d | sh -',
                        'base64 -d |\n bash', 'base64 -d | bash # comment']:
            with self.subTest(command=command):
                self.assertIsNotNone(self.hit(command))

    def test_requires_direct_pipe_and_decode_mode(self):
        for command in ['base64 -d', 'base64 -d; bash', 'base64 -d && bash',
                        'base64 -d || bash', 'base64 -d & bash', 'bash | base64 -d',
                        'base64 -d | cat; bash', 'base64 -d | cat | bash',
                        'base64 | sh', 'base64 -- -d | sh', 'base64 --help -d | sh',
                        'base64 --decode --version | bash']:
            with self.subTest(command=command):
                self.assertIsNone(self.hit(command))

    def test_literal_examples_and_comments_are_not_commands(self):
        for command in ['echo "base64 -d | bash"', "printf '%s' 'base64 -d | perl'",
                        '# base64 -d | bash', 'echo base64 -d | bash',
                        'base64 -d "data|bash"', r'echo base64\ -d\ \|\ bash',
                        "'LC_ALL=C' base64 -d | sh", 'base64 -d # | sh']:
            with self.subTest(command=command):
                self.assertIsNone(self.hit(command))

    def test_interpreter_must_read_program_from_stdin(self):
        for command in ['base64 -d | bash local.sh', 'base64 -d | bash -c "echo ok"',
                        'base64 -d | sh -n', 'base64 -d | bash --help',
                        'base64 -d | perl -e "print 1"', 'base64 -d | perl -c',
                        'base64 -d | perl local.pl']:
            with self.subTest(command=command):
                self.assertIsNone(self.hit(command))

    def test_redirects_and_unsupported_shell_constructs(self):
        for command in ['base64 -d > output | bash', 'base64 -d | sh < local.sh',
                        'base64 -d 2>/dev/null | bash',  # conservative unsupported form
                        'echo "$(cat input)" | base64 -d | sh',
                        '(base64 -d) | bash', 'base64 -d |& bash',
                        'base64 -d | bash |', '| base64 -d | bash',
                        'base64 -d | bash &&',
                        'cat <<EOF\nbase64 -d | bash\nEOF',
                        "echo 'unterminated; base64 -d | sh", 'base64 -d | sh\\']:
            with self.subTest(command=command):
                self.assertIsNone(self.hit(command))

    def test_no_cross_row_or_cross_session_linking(self):
        rows = [('2026-11-02T00:00:00Z', 'base64 -d'),
                ('2026-11-02T00:00:01Z', 'bash')]
        self.assertNotIn('S02', match(self.rules, rows))
        self.assertNotIn('S02', match(self.rules, rows[:1]))
        self.assertNotIn('S02', match(self.rules, rows[1:]))

    def test_count_matching_rows_not_pipeline_combinations(self):
        command = 'base64 -d | sh; base64 --decode input | perl'
        self.assertEqual(self.hit(command), ('2026-11-02T00:00:00Z', 1))
        rows = [('2026-11-02T00:00:00Z', command), ('2026-11-02T00:00:01Z', command)]
        self.assertEqual(match(self.rules, rows)['S02'], ('2026-11-02T00:00:00Z', 2))

    def test_evidence_spans_identify_connected_commands(self):
        text = 'echo example; base64 -d payload | /bin/bash -s; echo done'
        pairs = decode_pipes(text, without_assignments)
        self.assertEqual(len(pairs), 1)
        pair = pairs[0]
        self.assertEqual(text[pair.decoder_start:pair.decoder_end].strip(), 'base64 -d payload')
        self.assertEqual(text[pair.interpreter_start:pair.interpreter_end].strip(), '/bin/bash -s')
        self.assertEqual(pair.interpreter, 'bash')

    def test_evidence_is_immutable_and_oversized_input_is_declined(self):
        pairs = decode_pipes('base64 -d | sh', without_assignments)
        with self.assertRaises(FrozenInstanceError):
            pairs[0].interpreter = 'perl'
        self.assertEqual(decode_pipes('base64 -d | sh' + ' ' * 131072, without_assignments), ())

    def test_cli_storage_repeat_and_session_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'test.sqlite'
            with closing(sqlite3.connect(db)) as con, con:
                con.executescript(ingest.SCHEMA)
                for source, sid, protocol, command in [
                    ('fixture', 'ssh_hit', 'ssh', 'base64 -d | bash'),
                    ('fixture', 'telnet_hit', 'telnet', 'base64 -d | perl'),
                    ('a', 'shared', 'ssh', 'base64 -d'),
                    ('b', 'shared', 'ssh', 'bash')]:
                    con.execute('INSERT INTO sessions(source,session_id,protocol,n_commands) VALUES (?,?,?,1)',
                                (source, sid, protocol))
                    con.execute('INSERT INTO commands VALUES (?,?,?,?)',
                                (source, sid, '2026-11-02T00:00:00Z', command))
            for _ in range(2):
                result = subprocess.run(
                    [sys.executable, str(ROOT / 'match_signatures.py'), '--db', str(db),
                     '--rules', str(ROOT / 'signatures/rules.yaml'), '--examples', 'S02'],
                    capture_output=True, text=True, encoding='utf-8',
                    env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('base64 -d | bash', result.stdout)
                with closing(sqlite3.connect(db)) as con:
                    self.assertEqual(con.execute("SELECT source,session_id,n_hits FROM signature_hits "
                                                 "WHERE rule_id='S02' ORDER BY session_id").fetchall(),
                                     [('fixture', 'ssh_hit', 1), ('fixture', 'telnet_hit', 1)])


if __name__ == '__main__':
    unittest.main()
