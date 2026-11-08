from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import ingest
from log_behavior_export import derived_id, export_database, iter_records, label_command
from match_signatures import SCHEMA, load_rules, match

ROOT = Path(__file__).resolve().parents[1]


class LogBehaviorExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(ROOT / 'signatures/rules.yaml')

    def test_positive_multi_label_and_exact_evidence(self):
        text = 'echo 한글; cat /etc/passwd; chmod u+x /tmp/p; ls; sh'
        labels = label_command(self.rules, text)
        self.assertTrue({'B11', 'B18', 'B19', 'B20'} <= {x['rule_id'] for x in labels})
        for label in labels:
            for evidence in label['evidence']:
                if evidence['kind'] == 'regex_match':
                    self.assertEqual(text[slice(*evidence['span'])], evidence['text'])
                else:
                    self.assertEqual(evidence['scope'], 'whole_original_input')

    def test_negative_and_legacy_false_positive_provenance(self):
        for text in ['enable', 'echo "cat /etc/passwd; ls; sh"',
                     'chmod -x /tmp/p', 'chmod +x', 'ls --help']:
            self.assertEqual(label_command(self.rules, text), [], text)
        labels = label_command(self.rules, 'echo "wget example.invalid/p"')
        b08 = next(x for x in labels if x['rule_id'] == 'B08')
        self.assertEqual(b08['evidence'][0]['claim'], 'literal_pattern_match_only')

    def test_regression_all_b_matches(self):
        for text in ['sh', 'ls; cat /etc/passwd', 'base64 -d input | sh',
                     'wget example.invalid/p; chmod +x p; ./p', 'uname -a',
                     'echo "wget"', 'passwd --help', 'dota', '',
                     'echo "unterminated; sh', 'cat /proc/version']:
            expected = {rid for rid in match(self.rules, [('2026-11-07T00:00:00Z', text)])
                        if rid.startswith('B')}
            self.assertEqual({x['rule_id'] for x in label_command(self.rules, text)}, expected)

    def test_export_roundtrip_stable_ids_events_and_no_database_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / 'input.db'
            with closing(sqlite3.connect(db)) as con:
                con.executescript(ingest.SCHEMA + SCHEMA)
                text = 'ls; sh\n echo "=1+1,한글"'
                for source in ('a', 'b'):
                    con.execute('INSERT INTO commands VALUES (?,?,?,?)', (source, 'same', 't', text))
                con.execute('INSERT INTO failed_commands VALUES (?,?,?,?)', ('a', 'same', 't', 'sh'))
                con.execute('INSERT INTO downloads VALUES (?,?,?,?,?)', ('a', 'same', 't', 'https://example.invalid/p', None))
                con.execute('INSERT INTO signature_hits VALUES (?,?,?,?,?)', ('a', 'same', 'S01', 't', 99))
                con.commit()
            before = sha256(db.read_bytes()).hexdigest()
            for name in ('first', 'second'):
                summary = export_database(db, ROOT / 'signatures/rules.yaml', Path(temp) / name)
                self.assertEqual(summary['counts']['command_input'], 2)
                self.assertEqual(sha256(db.read_bytes()).hexdigest(), before)
            first = (Path(temp) / 'first/logs.jsonl').read_text(encoding='utf-8')
            self.assertEqual(first, (Path(temp) / 'second/logs.jsonl').read_text(encoding='utf-8'))
            rows = [json.loads(line) for line in first.splitlines()]
            self.assertEqual(len({r['log_id'] for r in rows}), 4)
            self.assertEqual(rows[0]['raw_command'], text)
            for row in rows[2:]:
                self.assertIsNone(row['unclassified'])
                self.assertEqual(row['labels'], [])
            import csv
            with (Path(temp) / 'first/logs.csv').open(encoding='utf-8-sig', newline='') as f:
                self.assertEqual(next(csv.DictReader(f))['raw_command'], text)
            with self.assertRaises(FileExistsError):
                export_database(db, ROOT / 'signatures/rules.yaml', Path(temp) / 'first')
            missing = Path(temp) / 'missing.db'
            with self.assertRaises(FileNotFoundError):
                export_database(missing, ROOT / 'signatures/rules.yaml', Path(temp) / 'missing')
            self.assertFalse(missing.exists())

    def test_id_has_no_rowid_or_database_path_dependency(self):
        values = ('a', 'session', 'timestamp', 'ls')
        self.assertEqual(derived_id('commands', values), derived_id('commands', list(values)))
        self.assertNotEqual(derived_id('commands', values), derived_id('failed_commands', values))


if __name__ == '__main__':
    unittest.main()
