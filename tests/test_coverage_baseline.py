import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import ingest

ROOT = Path(__file__).resolve().parents[1]


class CoverageBaselineTests(unittest.TestCase):
    def run_tool(self, db, output, baseline=None):
        args = [sys.executable, str(ROOT / 'evaluate_coverage.py'), '--db', str(db),
                '--rules', str(ROOT / 'signatures/rules.yaml'), '--output-dir', str(output)]
        if baseline:
            args.extend(['--baseline-rules', str(baseline)])
        return subprocess.run(args, capture_output=True, text=True, encoding='utf-8',
                              env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})

    def test_replaced_rule_cannot_silently_disappear_from_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            db, output = Path(directory) / 'missing.db', Path(directory) / 'out'
            result = self.run_tool(db, output)
            self.assertEqual(result.returncode, 2)
            self.assertIn('--baseline-rules', result.stderr)
            self.assertFalse(db.exists())
            self.assertFalse(output.exists())

    def test_explicit_baseline_file_is_used_and_fingerprinted(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            db, output, baseline = directory / 'test.db', directory / 'out', directory / 'before.yaml'
            con = sqlite3.connect(db)
            con.executescript(ingest.SCHEMA)
            con.close()
            baseline.write_text('- id: B04\n  type: behavior\n  patterns: [authorized_keys]\n', encoding='utf-8')
            result = self.run_tool(db, output, baseline)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((output / 'coverage.json').read_text(encoding='utf-8'))
            self.assertIsNotNone(report['baseline_rules_sha256'])


if __name__ == '__main__':
    unittest.main()
