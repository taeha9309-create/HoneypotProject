import gzip
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

import ingest


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = self.root / 'cowrie.json'
        self.db = self.root / 'test.db'

    def event(self, **kwargs):
        return dict(dict(eventid='cowrie.session.file_download', session='s',
                         timestamp='2026-11-08T00:00:00Z'), **kwargs)

    def write(self, events):
        self.log.write_text(''.join(json.dumps(e)+'\n' for e in events), encoding='utf-8')

    def run_ingest(self, force=False):
        args = ['ingest.py', str(self.root), '--db', str(self.db), '--source', 'test']
        with patch.object(sys, 'argv', args + (['--force'] if force else [])):
            ingest.main()

    def rows(self, table='downloads'):
        with sqlite3.connect(self.db) as c:
            return c.execute('SELECT * FROM '+table).fetchall()

    def test_repeat_growth_null_empty_force(self):
        events = [self.event(), self.event(url=None), self.event(url='')]
        self.write(events)
        self.run_ingest()
        self.run_ingest()
        self.run_ingest(True)
        self.assertEqual(len(self.rows()), 1)
        self.write(events + [self.event(url='https://example.invalid/data')])
        self.run_ingest()
        self.assertEqual(len(self.rows()), 2)

    def test_legacy_null_empty_and_key_boundaries(self):
        with sqlite3.connect(self.db) as c:
            c.executescript(ingest.SCHEMA)
            c.execute("INSERT INTO downloads VALUES ('test','s','t',NULL,'old')")
            c.execute("INSERT INTO downloads VALUES ('test','s','u','','old')")
            ingest.save(c, 'test', {}, [], [], [('s','t','','new'), ('s','u',None,'new'),
                        ('s','v',None,None), ('other','u',None,None)])
            ingest.save(c, 'other', {}, [], [], [('s','u',None,None)])
        self.assertEqual(len(self.rows()), 5)
        self.assertEqual(self.rows()[0][-1], 'old')

    def test_rotation_gzip_partial_tail(self):
        self.write([self.event()])
        self.run_ingest()
        rotated = self.root / 'cowrie.json.2026-11-08'
        self.log.rename(rotated)
        self.write([self.event(), self.event(url='x')])
        with self.log.open('a', encoding='utf-8') as f:
            f.write('{"eventid":')
        self.run_ingest()
        self.assertEqual(len(self.rows()), 2)
        with gzip.open(self.root / 'cowrie.json.2026-11-08.gz', 'wt', encoding='utf-8') as f:
            f.write(rotated.read_text(encoding='utf-8'))
        self.write([self.event(), self.event(url='x'), self.event(url='y')])
        self.run_ingest()
        self.assertEqual(len(self.rows()), 3)

    def test_ips_force_preserves_derived_results(self):
        self.assertTrue({'39.124.23.44','118.235.26.80','211.238.109.139'} <= ingest.TEST_IPS)
        self.write([dict(self.event(src_ip=ip), session=str(i)) for i, ip in
                    enumerate(['211.238.109.168','211.108.129.43'])])
        self.run_ingest()
        with sqlite3.connect(self.db) as c:
            c.execute('UPDATE sessions SET excluded=0')
            for table in ('signature_hits', 'ml_results'):
                c.execute('CREATE TABLE '+table+' (payload BLOB)')
                c.execute('INSERT INTO '+table+" VALUES (X'0102')")
        self.run_ingest()
        self.assertEqual([r[-1] for r in self.rows('sessions')], [0,0])
        self.run_ingest(True)
        self.assertEqual([r[-1] for r in self.rows('sessions')], [1,1])
        for table in ('signature_hits','ml_results'):
            self.assertEqual(self.rows(table), [(b'\x01\x02',)])
