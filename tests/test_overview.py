from contextlib import closing
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import ingest
from dashboard.overview import stats,render
from dashboard.import_auth import import_logs


class OverviewTests(unittest.TestCase):
    def fixture(self,root):
        db=root/'source.db'
        con=sqlite3.connect(db);con.executescript(ingest.SCHEMA)
        for sid,source,excluded,ts in [('a','syd',0,'2026-11-01T15:30:00Z'),('b','syd',0,'2026-11-02T02:00:00Z'),('c','syd',1,'2026-11-02T02:00:00Z'),('d','other',0,'2026-11-02T02:00:00Z')]:
            con.execute('INSERT INTO sessions(source,session_id,excluded,start_ts,end_ts,src_ip,protocol,login_success,username,password) VALUES(?,?,?,?,?,?,?,?,?,?)',(source,sid,excluded,ts,ts,'192.0.2.1','ssh',1,'<user>','</script><script>alert(1)</script>'))
        con.execute("INSERT INTO commands VALUES('syd','a','2026-11-01T15:30:00Z','uname')")
        con.commit();return db,con

    def test_kst_day_filter_no_fabricated_attempts_and_safe_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);db,con=self.fixture(root)
            with patch('dashboard.overview.ROOT',root):
                data=stats(con,{'day':'2026-11-02','source':'syd'})
                self.assertEqual(data['total'],2)
                self.assertEqual(data['commands'],1)
                self.assertEqual(data['hourly'][0],1)
                self.assertIsNone(data['auth'])
                self.assertEqual(data['success_sessions'],2)
                self.assertEqual(data['unplaced'],2)
                self.assertEqual(len(data['events']),2)
                html=render(con,{'day':'2026-11-02'})
                self.assertNotIn('</script><script>alert',html)
                self.assertIn('\\u003c',html)
                with self.assertRaises(ValueError):stats(con,{'day':'bad'})
                with self.assertRaises(ValueError):stats(con,{'source':"' OR 1=1 --"})
                live=stats(con,{'mode':'live'},now=datetime(2026,11,10,tzinfo=timezone.utc))
                self.assertEqual(live['total'],0)
                self.assertTrue(live['archived'])
            con.close()

    def test_auth_import_deduplicates_and_preserves_primary_database(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);db,con=self.fixture(root)
            raw=root/'events.json'
            event={'session':'a','src_ip':'192.0.2.1','timestamp':'2026-11-01T15:30:00Z','eventid':'cowrie.login.failed','username':'root','password':'guess'}
            raw.write_text('\n'.join(json.dumps(e) for e in [event,event,dict(event,session='c'),dict(event,src_ip='192.0.2.99')]),encoding='utf-8')
            before=hashlib.sha256(db.read_bytes()).hexdigest()
            out=root/'data/overview_auth.db'
            self.assertEqual(import_logs(db,[str(raw)],'syd',out),1)
            self.assertEqual(import_logs(db,[str(raw)],'syd',out),0)
            with patch('dashboard.overview.ROOT',root):
                data=stats(con,{'day':'2026-11-02','source':'syd'})
                self.assertEqual(data['auth'],{'total':1,'success':0,'failed':1})
                self.assertEqual(data['users'],[('root',1)])
            self.assertEqual(before,hashlib.sha256(db.read_bytes()).hexdigest())
            con.close()
