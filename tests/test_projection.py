import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import ingest
from dashboard.projection import snapshot, render


class ProjectionTests(unittest.TestCase):
    def test_stale_cache_hidden_and_safe_pattern_navigation(self):
        with tempfile.TemporaryDirectory() as folder:
            con=sqlite3.connect(':memory:')
            con.executescript(ingest.SCHEMA)
            con.execute('CREATE TABLE ml_clusters(source,session_id,protocol,cluster_id)')
            con.execute("INSERT INTO sessions(source,session_id) VALUES('syd','one')")
            con.execute("INSERT INTO commands VALUES('syd','one','2026-11-01','uname -a')")
            con.execute("INSERT INTO ml_clusters VALUES('syd','one','telnet',3)")
            records,digest=snapshot(con)
            self.assertEqual(len(records),1)
            cache=Path(folder)/'points.json'
            cache.write_text(json.dumps({'fingerprint':digest,'points':[{'id':'abc','protocol':'telnet','cluster_id':3,'x':0,'y':0,'members':[['syd','one']],'preview':'<script>alert(1)</script>'}]}),encoding='utf-8')
            html=render(con,{'protocol':'telnet','pattern':'abc'},cache)
            self.assertIn('<svg',html)
            self.assertIn('session=one',html)
            self.assertNotIn('<script>',html)
            self.assertIn('&lt;script&gt;',html)
            con.execute("UPDATE commands SET command='changed'")
            stale=render(con,{},cache)
            self.assertIn('현재 DB와 일치하지 않습니다',stale)
            self.assertNotIn('<svg',stale)
            con.close()

    def test_excluded_and_test_ip_are_not_projected(self):
        con=sqlite3.connect(':memory:')
        con.executescript(ingest.SCHEMA)
        con.execute('CREATE TABLE ml_clusters(source,session_id,protocol,cluster_id)')
        for sid,excluded,ip in [('ok',0,None),('excluded',1,None),('testip',0,'211.238.109.139')]:
            con.execute('INSERT INTO sessions(source,session_id,excluded,src_ip) VALUES(?,?,?,?)',('syd',sid,excluded,ip))
            con.execute('INSERT INTO commands VALUES(?,?,?,?)',('syd',sid,'2026-11-01','uname'))
            con.execute('INSERT INTO ml_clusters VALUES(?,?,?,?)',('syd',sid,'telnet',0))
        self.assertEqual([r['session_id'] for r in snapshot(con)[0]],['ok'])
        con.close()
