import sqlite3
import tempfile
import unittest
from pathlib import Path
from hashlib import sha256
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.request import urlopen

import ingest
import match_signatures
from dashboard.app import Dashboard, ROOT, make_handler


class DashboardTests(unittest.TestCase):
    def test_http_pages_and_invalid_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Dashboard(Path(directory)/'missing.db',ROOT/'signatures/rules.yaml')
            server = ThreadingHTTPServer(('127.0.0.1',0),make_handler(app))
            worker = Thread(target=server.serve_forever,daemon=True)
            worker.start()
            try:
                for page in ['overview','sessions','detection','ml']:
                    with urlopen(f'http://127.0.0.1:{server.server_port}/{page}') as response:
                        self.assertEqual(response.status,200)
                        self.assertIn('데이터 없음',response.read().decode('utf-8'))
                        self.assertIn("default-src 'none'",response.headers['Content-Security-Policy'])
            finally:
                server.shutdown(); server.server_close(); worker.join()

    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'missing.db'
            app = Dashboard(path,ROOT/'signatures/rules.yaml')
            self.assertIn('데이터 없음',app.render('/overview',{}))
            self.assertFalse(path.exists())

    def test_real_schema_filters_evidence_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'test.db'
            con = sqlite3.connect(path)
            con.executescript(ingest.SCHEMA+match_signatures.SCHEMA)
            for source,excluded in [('seoul',0),('syd',0),('test',1)]:
                con.execute('INSERT INTO sessions(source,session_id,protocol,src_ip,start_ts,excluded) VALUES(?,?,?,?,?,?)',(source,'same','ssh','192.0.2.1','2026-11-01T00:00:00Z',excluded))
            cmds = [('2026-11-01T00:00:00Z','uname -a'),('2026-11-01T00:00:01Z','<script>alert(1)</script>')]
            con.executemany('INSERT INTO commands VALUES(?,?,?,?)',[('seoul','same',*r) for r in cmds])
            con.execute('INSERT INTO signature_hits VALUES(?,?,?,?,?)',('seoul','same','B01',cmds[0][0],1))
            con.commit(); con.close()
            before = sha256(path.read_bytes()).digest()
            app = Dashboard(path,ROOT/'signatures/rules.yaml')
            overview = app.render('/overview',{})
            self.assertIn('미구현',overview)
            filtered = app.render('/sessions',{'source':'seoul','commands':'1'})
            self.assertIn('총 1개',filtered)
            self.assertNotIn('syd / same',filtered)
            self.assertIn('총 0개',app.render('/sessions',{'ip':"' OR 1=1 --"}))
            detail = app.render('/session',{'source':'seoul','session':'same'})
            self.assertIn('시스템 사양 조사',detail)
            self.assertIn('명령어 근거',detail)
            self.assertNotIn('<script>',detail)
            self.assertIn('&lt;script&gt;',detail)
            self.assertNotIn('uname -a',app.render('/session',{'source':'syd','session':'same'}))
            self.assertIn('실제 ml_clusters 결과가 없습니다',app.render('/ml',{}))
            self.assertIn('B01',app.render('/detection',{'rule':'B01'}))
            self.assertEqual(before,sha256(path.read_bytes()).digest())

    def test_ml_cluster_key_includes_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'test.db'
            con = sqlite3.connect(path)
            con.executescript(ingest.SCHEMA)
            # Same column contract as ml/cluster.py, without importing ML training dependencies.
            con.execute('CREATE TABLE ml_clusters(source,session_id,protocol,model,params,cluster_id,is_noise,outlier_score,probability,assigned_by,assigned_at)')
            for protocol in ['ssh','telnet']:
                con.execute('INSERT INTO sessions(source,session_id) VALUES(?,?)',('local',protocol))
                con.execute('INSERT INTO ml_clusters VALUES(?,?,?,?,?,?,?,?,?,?,?)',('local',protocol,protocol,'hdbscan','{}',0,0,.2,.8,'fit','2026-11-01'))
            con.commit(); con.close()
            app = Dashboard(path,ROOT/'signatures/rules.yaml')
            detail = app.render('/ml',{'protocol':'ssh','cluster':'0'})
            self.assertIn('session=ssh',detail)
            self.assertNotIn('session=telnet',detail)


if __name__ == '__main__':
    unittest.main()
