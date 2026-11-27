"""패턴 분석의 신규 후보 거르기 테스트. 합성 데이터만 쓴다 (실제 로그 아님)."""
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'streamlit_app'))
import patterns as P  # noqa: E402


def _row(sid, reasons, score, seq):
    return {'protocol': 'telnet', 'source': 'syd', 'session_id': sid, 'src_ip': '1.2.3.4',
            'start_ts': '2026-11-01T00:00:00Z', 'cluster_id': 0, 'outlier_score': score,
            'n_commands': 1, 'downloaded': 0, 'n_sessions': 1, 'reasons': reasons,
            'normalized_seq': seq, 'raw_seq': seq}


class NovelViewTests(unittest.TestCase):
    def test_zero_score_outliers_are_dropped(self):
        novel = pd.DataFrame([
            _row('a', 'outlier', 0.0, 'x1'),          # 점수 0: 제외
            _row('b', 'outlier', 0.04, 'x2'),         # 기준 미만: 제외
            _row('c', 'outlier', 0.05, 'x3'),         # 기준: 포함
            _row('d', 'noise,outlier', 0.0, 'x4'),    # 노이즈: 점수와 무관하게 포함
            _row('e', 'noise', 1.0, 'x5'),
        ])
        ml = SimpleNamespace(novel=novel)
        sc = SimpleNamespace(sessions=pd.DataFrame({'source': ['syd'] * 5, 'session_id': list('abcde')}))
        out = P.novel_view(ml, sc)
        self.assertEqual(sorted(out['session_id']), ['c', 'd', 'e'])

    def test_empty_after_filter(self):
        novel = pd.DataFrame([_row('a', 'outlier', 0.0, 'x1')])
        ml = SimpleNamespace(novel=novel)
        sc = SimpleNamespace(sessions=pd.DataFrame({'source': ['syd'], 'session_id': ['a']}))
        self.assertTrue(P.novel_view(ml, sc).empty)


if __name__ == '__main__':
    unittest.main()
