"""패턴 분석(ML) 페이지용 데이터. build_ml.py 결과(ml.db, ml_out/*.csv)를 읽는다.

군집 이름은 사람이 붙이기 전까지 자동으로 만든다:
  표식(busybox 뒤 대문자 이름, hostname 값, 숨김 파일명, 다운로드 도구) + 군집 세션 절반 이상에서 관측된 공격 단계.
번호는 이 학습 실행에서만 의미가 있으며 다른 실행(팀원 결과 등)의 번호와 합치지 않는다.
"""
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3

import pandas as pd

import data as D
import detect as X
import story as S

BUSYBOX_RE = re.compile(r'busybox\s+([A-Z][A-Z0-9]{2,})\b')
HOSTNAME_RE = re.compile(r'hostname\s+([A-Za-z0-9_-]{3,})')
HIDDEN_FILE_RE = re.compile(r'/(\.[A-Za-z0-9_]{1,10})\b|>\s*(\.[A-Za-z0-9_]{1,10})\b')
NOISE_NAME = '노이즈 (어느 군집에도 안 맞음)'


@dataclass
class MLData:
    clusters: pd.DataFrame      # source, session_id, protocol, cluster_id, is_noise, outlier_score
    points: pd.DataFrame        # protocol, point_id, cluster_id, x, y, sessions, preview
    members: pd.DataFrame       # source, session_id, point_id
    summary: pd.DataFrame       # cluster_summary.csv
    novel: pd.DataFrame         # novel_candidates.csv
    meta: dict


def load(data_dir):
    data_dir = Path(data_dir)
    db = data_dir / 'ml.db'
    if not db.exists():
        return None
    with closing(sqlite3.connect(db.resolve().as_uri() + '?mode=ro', uri=True)) as con:
        read = lambda q: pd.read_sql_query(q, con)  # noqa: E731
        clusters = read('SELECT source, session_id, protocol, cluster_id, is_noise, outlier_score FROM ml_clusters')
        points, members = read('SELECT * FROM ml_points'), read('SELECT * FROM ml_point_members')
        meta = dict(con.execute('SELECT key, value FROM ml_meta').fetchall())
    out = data_dir / 'ml_out'
    summary = pd.read_csv(out / 'cluster_summary.csv', encoding='utf-8-sig') if (out / 'cluster_summary.csv').exists() \
        else pd.DataFrame()
    novel = pd.read_csv(out / 'novel_candidates.csv', encoding='utf-8-sig') if (out / 'novel_candidates.csv').exists() \
        else pd.DataFrame()
    return MLData(clusters, points, members, summary, novel, meta)


def markers(text):
    """대표 시퀀스에서 사람이 알아보기 쉬운 표식을 뽑는다."""
    found = []
    found += [f'busybox {m}' for m in dict.fromkeys(BUSYBOX_RE.findall(text or ''))][:2]
    found += [f'hostname {m}' for m in dict.fromkeys(HOSTNAME_RE.findall(text or ''))][:1]
    files = [a or b for a, b in HIDDEN_FILE_RE.findall(text or '')]
    found += [f'{m} 파일' for m in list(dict.fromkeys(files))[:2]]
    low = (text or '').lower()
    tools = [t for t in ('wget', 'curl', 'tftp', 'ftpget') if t in low]
    if tools:
        found.append('/'.join(tools) + ' 다운로드')
    if 'kill -9' in low:
        found.append('프로세스 종료')
    return found


def cluster_table(ml, ds, sc, rules):
    """조회 범위 안의 군집별 집계 + 자동 이름. (protocol, cluster_id) 단위."""
    c = ml.clusters.merge(sc.sessions[['source', 'session_id', 'src_ip', 'start']], on=['source', 'session_id'])
    if c.empty:
        return pd.DataFrame()
    hits = sc.hits.merge(c[['source', 'session_id', 'protocol', 'cluster_id']], on=['source', 'session_id'])
    rows = []
    summ = ml.summary.set_index(['protocol', 'cluster_id']) if not ml.summary.empty else None
    for (proto, cid), g in c.groupby(['protocol', 'cluster_id']):
        n = len(g)
        h = hits[(hits['protocol'] == proto) & (hits['cluster_id'] == cid)]
        share = (h.drop_duplicates(['source', 'session_id', 'rule_id']).groupby('rule_id').size() / n).sort_values(ascending=False)
        common = [r for r, v in share.items() if v >= 0.5 and r != 'B19']
        steps = sorted({X.rule_step(rules, r) for r in common}, key=lambda k: list(S.STEPS).index(k))
        top_danger = max((X.DANGER.get(r, 0) for r in common), default=0)
        rep = summ.loc[(proto, cid), 'representative'] if summ is not None and (proto, cid) in summ.index else ''
        mk = markers(rep)
        if cid == -1:
            name = NOISE_NAME
        else:
            parts = [', '.join(mk[:2])] if mk else []
            parts.append(' → '.join(S.STEPS[k][0] for k in steps[:3]) if steps else '명령창 열기·탐색')
            name = ' · '.join(p for p in parts if p)
            if not mk and not steps:   # 표식·단계가 없으면 대표 명령 앞부분으로 구분한다
                head = ' → '.join(dict.fromkeys(x.strip() for x in (rep or '').split(' ; ') if x.strip()))
                name += f' ({head[:40]}{"…" if len(head) > 40 else ""})' if head else ''
        by_src = g['source'].value_counts()
        rows.append({'protocol': proto, 'cluster_id': int(cid), 'name': name, 'sessions': n,
                     'ips': int(g['src_ip'].nunique()), 'seoul': int(by_src.get('seoul', 0)), 'syd': int(by_src.get('syd', 0)),
                     'first': g['start'].min(), 'last': g['start'].max(), 'days': int(g['start'].dt.date.nunique()),
                     'top_ip_share': g['src_ip'].value_counts(normalize=True).iloc[0] * 100,
                     'danger': top_danger, 'common_rules': common, 'representative': rep,
                     'top_commands': summ.loc[(proto, cid), 'top_commands'] if summ is not None and (proto, cid) in summ.index else '',
                     'rep_share': float(summ.loc[(proto, cid), 'rep_share']) if summ is not None and (proto, cid) in summ.index else None})
    out = pd.DataFrame(rows)
    out['key'] = out['protocol'] + ':' + out['cluster_id'].astype(str)
    out['label'] = out.apply(lambda r: f"{r['protocol'].upper()} {r['cluster_id']}" if r['cluster_id'] >= 0
                             else f"{r['protocol'].upper()} 노이즈", axis=1)
    out['order'] = out['cluster_id'].map(lambda x: 10 ** 6 if x == -1 else 0) - out['sessions']
    return out.sort_values(['protocol', 'order']).drop(columns='order').reset_index(drop=True)


def cluster_daily(ml, sc, proto, cid):
    c = ml.clusters[(ml.clusters['protocol'] == proto) & (ml.clusters['cluster_id'] == cid)]
    s = sc.sessions.merge(c[['source', 'session_id']], on=['source', 'session_id'])
    s = s.assign(day=s['start'].dt.floor('D').dt.tz_localize(None), name=s['source'].map(lambda x: D.SOURCE_NAMES.get(x, x)))
    return s.groupby(['day', 'name']).size().rename('sessions').reset_index()


def cluster_rules(ml, sc, rules, proto, cid):
    c = ml.clusters[(ml.clusters['protocol'] == proto) & (ml.clusters['cluster_id'] == cid)]
    keys = sc.sessions.merge(c[['source', 'session_id']], on=['source', 'session_id'])[['source', 'session_id']]
    n = len(keys)
    h = sc.hits.merge(keys, on=['source', 'session_id']).drop_duplicates(['source', 'session_id', 'rule_id'])
    meta = {r['id']: r for r in rules}
    g = h.groupby('rule_id').size().rename('sessions').reset_index()
    g = g[g['rule_id'].map(lambda r: meta.get(r, {}).get('type') == 'behavior')]
    g['percent'] = g['sessions'] / max(n, 1) * 100
    g['plain'] = g['rule_id'].map(lambda r: S.PLAIN.get(r, meta[r].get('name', r)))
    g['danger'] = g['rule_id'].map(lambda r: X.DANGER.get(r, 1))
    return g.sort_values(['danger', 'percent'], ascending=False).reset_index(drop=True)


def cluster_sessions(ml, sc, proto, cid):
    c = ml.clusters[(ml.clusters['protocol'] == proto) & (ml.clusters['cluster_id'] == cid)]
    s = sc.sessions.merge(c[['source', 'session_id', 'outlier_score']], on=['source', 'session_id'])
    return s.sort_values('start', ascending=False).reset_index(drop=True)


def cluster_servers(ds, sc, ml, proto, cid):
    """이 군집 세션이 파일을 가져오려던 서버 (위협 정보와 연결)."""
    import intel as I
    c = ml.clusters[(ml.clusters['protocol'] == proto) & (ml.clusters['cluster_id'] == cid)]
    keys = pd.MultiIndex.from_frame(c[['source', 'session_id']])
    sub = D.Scope(sc.f, sc.sessions[pd.MultiIndex.from_frame(sc.sessions[['source', 'session_id']]).isin(keys)],
                  sc.commands[pd.MultiIndex.from_frame(sc.commands[['source', 'session_id']]).isin(keys)],
                  sc.failed, sc.logins, sc.files[pd.MultiIndex.from_frame(sc.files[['source', 'session_id']]).isin(keys)]
                  if len(sc.files) else sc.files, sc.hits, sc.raw_selected, sc.raw_partial)
    sv = I.download_servers(ds, sub)
    return sv[sv['kind'] != '루프백(무시)'] if len(sv) else sv


def points_in_scope(ml, sc):
    """조회 범위 안의 세션 수로 점 크기를 다시 센다."""
    m = ml.members.merge(sc.sessions[['source', 'session_id']], on=['source', 'session_id'])
    cnt = m.groupby('point_id').size()
    p = ml.points.copy()
    p['in_scope'] = p['point_id'].map(cnt).fillna(0).astype(int)
    return p[p['in_scope'] > 0].reset_index(drop=True)


NOVEL_MIN_OUTLIER = 0.05   # 이 점수 미만이면서 노이즈도 아닌 행은 후보에서 뺀다 (아래 설명)


def novel_view(ml, sc):
    n = ml.novel
    if n.empty:
        return n
    # novel_candidates.csv는 큰 군집의 "상위 5%" 경계가 0 근처가 되어 점수 0인 세션까지 outlier로 담는다.
    # 노이즈이거나 이상 점수가 기준 이상인 행만 남긴다 (팀원 전달 문서 7장 기준).
    is_noise = n['reasons'].fillna('').str.contains('noise')
    n = n[is_noise | (pd.to_numeric(n['outlier_score'], errors='coerce').fillna(0) >= NOVEL_MIN_OUTLIER)]
    if n.empty:
        return n
    keys = pd.MultiIndex.from_frame(sc.sessions[['source', 'session_id']])
    n = n[pd.MultiIndex.from_frame(n[['source', 'session_id']]).isin(keys)]
    if n.empty:
        return n
    g = (n.groupby(['protocol', 'normalized_seq'], sort=False)
         .agg(sessions=('n_sessions', 'max'), cluster=('cluster_id', 'first'), outlier=('outlier_score', 'max'),
              reasons=('reasons', 'first'), downloaded=('downloaded', 'max'), ip=('src_ip', 'first'),
              first=('start_ts', 'min'), source=('source', 'first'), session_id=('session_id', 'first'))
         .reset_index().sort_values('outlier', ascending=False).reset_index(drop=True))
    g['first'] = pd.to_datetime(g['first'], utc=True, format='ISO8601').dt.tz_convert(D.KST)
    return g
