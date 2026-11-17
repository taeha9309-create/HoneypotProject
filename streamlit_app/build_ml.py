"""대시보드 전용 ML 군집화: 서울+시드니 세션을 합쳐 팀의 ml/cluster.py fit으로 학습한다.

사용법 (build_db.py 다음에):
    python streamlit_app/build_ml.py [--data data/dashboard]

- 입력: data/dashboard/seoul.db, syd.db (build_db.py 결과). 읽기만 한다.
- 결과: data/dashboard/ml.db (sessions·commands 합본 + ml_clusters + ml_points),
        data/dashboard/ml_out/ (session_clusters.csv, cluster_summary.csv, novel_candidates.csv, comparison.csv ...),
        data/dashboard/ml_models/ (프로토콜별 모델)
- 팀원이 만든 ml/out, ml/models, 시드니 DB의 ml_clusters는 건드리지 않는다.
- 군집 번호는 이 실행에서만 의미가 있다(다른 실행의 같은 번호와 합치지 않는다).
"""
import argparse
from collections import defaultdict
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sqlite3
import sys

import numpy as np
from sklearn.decomposition import PCA

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ingest  # noqa: E402
from ml import cluster as ML  # noqa: E402

POINTS = """
CREATE TABLE ml_points (            -- 군집 그림용 2차원 좌표 (고유 정규화 시퀀스 1개 = 점 1개)
    protocol TEXT NOT NULL, point_id TEXT NOT NULL, cluster_id INTEGER NOT NULL,
    x REAL NOT NULL, y REAL NOT NULL, sessions INTEGER NOT NULL, preview TEXT NOT NULL,
    PRIMARY KEY (protocol, point_id));
CREATE TABLE ml_point_members (source TEXT NOT NULL, session_id TEXT NOT NULL, point_id TEXT NOT NULL,
    PRIMARY KEY (source, session_id));
CREATE TABLE ml_meta (key TEXT PRIMARY KEY, value TEXT);
"""


def merge_sources(data_dir, target):
    """seoul.db·syd.db의 sessions/commands를 한 DB로 합친다 (ml/cluster.py가 한 DB를 읽기 때문)."""
    # uri=True로 열어야 ATTACH에서 '?mode=ro'(입력 DB 읽기 전용)가 적용된다
    with closing(sqlite3.connect(Path(target).resolve().as_uri(), uri=True)) as con:
        con.executescript(ingest.SCHEMA)
        n = 0
        for name in ('seoul.db', 'syd.db'):
            path = Path(data_dir) / name
            if not path.exists():
                continue
            con.execute('ATTACH DATABASE ? AS src', (path.resolve().as_uri() + '?mode=ro',))
            con.execute('INSERT OR IGNORE INTO sessions SELECT * FROM src.sessions')
            con.execute('INSERT OR IGNORE INTO commands SELECT * FROM src.commands')
            con.commit()
            con.execute('DETACH DATABASE src')
            n += 1
        return n


def project(con):
    """팀 대시보드(project_clusters.py)와 같은 방식: 정규화 시퀀스 TF-IDF → SVD → L2 → PCA 2차원."""
    sessions = ML.load_sessions(con)
    labels = {(s, i): (p, c) for s, i, p, c in con.execute(
        'SELECT source, session_id, protocol, cluster_id FROM ml_clusters')}
    groups = defaultdict(list)
    for key, s in sessions.items():
        if key not in labels:
            continue
        proto, cid = labels[key]
        groups[(proto, ML.normalize_session(s['cmds']), cid)].append(key)
    points, members = [], []
    for proto in sorted({p for p, _, _ in groups}):
        seqs = sorted({seq for p, seq, _ in groups if p == proto})
        if len(seqs) > 1:
            _, _, _, z = ML.features(seqs)
            n = min(2, z.shape[0], z.shape[1])
            xy = PCA(n_components=n, svd_solver='full').fit_transform(z)
            if n == 1:
                xy = np.column_stack([xy[:, 0], np.zeros(len(xy))])
        else:
            xy = np.zeros((len(seqs), 2))
        where = {seq: v for seq, v in zip(seqs, xy)}
        for (p, seq, cid), keys in groups.items():
            if p != proto:
                continue
            pid = sha256(json.dumps([p, cid, seq], ensure_ascii=True).encode()).hexdigest()[:16]
            points.append((p, pid, int(cid), float(where[seq][0]), float(where[seq][1]), len(keys), ' ; '.join(seq)[:600]))
            members += [(s, i, pid) for s, i in keys]
    con.executescript(POINTS)
    con.executemany('INSERT INTO ml_points VALUES (?,?,?,?,?,?,?)', points)
    con.executemany('INSERT OR IGNORE INTO ml_point_members VALUES (?,?,?)', members)
    con.commit()
    return len(points)


def build(data_dir=ROOT / 'data/dashboard', log=print):
    data_dir = Path(data_dir)
    target, tmp = data_dir / 'ml.db', data_dir / 'ml.db.tmp'
    out_dir, models_dir = data_dir / 'ml_out', data_dir / 'ml_models'
    tmp.unlink(missing_ok=True)
    for d in (out_dir, models_dir):
        shutil.rmtree(d, ignore_errors=True)
    n = merge_sources(data_dir, tmp)
    if not n:
        raise FileNotFoundError(f'{data_dir}에 seoul.db/syd.db가 없습니다. build_db.py를 먼저 실행하세요.')
    with closing(sqlite3.connect(tmp)) as con:
        ML.fit(con, out_dir, models_dir)
        pts = project(con)
        con.executemany('INSERT INTO ml_meta VALUES (?,?)', [
            ('trained_at', con.execute("SELECT max(assigned_at) FROM ml_clusters").fetchone()[0] or ''),
            ('params', con.execute('SELECT DISTINCT params FROM ml_clusters LIMIT 1').fetchone()[0]
             if con.execute('SELECT count(*) FROM ml_clusters').fetchone()[0] else ''),
            ('normalize_version', str(ML.NORMALIZE_VERSION)),
            ('sources', 'seoul+syd')])
        con.commit()
    target.unlink(missing_ok=True)
    shutil.move(str(tmp), str(target))
    log(f'완료: {target} · 그림 점 {pts:,}개 · 결과 CSV {out_dir}')
    return target


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--data', default=str(ROOT / 'data/dashboard'))
    build(p.parse_args().data)


if __name__ == '__main__':
    main()
