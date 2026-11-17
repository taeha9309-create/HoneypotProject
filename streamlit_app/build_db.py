"""대시보드용 DB를 만든다. 원본 로그와 기존 DB는 읽기만 한다.

사용법 (저장소 루트에서):
    python streamlit_app/build_db.py \
        --seoul-logs D:/HoneyPot/cowrie-seoul-logs \
        --syd-db data/syd_20261109/honeypot.db \
        --geo work/geo/dbip-country-ipv4.csv

결과 (기본 data/dashboard/, git에 올리지 않음):
    seoul.db      서울 원본 로그를 ingest.py로 새로 적재한 DB (source=seoul)
    syd.db        시드니 DB 사본 (sqlite backup)
    dashboard.db  대시보드 보조 자료
        login_events   원본 로그의 인증 성공·실패 (세션·시간·IP가 맞는 것만)
        file_events    다운로드 성공·실패, 업로드 (원본 로그 기준)
        hits           현재 rules.yaml로 다시 계산한 탐지 결과
        geo            IP → 국가 (DB-IP Country Lite, 오프라인)
        log_hours      원본 로그의 시간별 이벤트 수 (수집 공백 확인용)
        sources        출처별 자료 범위와 원본 로그 보유 여부
        meta           생성 시각, 규칙 파일 해시·커밋, 입력 경로

원본 로그가 없는 출처(시드니 사본)는 login_events·file_events·log_hours가 '미수집'이다.
대시보드는 이를 0건과 구분해서 보여 준다.
"""
import argparse
from bisect import bisect_right
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ingest  # noqa: E402
from match_signatures import iter_sessions, load_rules, match  # noqa: E402

SCHEMA = """
CREATE TABLE login_events (
    source TEXT NOT NULL, session_id TEXT NOT NULL, ts TEXT NOT NULL,
    success INTEGER NOT NULL, username TEXT, password TEXT,
    PRIMARY KEY (source, session_id, ts, success, username, password));
CREATE TABLE file_events (
    source TEXT NOT NULL, session_id TEXT NOT NULL, ts TEXT NOT NULL,
    kind TEXT NOT NULL,           -- download / download_failed / upload
    url TEXT, shasum TEXT, filename TEXT, error TEXT,
    UNIQUE (source, session_id, ts, kind, url, shasum));
CREATE TABLE hits (
    source TEXT NOT NULL, session_id TEXT NOT NULL, rule_id TEXT NOT NULL,
    first_ts TEXT NOT NULL, n_hits INTEGER NOT NULL,
    PRIMARY KEY (source, session_id, rule_id));
CREATE TABLE geo (ip TEXT PRIMARY KEY, country TEXT);
CREATE TABLE log_hours (source TEXT NOT NULL, hour TEXT NOT NULL, events INTEGER NOT NULL,
    PRIMARY KEY (source, hour));
CREATE TABLE sources (
    source TEXT PRIMARY KEY, db TEXT NOT NULL, has_raw_logs INTEGER NOT NULL,
    first_event TEXT, last_event TEXT, imported_at TEXT NOT NULL, note TEXT);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
"""


def utc(ts):
    """ISO 문자열 → UTC datetime. 시간대가 없거나 잘못되면 None."""
    try:
        value = datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None
    return value.astimezone(timezone.utc) if value.tzinfo else None


def iso(value):
    return value.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def ro(path):
    con = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    con.execute('PRAGMA query_only=ON')
    return con


def ingest_logs(logs, db, source):
    """기존 ingest.py를 그대로 실행한다 (테스트 IP 제외 규칙 포함)."""
    cmd = [sys.executable, str(ROOT / 'ingest.py'), str(logs), '--db', str(db), '--source', source]
    subprocess.run(cmd, check=True, cwd=ROOT)


def copy_db(src, dst):
    with closing(ro(src)) as a, closing(sqlite3.connect(dst)) as b:
        a.backup(b)


def scan_raw_logs(logs, db, source):
    """원본 로그에서 인증·파일 이벤트와 시간별 이벤트 수를 읽는다.

    import_auth.py와 같은 기준: DB에 있는 excluded=0 세션이고, 이벤트 시각이 세션 시작~끝 안이며,
    src_ip가 있으면 세션의 IP와 같아야 한다.
    """
    with closing(ro(db)) as con:
        sessions = {sid: (ip, utc(start), utc(end)) for sid, ip, start, end in con.execute(
            'SELECT session_id, src_ip, start_ts, end_ts FROM sessions WHERE source=? AND excluded=0', (source,))}
    logins, files, hours = set(), set(), Counter()
    first = last = None
    skipped = Counter()
    for path in ingest.iter_files([logs]):
        for e in ingest.iter_events(path):
            ts = utc(e.get('timestamp'))
            if ts is None:
                skipped['bad_ts'] += 1
                continue
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
            hours[ts.strftime('%Y-%m-%dT%H')] += 1
            eid = e.get('eventid') or ''
            if not (eid.startswith('cowrie.login.') or eid.startswith('cowrie.session.file_')):
                continue
            sid = e.get('session')
            if sid not in sessions:
                skipped['unknown_or_excluded_session'] += 1
                continue
            ip, start, end = sessions[sid]
            if start is None or end is None or not start <= ts <= end:
                skipped['outside_session'] += 1
                continue
            if e.get('src_ip') and ip and e['src_ip'] != ip:
                skipped['ip_mismatch'] += 1
                continue
            if eid in ('cowrie.login.success', 'cowrie.login.failed'):
                logins.add((source, sid, iso(ts), int(eid.endswith('success')),
                            str(e.get('username') if e.get('username') is not None else ''),
                            str(e.get('password') if e.get('password') is not None else '')))
            elif eid in ('cowrie.session.file_download', 'cowrie.session.file_download.failed',
                         'cowrie.session.file_upload'):
                kind = {'cowrie.session.file_download': 'download',
                        'cowrie.session.file_download.failed': 'download_failed',
                        'cowrie.session.file_upload': 'upload'}[eid]
                files.add((source, sid, iso(ts), kind, e.get('url'), e.get('shasum'),
                           e.get('filename') or e.get('outfile'), e.get('error') or e.get('message')))
    return logins, files, hours, first, last, skipped


def compute_hits(db, rules):
    rows = []
    with closing(ro(db)) as con:
        for (source, sid), cmds in iter_sessions(con):
            for rid, (ts, n) in match(rules, cmds).items():
                rows.append((source, sid, rid, ts, n))
    return rows


def load_geo_ranges(csv_path):
    starts, ranges = [], []
    with open(csv_path, encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) != 3:
                continue
            a, b, country = parts
            try:
                ranges.append((int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b)), country))
            except ValueError:
                continue
    ranges.sort()
    starts = [r[0] for r in ranges]
    return starts, ranges


def lookup(starts, ranges, ip):
    try:
        address = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return None
    if address.version != 4 or not address.is_global:
        return None
    i = bisect_right(starts, int(address)) - 1
    if i >= 0 and int(address) <= ranges[i][1]:
        return ranges[i][2]
    return None


def git_commit(path):
    try:
        out = subprocess.run(['git', 'log', '-1', '--format=%h %cs', '--', str(path)], cwd=ROOT,
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ''


def build(out, seoul_logs=None, syd_db=None, geo_csv=None, rules_path=ROOT / 'signatures/rules.yaml',
          log=print):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    target = out / 'dashboard.db'
    tmp = out / 'dashboard.db.tmp'
    tmp.unlink(missing_ok=True)
    rules = load_rules(rules_path)
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    with closing(sqlite3.connect(tmp)) as con:
        con.executescript(SCHEMA)
        meta = {'built_at': now, 'rules_sha256': sha256(Path(rules_path).read_bytes()).hexdigest(),
                'rules_commit': git_commit(rules_path), 'geo_provider': '', 'inputs': {}}
        sources = []

        if seoul_logs:
            db = out / 'seoul.db'
            db.unlink(missing_ok=True)  # 매번 원본 로그에서 새로 만든다
            log(f'[seoul] ingest {seoul_logs} -> {db}')
            ingest_logs(seoul_logs, db, 'seoul')
            logins, files, hours, first, last, skipped = scan_raw_logs(seoul_logs, db, 'seoul')
            con.executemany('INSERT OR IGNORE INTO login_events VALUES (?,?,?,?,?,?)', sorted(logins))
            con.executemany('INSERT OR IGNORE INTO file_events VALUES (?,?,?,?,?,?,?,?)', sorted(files, key=str))
            con.executemany('INSERT INTO log_hours VALUES (?,?,?)',
                            [('seoul', h, n) for h, n in sorted(hours.items())])
            log(f'[seoul] 인증 {len(logins):,} / 파일 {len(files):,} / 제외 {dict(skipped)}')
            sources.append(('seoul', db.name, 1, iso(first) if first else None, iso(last) if last else None,
                            now, f'원본 로그 {seoul_logs}'))
            meta['inputs']['seoul'] = str(seoul_logs)

        if syd_db:
            db = out / 'syd.db'
            db.unlink(missing_ok=True)
            log(f'[syd] copy {syd_db} -> {db}')
            copy_db(syd_db, db)
            with closing(ro(db)) as c:
                first, last = c.execute('SELECT min(start_ts), max(coalesce(end_ts, start_ts)) FROM sessions '
                                        "WHERE source='syd'").fetchone()
            sources.append(('syd', db.name, 0, first, last, now,
                            f'팀원 전달 DB 사본 {syd_db}. 원본 로그 없음: 인증 실패·파일 실패·수집 공백은 미수집'))
            meta['inputs']['syd'] = str(syd_db)

        con.executemany('INSERT INTO sources VALUES (?,?,?,?,?,?,?)', sources)

        ips = set()
        for source, name, *_ in sources:
            log(f'[{source}] 탐지 규칙 재계산')
            con.executemany('INSERT OR REPLACE INTO hits VALUES (?,?,?,?,?)', compute_hits(out / name, rules))
            with closing(ro(out / name)) as c:
                ips |= {r[0] for r in c.execute('SELECT DISTINCT src_ip FROM sessions WHERE src_ip IS NOT NULL')}

        if geo_csv:
            starts, ranges = load_geo_ranges(geo_csv)
            con.executemany('INSERT INTO geo VALUES (?,?)', [(ip, lookup(starts, ranges, ip)) for ip in sorted(ips)])
            meta['geo_provider'] = 'DB-IP IP to Country Lite (CC BY 4.0), via sapics/ip-location-db'
            meta['inputs']['geo'] = str(geo_csv)
            log(f'[geo] IP {len(ips):,}개 조회')

        con.executemany('INSERT INTO meta VALUES (?,?)',
                        [(k, json.dumps(v, ensure_ascii=False) if isinstance(v, dict) else v) for k, v in meta.items()])
        con.commit()
    target.unlink(missing_ok=True)
    shutil.move(str(tmp), str(target))
    log(f'완료: {target}')
    return target


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--seoul-logs', help='서울 Cowrie JSON 로그 폴더')
    p.add_argument('--syd-db', help='시드니 DB 사본 (읽기만 함)')
    p.add_argument('--geo', help='DB-IP country IPv4 CSV (first,last,country)')
    p.add_argument('--rules', default=str(ROOT / 'signatures/rules.yaml'))
    p.add_argument('--out', default=str(ROOT / 'data/dashboard'))
    a = p.parse_args()
    if not (a.seoul_logs or a.syd_db):
        p.error('--seoul-logs 또는 --syd-db 중 하나는 필요합니다')
    build(a.out, a.seoul_logs, a.syd_db, a.geo, a.rules)


if __name__ == '__main__':
    main()
