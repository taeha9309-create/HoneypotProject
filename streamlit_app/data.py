"""Streamlit 대시보드 데이터 계층 (읽기 전용).

build_db.py가 만든 data/dashboard/ 아래 DB만 읽는다.
- dashboard.db: login_events, file_events, hits, geo, log_hours, sources, meta
- sources 표에 적힌 출처별 DB(seoul.db, syd.db): sessions, commands, failed_commands, downloads

지표 정의는 docs/dashboard-plan-v2.ko.md 4절을 따른다.
- 시각은 UTC로 저장돼 있고 화면·필터는 KST. 기간 = 시작일 00:00 이상, 종료일 다음 날 00:00 미만.
- 세션은 시작 시각, 명령·인증·파일은 각자의 발생 시각, 탐지는 규칙의 최초 일치 시각 기준.
- excluded=1(테스트 접속)은 읽지 않는다.
"""
from collections import Counter, defaultdict
from contextlib import closing
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
import json
from pathlib import Path
import re
import sqlite3
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from explain_signatures import explain_session  # noqa: E402
from log_behavior_export import label_command  # noqa: E402
from session_triage import review_unclassified  # noqa: E402

KST = 'Asia/Seoul'
DEFAULT_DIR = ROOT / 'data/dashboard'
SOURCE_NAMES = {'seoul': '서울', 'syd': '시드니'}

# 우선 확인 행동 (기획서 4절). 쉬운 이름은 화면용.
PRIORITY_RULES = {
    'S01': '다운로드 후 실행', 'S02': '디코딩 후 실행', 'B04': 'SSH 키 심기',
    'B05': '예약 작업 등록', 'B07': '로그 삭제', 'B06': '명령 기록 끄기', 'B15': '방화벽 해제',
}
# 규칙에 안 걸린 입력의 표시용 설명 (session_triage.review_unclassified의 후보 사유)
REVIEW_LABELS = {
    'empty_input': '빈 입력', 'protocol_header_candidate': '프로토콜 탐색 추정',
    'device_cli_entry_candidate': '장비 셸 진입 시도', 'process_cmdline_read_candidate': '프로세스 정보 조회',
    'hostname_read_candidate': '호스트 이름 조회', 'busybox_probe_candidate': 'busybox 확인',
    'other_unmodeled_input': '분류되지 않은 입력',
}

IP_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}(?::\d{1,5})?(?![\d.])")
URL_SCHEME_RE = re.compile(r"\b(https?|ftp|tftp)://", re.I)
DEFANG = {'http': 'hxxp', 'https': 'hxxps', 'ftp': 'fxp', 'tftp': 'txftp'}
SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\||[\r\n]+)\s*")


# ---------------------------------------------------------------- 표시용 가공

def mask_ip(ip):
    """목록용: '221.161.112.140' -> '221.161.x.x'. 상세 화면에서만 전체를 보여 준다."""
    if not isinstance(ip, str) or not ip:
        return '-'
    m = IP_RE.fullmatch(ip)
    return f'{m.group(1)}.{m.group(2)}.x.x' if m else ip[:8] + '…'


def defang(text, limit=None, mask_ips=True):
    """공격자 문자열: URL은 링크가 되지 않게, (목록에서는) IP는 가린다. 제어 문자는 보이게 바꾼다."""
    if text is None or (isinstance(text, float) and pd.isna(text)):
        return ''
    text = URL_SCHEME_RE.sub(lambda m: DEFANG[m.group(1).lower()] + '://', str(text))
    text = text.replace('\x00', '\\x00')
    if mask_ips:
        text = IP_RE.sub(lambda m: f'{m.group(1)}.{m.group(2)}.x.x', text)
    if limit and len(text) > limit:
        text = text[:limit] + '…'
    return text


def short_hash(h):
    return f'{h[:10]}…{h[-6:]}' if isinstance(h, str) and len(h) > 20 else (h or '')


def file_name(url, filename=None):
    if isinstance(url, str) and url:
        tail = url.rstrip('/').rsplit('/', 1)[-1]
        if tail and '://' not in tail and tail not in ('', url):
            return short_hash(tail) if re.fullmatch(r'[0-9a-fA-F]{32,}', tail) else tail
    if isinstance(filename, str) and filename:
        name = Path(filename).name
        return short_hash(name) if re.fullmatch(r'[0-9a-fA-F]{32,}', name) else name
    return '이름 미상'


# ---------------------------------------------------------------- 적재

@dataclass
class Dataset:
    sessions: pd.DataFrame
    commands: pd.DataFrame
    failed: pd.DataFrame
    logins: pd.DataFrame
    files: pd.DataFrame
    hits: pd.DataFrame
    log_hours: pd.DataFrame
    sources: pd.DataFrame
    meta: dict
    rules: list
    warnings: list = field(default_factory=list)

    @property
    def raw_sources(self):
        """원본 로그가 있어 인증·파일 실패·수집 공백을 알 수 있는 출처."""
        return set(self.sources.loc[self.sources['has_raw_logs'] == 1, 'source'])


def _ro(path):
    con = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    con.execute('PRAGMA query_only=ON')
    return con


def _kst(series):
    return pd.to_datetime(series, utc=True, format='ISO8601').dt.tz_convert(KST)


def load(data_dir, rules):
    data_dir = Path(data_dir)
    side = data_dir / 'dashboard.db'
    if not side.exists():
        raise FileNotFoundError(f'{side}가 없습니다. streamlit_app/build_db.py를 먼저 실행하세요.')
    with closing(_ro(side)) as con:
        read = lambda sql: pd.read_sql_query(sql, con)  # noqa: E731
        sources = read('SELECT * FROM sources ORDER BY source')
        logins, files, hits = read('SELECT * FROM login_events'), read('SELECT * FROM file_events'), read('SELECT * FROM hits')
        log_hours, geo = read('SELECT * FROM log_hours'), read('SELECT * FROM geo')
        meta = dict(con.execute('SELECT key, value FROM meta').fetchall())
    frames, warnings = defaultdict(list), []
    for row in sources.itertuples():
        path = data_dir / row.db
        if not path.exists():
            warnings.append(f'{row.source}: {path.name}가 없습니다.')
            continue
        with closing(_ro(path)) as con:
            p = (row.source,)
            live = ('JOIN sessions s ON s.source=t.source AND s.session_id=t.session_id '
                    'WHERE s.excluded=0 AND t.source=?')
            frames['sessions'].append(pd.read_sql_query(
                'SELECT source, session_id, sensor, src_ip, protocol, client_version, start_ts, end_ts, '
                'login_success, username, password, n_commands, n_failed FROM sessions '
                'WHERE excluded=0 AND source=?', con, params=p))
            frames['commands'].append(pd.read_sql_query(
                f'SELECT t.source, t.session_id, t.ts, t.command FROM commands t {live}', con, params=p))
            frames['failed'].append(pd.read_sql_query(
                f'SELECT t.source, t.session_id, t.ts, t.command FROM failed_commands t {live}', con, params=p))
            if row.has_raw_logs == 0:
                # 원본 로그가 없는 출처는 ingest의 downloads(성공 다운로드)만 파일 이벤트로 쓴다
                dl = pd.read_sql_query(f'SELECT t.source, t.session_id, t.ts, t.url, t.shasum FROM downloads t {live}',
                                       con, params=p)
                dl = dl.assign(kind='download', filename=None, error=None)
                frames['files_extra'].append(dl)

    def cat(name, cols):
        return pd.concat(frames[name], ignore_index=True) if frames[name] else pd.DataFrame(columns=cols)

    sessions = cat('sessions', ['source', 'session_id', 'src_ip', 'protocol', 'start_ts', 'end_ts',
                                'login_success', 'username', 'password', 'n_commands'])
    commands = cat('commands', ['source', 'session_id', 'ts', 'command'])
    failed = cat('failed', ['source', 'session_id', 'ts', 'command'])
    if frames['files_extra']:
        files = pd.concat([files] + frames['files_extra'], ignore_index=True)

    sessions['start'] = _kst(sessions['start_ts'])
    sessions['n_commands'] = sessions['n_commands'].fillna(0).astype(int)
    sessions['login_success'] = sessions['login_success'].fillna(0).astype(int)
    country = dict(zip(geo['ip'], geo['country']))
    sessions['country'] = sessions['src_ip'].map(country)
    sessions['ip_masked'] = sessions['src_ip'].map(mask_ip)
    commands['time'] = _kst(commands['ts'])
    failed['time'] = _kst(failed['ts'])
    logins['time'] = _kst(logins['ts'])
    files['time'] = _kst(files['ts'])
    hits['time'] = _kst(hits['first_ts'])
    log_hours['time'] = pd.to_datetime(log_hours['hour'] + ':00:00Z', utc=True).dt.tz_convert(KST)
    for col in ('first_event', 'last_event', 'imported_at'):
        sources[col] = _kst(sources[col])
    if 'inputs' in meta:
        meta['inputs'] = json.loads(meta['inputs'])
    return Dataset(sessions, commands, failed, logins, files, hits, log_hours, sources, meta, rules, warnings)


# ---------------------------------------------------------------- 필터와 범위

@dataclass(frozen=True)
class Filters:
    sources: tuple
    protocols: tuple
    start: date            # KST, 포함
    end: date              # KST, 포함 (내부적으로 다음 날 00:00 미만)
    full_period: bool = False

    @property
    def days(self):
        return (self.end - self.start).days + 1

    def bounds(self):
        lo = pd.Timestamp(self.start, tz=KST)
        return lo, pd.Timestamp(self.end, tz=KST) + pd.Timedelta(days=1)

    def previous(self):
        """같은 길이의 직전 기간."""
        span = timedelta(days=self.days)
        return Filters(self.sources, self.protocols, self.start - span, self.end - span, False)


def data_range(ds):
    return ds.sessions['start'].min().date(), ds.sessions['start'].max().date()


@dataclass
class Scope:
    """필터에 맞는 각 표의 행. 각 표는 자기 발생 시각 기준으로 기간을 자른다."""
    f: Filters
    sessions: pd.DataFrame
    commands: pd.DataFrame
    failed: pd.DataFrame
    logins: pd.DataFrame
    files: pd.DataFrame
    hits: pd.DataFrame
    raw_selected: bool      # 원본 로그가 있는 출처가 하나라도 선택됐는가
    raw_partial: bool       # 원본 로그가 없는 출처도 섞여 있는가


def scope(ds, f):
    lo, hi = f.bounds()
    base = ds.sessions[ds.sessions['source'].isin(f.sources) & ds.sessions['protocol'].isin(f.protocols)]
    keys = pd.MultiIndex.from_frame(base[['source', 'session_id']])

    def cut(df, col='time'):
        if df.empty:
            return df
        in_keys = pd.MultiIndex.from_frame(df[['source', 'session_id']]).isin(keys)
        return df[in_keys & (df[col] >= lo) & (df[col] < hi)]

    sess = base[(base['start'] >= lo) & (base['start'] < hi)]
    raw = ds.raw_sources & set(f.sources)
    return Scope(f, sess, cut(ds.commands), cut(ds.failed), cut(ds.logins), cut(ds.files), cut(ds.hits),
                 bool(raw), bool(raw) and bool(set(f.sources) - ds.raw_sources))


# ---------------------------------------------------------------- 데이터 상태

def source_status(ds, f):
    rows = []
    for r in ds.sources.itertuples():
        if r.source not in f.sources:
            continue
        gaps = None
        if r.has_raw_logs:
            h = ds.log_hours[ds.log_hours['source'] == r.source].set_index('time')['events']
            full = pd.date_range(h.index.min(), h.index.max(), freq='h')
            gaps = int((h.reindex(full, fill_value=0) == 0).sum())
        rows.append({'source': r.source, 'name': SOURCE_NAMES.get(r.source, r.source),
                     'first_event': r.first_event, 'last_event': r.last_event,
                     'imported_at': r.imported_at, 'has_raw_logs': bool(r.has_raw_logs),
                     'empty_hours': gaps, 'note': r.note})
    return rows


# ---------------------------------------------------------------- 핵심 숫자

def _priority_keys(hits):
    p = hits[hits['rule_id'].isin(PRIORITY_RULES)]
    return set(zip(p['source'], p['session_id']))


def kpis(sc):
    lg = sc.logins
    return {
        'sessions': len(sc.sessions),
        'ips': int(sc.sessions['src_ip'].nunique()),
        'auth': len(lg) if sc.raw_selected else None,
        'auth_success': int(lg['success'].sum()) if sc.raw_selected else None,
        'commands': len(sc.commands),
        'command_sessions': int(sc.commands[['source', 'session_id']].drop_duplicates().shape[0]),
        'priority': len(_priority_keys(sc.hits)),
    }


def change(cur, prev):
    if cur is None or prev in (None, 0):
        return None
    return (cur - prev) / prev * 100


def compare(ds, f):
    """직전 같은 길이 기간의 KPI. 전체 기간이거나 직전 기간이 데이터 시작보다 앞이면 None."""
    if f.full_period:
        return None
    pf = f.previous()
    first, _ = data_range(ds)
    if pf.start < first:
        return None
    return kpis(scope(ds, pf))


# ---------------------------------------------------------------- 추이와 분포

def timeline(sc, by='protocol'):
    grain = 'h' if sc.f.days == 1 else 'D'
    s = sc.sessions.assign(bucket=sc.sessions['start'].dt.floor(grain).dt.tz_localize(None))
    out = s.groupby(['bucket', by]).size().rename('sessions').reset_index()
    if by == 'source':
        out['source'] = out['source'].map(lambda x: SOURCE_NAMES.get(x, x))
    return out, grain


def source_split(sc):
    """허니팟(출처)별 세션 수와 비율."""
    vc = sc.sessions['source'].value_counts()
    total = int(vc.sum())
    return pd.DataFrame({'source': vc.index, 'name': [SOURCE_NAMES.get(x, x) for x in vc.index],
                         'sessions': vc.values, 'percent': vc.values / total * 100 if total else 0})


def ip_concentration(sc):
    """세션이 몇몇 IP에 얼마나 몰렸는가: 1위 IP, 2~3위 IP, 나머지의 세션 비율."""
    vc = sc.sessions['src_ip'].value_counts()
    total = int(vc.sum())
    if not total:
        return {'total': 0, 'ips': 0, 'top1': 0.0, 'top3': 0.0, 'top1_ip': None, 'parts': pd.DataFrame()}
    top1, top3 = vc.iloc[0] / total * 100, vc.iloc[:3].sum() / total * 100
    parts = pd.DataFrame({'part': ['1위 IP', '2~3위 IP', f'나머지 {max(len(vc) - 3, 0):,}개 IP'],
                          'percent': [top1, top3 - top1, 100 - top3], 'order': [0, 1, 2]})
    return {'total': total, 'ips': len(vc), 'top1': top1, 'top3': top3, 'top1_ip': vc.index[0], 'parts': parts}


def protocol_split(sc):
    vc = sc.sessions['protocol'].value_counts()
    total = int(vc.sum())
    return pd.DataFrame({'protocol': vc.index, 'sessions': vc.values,
                         'percent': vc.values / total * 100 if total else 0})


def weekday_hour(sc):
    s = sc.sessions
    out = (pd.DataFrame({'weekday': s['start'].dt.weekday, 'hour': s['start'].dt.hour})
           .value_counts().rename('sessions').reset_index())
    out['요일'] = out['weekday'].map(dict(enumerate('월화수목금토일')))
    return out


def countries(sc):
    s = sc.sessions
    g = (s.assign(country=s['country'].fillna('??')).groupby('country')
         .agg(sessions=('session_id', 'size'), ips=('src_ip', 'nunique')).reset_index()
         .sort_values('sessions', ascending=False))
    return g


def map_frames(sc):
    """하루 선택 시 재생용: 시간(0~23)별 누적 국가 세션 수."""
    s = sc.sessions.assign(hour=sc.sessions['start'].dt.hour, country=sc.sessions['country'].fillna('??'))
    return s.groupby(['hour', 'country']).size().rename('sessions').reset_index()


# ---------------------------------------------------------------- 행동

def rule_names(rules):
    return {r['id']: r.get('name', r['id']) for r in rules}


def priority_summary(sc, rules):
    names = rule_names(rules)
    p = sc.hits[sc.hits['rule_id'].isin(PRIORITY_RULES)]
    by_rule = p.groupby('rule_id').size().reindex(list(PRIORITY_RULES), fill_value=0)
    table = pd.DataFrame({'rule_id': by_rule.index, 'label': [PRIORITY_RULES[r] for r in by_rule.index],
                          'rule_name': [names.get(r, r) for r in by_rule.index], 'sessions': by_rule.values})
    recent = (p.sort_values('time', ascending=False).drop_duplicates(['source', 'session_id']).head(5)
              .merge(sc.sessions[['source', 'session_id', 'src_ip', 'ip_masked', 'protocol']],
                     on=['source', 'session_id'], how='left'))
    acts = p.groupby(['source', 'session_id'])['rule_id'].apply(
        lambda ids: ', '.join(PRIORITY_RULES[i] for i in PRIORITY_RULES if i in set(ids)))
    recent['behaviors'] = [acts.get((s, i), '') for s, i in zip(recent['source'], recent['session_id'])]
    return table, recent


# 거의 모든 Telnet 봇 세션에 걸려 순위에서 정보가 없는 규칙. Top N에서 빼고 따로 표시한다.
COMMON_RULES = ('B19',)


def behavior_top(sc, rules, top=5, exclude=()):
    meta = {r['id']: r for r in rules}
    b = sc.hits[sc.hits['rule_id'].map(lambda r: meta.get(r, {}).get('type') == 'behavior')
                & ~sc.hits['rule_id'].isin(exclude)]
    g = b.groupby('rule_id').size().rename('sessions').reset_index().sort_values('sessions', ascending=False)
    pop = sc.commands[['source', 'session_id']].drop_duplicates().shape[0]
    g['label'] = g['rule_id'].map(lambda r: meta[r].get('name', r))
    g['stage'] = g['rule_id'].map(lambda r: meta[r].get('stage', ''))
    g['attack'] = g['rule_id'].map(lambda r: str(meta[r].get('attack', '') or ''))
    g['percent'] = g['sessions'] / pop * 100 if pop else 0.0
    return g.head(top).reset_index(drop=True)


def common_rule_share(sc, rules):
    """COMMON_RULES 각각의 세션 수와 명령 세션 대비 비율 (Top N 아래 안내용)."""
    names = rule_names(rules)
    pop = sc.commands[['source', 'session_id']].drop_duplicates().shape[0]
    out = []
    for rid in COMMON_RULES:
        n = int(sc.hits.loc[sc.hits['rule_id'] == rid, ['source', 'session_id']].drop_duplicates().shape[0])
        out.append({'rule_id': rid, 'name': names.get(rid, rid), 'sessions': n,
                    'percent': n / pop * 100 if pop else 0.0})
    return out


def describe_command(rules, command):
    """명령 한 줄의 표시용 설명과 근거 종류. 탐지 결과(rule_ids)와 분리해서 돌려준다."""
    labels = label_command(rules, command)
    if labels:
        return ', '.join(l['name'] for l in labels), '규칙 일치', [l['rule_id'] for l in labels]
    reasons = review_unclassified([(None, command)])
    text = ', '.join(REVIEW_LABELS.get(r, r) for r in reasons)
    basis = '근거 부족' if reasons == ['other_unmodeled_input'] else '입력 기반 추정'
    return text, basis, []


# ---------------------------------------------------------------- 인증

def auth_summary(sc, top=8):
    lg = sc.logins
    if not sc.raw_selected:
        return None

    def topn(series):
        vc = series.map(lambda v: defang(v, 30, mask_ips=False) or '(빈 값)').value_counts().head(top)
        return pd.DataFrame({'value': vc.index, 'count': vc.values})
    return {'total': len(lg), 'success': int(lg['success'].sum()), 'failed': int((lg['success'] == 0).sum()),
            'users': topn(lg['username']), 'passwords': topn(lg['password']),
            'pairs': topn(lg['username'].fillna('') + ' / ' + lg['password'].fillna('')),
            'failed_users': topn(lg.loc[lg['success'] == 0, 'username'])}


# ---------------------------------------------------------------- 파일

def file_summary(sc):
    fe = sc.files
    ok = fe[fe['kind'].isin(['download', 'upload'])].copy()
    ok['key'] = ok['shasum'].fillna(ok['url'])
    g = (ok.groupby('key').agg(
        kind=('kind', 'first'), url=('url', 'first'), filename=('filename', 'first'), shasum=('shasum', 'first'),
        sessions=('session_id', 'nunique'), events=('session_id', 'size'), first=('time', 'min'), last=('time', 'max'))
        .reset_index().sort_values('last', ascending=False))
    g['name'] = [file_name(u, n) for u, n in zip(g['url'], g['filename'])]
    failed = fe[fe['kind'] == 'download_failed']
    return {'files': g, 'downloads': int((fe['kind'] == 'download').sum()),
            'uploads': int((fe['kind'] == 'upload').sum()), 'failed': len(failed),
            'unique_hashes': int(ok['shasum'].nunique())}


# ---------------------------------------------------------------- IP

def repeat_ips(sc, rules, top=10):
    s = sc.sessions
    g = (s.groupby('src_ip').agg(sessions=('session_id', 'size'),
                                 days=('start', lambda t: t.dt.date.nunique()),
                                 country=('country', 'first'), last=('start', 'max'))
         .reset_index().sort_values('sessions', ascending=False).head(top))
    names = rule_names(rules)
    h = sc.hits.merge(s[['source', 'session_id', 'src_ip']], on=['source', 'session_id'])
    h = h[h['rule_id'] != 'B19']  # 셸 진입 요청은 거의 모든 Telnet 세션에 걸려 대표 행동으로 쓰지 않는다
    top_rule = h.groupby('src_ip')['rule_id'].agg(lambda r: r.value_counts().index[0])
    g['behavior'] = g['src_ip'].map(lambda ip: names.get(top_rule.get(ip), '') if ip in top_rule else '')
    g['ip_masked'] = g['src_ip'].map(mask_ip)
    return g.reset_index(drop=True)


# ---------------------------------------------------------------- 최근 명령과 신규 항목

def recent_commands(sc, rules, limit=20):
    c = sc.commands.sort_values('time', ascending=False).head(limit)
    c = c.merge(sc.sessions[['source', 'session_id', 'src_ip', 'ip_masked', 'protocol']],
                on=['source', 'session_id'], how='left')
    desc = [describe_command(rules, x) for x in c['command']]
    c['behavior'] = [d[0] for d in desc]
    c['basis'] = [d[1] for d in desc]
    c['rules'] = [', '.join(d[2]) for d in desc]
    c['command_view'] = c['command'].map(lambda x: defang(x, 120))
    return c.reset_index(drop=True)


def new_items(ds, sc):
    """전체 기간: 누적 고유 항목 수. 기간 선택: 조회 시작 이전(선택 출처의 보유 데이터)에 없던 항목 수."""
    f = sc.f
    lo, _ = f.bounds()
    srcs = set(f.sources)
    s = ds.sessions[ds.sessions['source'].isin(srcs)]
    c = ds.commands[ds.commands['source'].isin(srcs)]
    fe = ds.files[ds.files['source'].isin(srcs) & ds.files['shasum'].notna()]
    cur_ip = set(sc.sessions['src_ip'].dropna())
    cur_cmd = set(sc.commands['command'])
    cur_hash = set(sc.files['shasum'].dropna())
    if f.full_period:
        return {'mode': '누적', 'ips': len(cur_ip), 'commands': len(cur_cmd), 'hashes': len(cur_hash)}
    old_ip = set(s.loc[s['start'] < lo, 'src_ip'].dropna())
    old_cmd = set(c.loc[c['time'] < lo, 'command'])
    old_hash = set(fe.loc[fe['time'] < lo, 'shasum'])
    return {'mode': '신규', 'ips': len(cur_ip - old_ip), 'commands': len(cur_cmd - old_cmd),
            'hashes': len(cur_hash - old_hash)}


# ---------------------------------------------------------------- 상세

def ip_detail(ds, ip):
    s = ds.sessions[ds.sessions['src_ip'] == ip].sort_values('start')
    if s.empty:
        return None
    keys = pd.MultiIndex.from_frame(s[['source', 'session_id']])

    def own(df):
        return df[pd.MultiIndex.from_frame(df[['source', 'session_id']]).isin(keys)] if not df.empty else df
    names = rule_names(ds.rules)
    hits = own(ds.hits)
    behaviors = (hits.groupby('rule_id')['session_id'].nunique().sort_values(ascending=False)
                 .rename('sessions').reset_index())
    behaviors['name'] = behaviors['rule_id'].map(names)
    logins = own(ds.logins)
    return {'sessions': s, 'country': s['country'].dropna().iloc[0] if s['country'].notna().any() else None,
            'first': s['start'].min(), 'last': s['start'].max(),
            'days': s['start'].dt.date.nunique(), 'sources': sorted(s['source'].unique()),
            'protocols': sorted(s['protocol'].dropna().unique()), 'behaviors': behaviors,
            'logins': logins, 'files': own(ds.files),
            'raw_known': bool(set(s['source']) & ds.raw_sources)}


def session_detail(ds, source, session_id):
    key = (ds.sessions['source'] == source) & (ds.sessions['session_id'] == session_id)
    if not key.any():
        return None
    meta = ds.sessions[key].iloc[0]

    def own(df):
        return df[(df['source'] == source) & (df['session_id'] == session_id)].sort_values('time')
    cmds = own(ds.commands)
    rows = list(zip(cmds['ts'], cmds['command']))
    desc = [describe_command(ds.rules, c) for c in cmds['command']]
    timeline = pd.DataFrame({'#': range(len(cmds)), '시각(KST)': cmds['time'].dt.strftime('%m-%d %H:%M:%S').values,
                             '명령': [defang(c, mask_ips=False) for c in cmds['command']],
                             '행동 설명': [d[0] for d in desc], '근거': [d[1] for d in desc],
                             '탐지 규칙': [', '.join(d[2]) for d in desc]})
    names = rule_names(ds.rules)
    hits = own(ds.hits).assign(name=lambda d: d['rule_id'].map(names))
    evidence = explain_session(ds.rules, rows)['matches'] if rows else []
    return {'meta': meta, 'timeline': timeline, 'commands': cmds['command'].tolist(), 'hits': hits,
            'evidence': evidence, 'logins': own(ds.logins), 'failed': own(ds.failed),
            'files': own(ds.files), 'raw_known': source in ds.raw_sources}


# ---------------------------------------------------------------- 세션 조사 페이지

FILE_KINDS = {'download': '다운로드', 'download_failed': '다운로드 실패', 'upload': '업로드'}


def session_list(sc, rules, ip_query='', priority_only=False, commands_only=False, rule_ids=(), login=None):
    """조사용 세션 목록. 사이드바 범위(sc) 안에서 페이지 필터를 더 건다."""
    s = sc.sessions
    hit_ids = sc.hits.groupby(['source', 'session_id'])['rule_id'].agg(lambda r: sorted(set(r)))
    keys = list(zip(s['source'], s['session_id']))
    rules_of = [hit_ids.get(k, []) for k in keys]
    out = s.assign(rule_list=rules_of)
    out['priority'] = out['rule_list'].map(lambda r: any(x in PRIORITY_RULES for x in r))
    if ip_query:
        out = out[out['src_ip'].fillna('').str.contains(ip_query.strip(), regex=False)]
    if priority_only:
        out = out[out['priority']]
    if commands_only:
        out = out[out['n_commands'] > 0]
    if rule_ids:
        want = set(rule_ids)
        out = out[out['rule_list'].map(lambda r: bool(want & set(r)))]
    if login is not None:
        out = out[out['login_success'] == int(login)]
    out = out.sort_values('start', ascending=False)
    out['rules'] = out['rule_list'].map(lambda r: ', '.join(r))
    out['behaviors'] = out['rule_list'].map(
        lambda r: ', '.join(PRIORITY_RULES[x] for x in PRIORITY_RULES if x in r))
    return out.reset_index(drop=True)


def session_events(ds, source, session_id):
    """한 세션의 인증·명령·실패 조각·파일 이벤트를 시간순으로 합친 타임라인."""
    def own(df):
        return df[(df['source'] == source) & (df['session_id'] == session_id)]
    parts = []
    lg = own(ds.logins)
    if not lg.empty:
        parts.append(pd.DataFrame({'time': lg['time'], 'order': 0,
                                   'kind': lg['success'].map({1: '인증 성공', 0: '인증 실패'}),
                                   'detail': [f'{defang(u, 40, False)} / {defang(p, 40, False)}'
                                              for u, p in zip(lg['username'], lg['password'])],
                                   'index': ''}))
    cmds = own(ds.commands).sort_values('ts')
    if not cmds.empty:
        parts.append(pd.DataFrame({'time': cmds['time'].reset_index(drop=True), 'order': 1, 'kind': '명령',
                                   'detail': [defang(c, mask_ips=False) for c in cmds['command']],
                                   'index': [f'#{i}' for i in range(len(cmds))]}))
    fl = own(ds.failed)
    if not fl.empty:
        parts.append(pd.DataFrame({'time': fl['time'], 'order': 2, 'kind': '실행 실패 조각',
                                   'detail': fl['command'].map(lambda x: defang(x, mask_ips=False)), 'index': ''}))
    fe = own(ds.files)
    if not fe.empty:
        parts.append(pd.DataFrame({'time': fe['time'], 'order': 3, 'kind': fe['kind'].map(FILE_KINDS),
                                   'detail': [f"{defang(u, mask_ips=False) or '(URL 없음)'}"
                                              + (f'  sha256:{short_hash(h)}' if isinstance(h, str) and h else '')
                                              + (f'  ({defang(e, 60, False)})' if isinstance(e, str) and e else '')
                                              for u, h, e in zip(fe['url'], fe['shasum'], fe['error'])],
                                   'index': ''}))
    if not parts:
        return pd.DataFrame(columns=['time', 'kind', 'detail', 'index'])
    ev = pd.concat(parts, ignore_index=True).sort_values(['time', 'order'], kind='stable')
    return ev.drop(columns='order').reset_index(drop=True)


def ip_list(sc, ip_query=''):
    s = sc.sessions
    if ip_query:
        s = s[s['src_ip'].fillna('').str.contains(ip_query.strip(), regex=False)]
    g = (s.groupby('src_ip').agg(sessions=('session_id', 'size'), days=('start', lambda t: t.dt.date.nunique()),
                                 first=('start', 'min'), last=('start', 'max'), country=('country', 'first'),
                                 sources=('source', lambda x: ', '.join(SOURCE_NAMES.get(v, v) for v in sorted(set(x)))),
                                 logins=('login_success', 'sum'), commands=('n_commands', 'sum'))
         .reset_index().sort_values('sessions', ascending=False))
    return g.reset_index(drop=True)


def ip_daily(ds, ip):
    s = ds.sessions[ds.sessions['src_ip'] == ip]
    out = (s.assign(day=s['start'].dt.floor('D').dt.tz_localize(None), source=s['source'].map(lambda x: SOURCE_NAMES.get(x, x)))
           .groupby(['day', 'source']).size().rename('sessions').reset_index())
    return out


def file_catalog(sc):
    """수집 파일 목록 (해시 기준, 해시가 없으면 URL 기준). 실물 보관 여부는 DB에 정보가 없어 '미확인'."""
    fe = sc.files[sc.files['kind'].isin(['download', 'upload'])].copy()
    if fe.empty:
        return pd.DataFrame(columns=['key', 'name', 'kinds', 'shasum', 'urls', 'sessions', 'ips', 'first', 'last'])
    fe['key'] = fe['shasum'].fillna(fe['url'])
    ips = sc.sessions.set_index(['source', 'session_id'])['src_ip']
    fe['ip'] = [ips.get(k) for k in zip(fe['source'], fe['session_id'])]
    g = (fe.groupby('key').agg(
        kinds=('kind', lambda k: ', '.join(FILE_KINDS[x] for x in sorted(set(k)))), shasum=('shasum', 'first'),
        url=('url', 'first'), urls=('url', lambda u: len(set(u.dropna()))), filename=('filename', 'first'),
        sessions=('session_id', 'nunique'), ips=('ip', 'nunique'), first=('time', 'min'), last=('time', 'max'))
        .reset_index().sort_values('last', ascending=False))
    g['name'] = [file_name(u, n) for u, n in zip(g['url'], g['filename'])]
    return g.reset_index(drop=True)


def file_observations(sc, key):
    fe = sc.files[(sc.files['shasum'] == key) | (sc.files['shasum'].isna() & (sc.files['url'] == key))]
    return fe.merge(sc.sessions[['source', 'session_id', 'src_ip', 'protocol']], on=['source', 'session_id'],
                    how='left').sort_values('time', ascending=False).reset_index(drop=True)


def failed_downloads(sc):
    fe = sc.files[sc.files['kind'] == 'download_failed']
    fe = fe.merge(sc.sessions[['source', 'session_id', 'src_ip']], on=['source', 'session_id'], how='left')
    return fe.sort_values('time', ascending=False).reset_index(drop=True)
