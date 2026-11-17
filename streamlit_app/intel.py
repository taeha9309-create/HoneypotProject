"""위협 정보(IOC)와 변화 브리핑: 허니팟에서 얻은 정보를 실제 방어에 옮겨 쓰기 위한 집계.

- 차단 후보 IP: 위험 행동·다운로드 시도·무차별 대입·반복 접속 등 이유가 하나라도 있는 출발지 IP.
- 다운로드 서버: 명령 안의 URL과 tftp/ftpget 대상, Cowrie 파일 이벤트의 URL에서 뽑은 호스트.
- 파일 해시: 실제로 받아진(또는 올라온) 파일의 SHA-256.
- 공격 계정: 인증 이벤트의 아이디·비밀번호 (비밀번호 금지 목록·계정 점검용).
모든 수치는 '입력 관측'이며 악성 확정이 아니다. 차단 전 사람이 검토한다.
"""
from collections import defaultdict
import ipaddress
import re

import pandas as pd

import data as D
import detect as X

URL_RE = re.compile(r"\b((?:https?|ftp|tftp))://([A-Za-z0-9.\-]+)(?::(\d{1,5}))?(/[^\s;|&'\"()<>]*)?", re.I)
TFTP_RE = re.compile(r"\b(tftp|ftpget)\b[^;|&\n]*?(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", re.I)
BRUTE_ATTEMPTS = 50   # 이 이상 인증을 시도한 IP는 무차별 대입 의심


def host_kind(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return '도메인'
    if ip.is_loopback:
        return '루프백(무시)'
    if not ip.is_global:
        return '사설·특수 주소'
    return '공인 IP'


def _servers_from_command(cmd):
    out = []
    for scheme, host, port, path in URL_RE.findall(cmd or ''):
        out.append((host.lower(), scheme.lower(), port, f'{scheme.lower()}://{host}{":" + port if port else ""}{path or ""}'))
    for tool, host in TFTP_RE.findall(cmd or ''):
        out.append((host, tool.lower(), '', f'{tool.lower()} {host}'))
    return out


# ---------------------------------------------------------------- 다운로드 서버

def download_servers(ds, sc):
    """공격자가 파일을 가져오려던 서버. 명령 원문과 Cowrie 파일 이벤트를 합친다."""
    rows = []
    c = sc.commands
    c = c[c['command'].str.contains('://|tftp|ftpget', case=False, regex=True)]  # 정규식 전에 후보만 남긴다
    for src, sid, t, cmd in zip(c['source'], c['session_id'], c['time'], c['command']):
        for host, tool, port, url in _servers_from_command(cmd):
            rows.append((host, tool, url, src, sid, t, 'command'))
    for r in sc.files.itertuples():
        for host, tool, port, url in _servers_from_command(r.url):
            rows.append((host, tool, url, r.source, r.session_id, r.time, r.kind))
    if not rows:
        return pd.DataFrame(columns=['host', 'kind', 'sessions', 'ips', 'urls', 'tools', 'ok', 'failed', 'first', 'last'])
    df = pd.DataFrame(rows, columns=['host', 'tool', 'url', 'source', 'session_id', 'time', 'event'])
    df = df.merge(sc.sessions[['source', 'session_id', 'src_ip']], on=['source', 'session_id'], how='left')
    g = df.groupby('host').agg(
        sessions=('session_id', 'nunique'), ips=('src_ip', 'nunique'),
        urls=('url', lambda u: sorted(set(u))), tools=('tool', lambda t: ', '.join(sorted(set(t)))),
        ok=('event', lambda e: int((e == 'download').sum())), failed=('event', lambda e: int((e == 'download_failed').sum())),
        first=('time', 'min'), last=('time', 'max'),
        self_hosted=('src_ip', lambda s: None)).reset_index()
    # 공격자 자신의 IP에서 파일을 내려주는 경우(감염된 장비가 다음 대상을 감염시키는 형태)
    own = df.assign(same=df['host'] == df['src_ip']).groupby('host')['same'].any()
    g['self_hosted'] = g['host'].map(own).fillna(False)
    g['kind'] = g['host'].map(host_kind)
    g = g.sort_values(['sessions', 'last'], ascending=False).reset_index(drop=True)
    return g


# ---------------------------------------------------------------- 차단 후보 IP

def ip_intel(ds, sc, rules):
    """IP별 근거와 차단 후보 이유. 이유가 하나도 없으면 후보가 아니다."""
    s = sc.sessions
    if s.empty:
        return pd.DataFrame()
    s = s.assign(day=s['start'].dt.date)
    base = (s.groupby('src_ip').agg(sessions=('session_id', 'size'), country=('country', 'first'),
                                    first=('start', 'min'), last=('start', 'max'),
                                    days=('day', 'nunique'),
                                    sources=('source', lambda x: ', '.join(D.SOURCE_NAMES.get(v, v) for v in sorted(set(x)))),
                                    logins=('login_success', 'sum'), commands=('n_commands', 'sum'))
            .reset_index())
    keys = s[['source', 'session_id', 'src_ip']]
    h = sc.hits.merge(keys, on=['source', 'session_id'], how='inner')
    h['danger'] = h['rule_id'].map(lambda r: X.DANGER.get(r, 0))
    max_danger = h.groupby('src_ip')['danger'].max()
    s01 = set(h.loc[h['rule_id'].isin(['S01', 'S02']), 'src_ip'])
    dl = set(h.loc[h['rule_id'] == 'B08', 'src_ip'])
    lg = sc.logins.merge(keys, on=['source', 'session_id'], how='inner')
    auth = lg.groupby('src_ip').agg(attempts=('success', 'size'), auth_ok=('success', 'sum'),
                                    passwords=('password', 'nunique'))
    base = base.join(auth, on='src_ip').fillna({'attempts': 0, 'auth_ok': 0, 'passwords': 0})
    for c in ('attempts', 'auth_ok', 'passwords'):
        base[c] = base[c].astype(int)
    base['danger'] = base['src_ip'].map(max_danger).fillna(0).astype(int)
    lo, _ = sc.f.bounds()
    seen_before = set(ds.sessions.loc[(ds.sessions['start'] < lo) & ds.sessions['source'].isin(sc.f.sources), 'src_ip'])

    def reasons(r):
        out = []
        if r['src_ip'] in s01:
            out.append('내려받아 실행')
        elif r['danger'] >= 3:
            out.append('위험 행동')
        if r['src_ip'] in dl and r['src_ip'] not in s01:
            out.append('다운로드 시도')
        if r['attempts'] >= BRUTE_ATTEMPTS:
            out.append('무차별 대입')
        if r['days'] >= 3 and r['sessions'] >= 20:
            out.append('반복 접속')
        return out
    base['reasons'] = base.apply(reasons, axis=1)
    # 우선순위: 1 즉시 차단 권장 / 2 검토 후 차단 / 3 관찰
    # 다른 악성코드 종료(B12)·채굴(B13)만 있는 IP는 2순위, 그 밖의 위험도 높음 행동은 1순위
    serious = set(h.loc[(h['danger'] >= 3) & ~h['rule_id'].isin(['B12', 'B13']), 'src_ip'])

    def tier(r):
        rs = set(r['reasons'])
        if not rs:
            return 0
        if '내려받아 실행' in rs or '다운로드 시도' in rs or r['src_ip'] in serious:
            return 1
        if '위험 행동' in rs or '무차별 대입' in rs:
            return 2
        return 3
    base['tier'] = base.apply(tier, axis=1)
    base['new'] = ~base['src_ip'].isin(seen_before) if not sc.f.full_period else False
    base['score'] = (base['reasons'].map(len) * 10 + base['danger'] * 5
                     + base['sessions'].clip(upper=500) / 50 + base['attempts'].clip(upper=1000) / 100)
    base['kind'] = base['src_ip'].map(host_kind)
    return base.sort_values(['score', 'sessions'], ascending=False).reset_index(drop=True)


TIER_NAMES = {1: '1순위 · 즉시 차단 권장', 2: '2순위 · 검토 후 차단', 3: '3순위 · 관찰'}
TIER_HELP = ('1순위: 파일을 내려받아 실행했거나, 다운로드를 시도했거나, 흔적 삭제·방화벽 해제·열쇠/예약 작업 심기를 한 IP. '
             '2순위: 다른 악성코드 종료(봇넷 감염 시도)나 무차별 대입(인증 50회 이상). 3순위: 여러 날 반복 접속만.')


def blocklist(ipi):
    bl = ipi[ipi['reasons'].map(bool) & (ipi['kind'] == '공인 IP')]
    return bl.sort_values(['tier', 'score'], ascending=[True, False]).reset_index(drop=True)


# ---------------------------------------------------------------- 공격 계정

def credentials(sc):
    lg = sc.logins
    if lg.empty:
        return pd.DataFrame(columns=['username', 'password', 'attempts', 'success', 'ips', 'first', 'last'])
    lg = lg.merge(sc.sessions[['source', 'session_id', 'src_ip']], on=['source', 'session_id'], how='left')
    g = (lg.groupby(['username', 'password']).agg(attempts=('success', 'size'), success=('success', 'sum'),
                                                  ips=('src_ip', 'nunique'), first=('time', 'min'), last=('time', 'max'))
         .reset_index().sort_values('attempts', ascending=False).reset_index(drop=True))
    return g


def top_values(sc, col, top=200):
    lg = sc.logins
    if lg.empty:
        return pd.DataFrame(columns=['value', 'attempts', 'success'])
    g = (lg.groupby(col).agg(attempts=('success', 'size'), success=('success', 'sum')).reset_index()
         .rename(columns={col: 'value'}).sort_values('attempts', ascending=False).head(top).reset_index(drop=True))
    return g


def exposure_checks(ds, sc, rules):
    """우리 회사 환경에서 점검할 항목. (항목, 근거 수치, 권장 조치)"""
    s = sc.sessions
    total = len(s)
    out = []
    if total:
        tel = int((s['protocol'] == 'telnet').sum())
        out.append(('외부에 열린 Telnet(23)', f'접속의 {tel / total * 100:.0f}%가 Telnet ({tel:,}세션)',
                    'Telnet을 끄거나 외부에서 막고, 꼭 필요하면 SSH로 대체'))
    cmds = sc.commands['command']
    iot = cmds.isin(['enable', 'system', 'shell', 'linuxshell', 'sh']).groupby(
        [sc.commands['source'], sc.commands['session_id']]).any().sum() if len(cmds) else 0
    pop = X.command_sessions(sc)
    if pop:
        out.append(('IoT·공유기 기본 명령 노림', f'명령 세션의 {iot / pop * 100:.0f}%가 장비용 명령(enable·shell·busybox)',
                    '외부에 노출된 공유기·카메라·DVR의 관리 포트와 기본 계정 점검'))
    if not sc.logins.empty:
        cred = credentials(sc)
        top = cred.head(5)
        pairs = ', '.join(f"{D.defang(u, 15, False)}/{D.defang(p, 15, False)}" for u, p in zip(top['username'], top['password']))
        out.append(('흔한 기본 계정 시도', f'상위 조합: {pairs}', '같은 아이디·비밀번호를 쓰는 계정이 없는지 점검, 비밀번호 금지 목록에 추가'))
        ok_rate = sc.logins['success'].mean() * 100
        out.append(('비밀번호 추측 성공률', f'허니팟 기준 {ok_rate:.1f}% (일부러 약하게 설정한 환경)',
                    '로그인 실패 횟수 제한·잠금, 키 기반 인증'))
    return pd.DataFrame(out, columns=['점검 항목', '근거', '권장 조치'])


# ---------------------------------------------------------------- 서울·시드니 공통

def shared_ips(sc):
    s = sc.sessions
    per = s.groupby('src_ip')['source'].nunique()
    both = per[per > 1].index
    g = (s[s['src_ip'].isin(both)].groupby(['src_ip', 'source']).size().unstack(fill_value=0).reset_index())
    g['total'] = g.drop(columns='src_ip').sum(axis=1)
    return g.sort_values('total', ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------- 변화 브리핑

def briefing_window(ds, f, days=7):
    """비교 기준: 기간을 골랐으면 그 기간, 전체 기간이면 '최근 7일'(마지막 수집일까지)을 새 기간으로 본다."""
    if f.full_period:
        last = ds.sessions.loc[ds.sessions['source'].isin(f.sources), 'start'].max().date()
        first = max(D.data_range(ds)[0], last - pd.Timedelta(days=days - 1).to_pytimedelta())
        return D.Filters(f.sources, f.protocols, first, last, False), f'최근 {days}일({first:%m-%d}~{last:%m-%d})'
    return f, f'선택 기간({f.start:%m-%d}~{f.end:%m-%d})'


def threat_level(br, sc_window, rules):
    """상황 등급: 위험(빨강) / 주의(노랑) / 안정(초록)과 그 이유."""
    h = sc_window.hits
    s01 = int(h[h['rule_id'].isin(['S01', 'S02'])][['source', 'session_id']].drop_duplicates().shape[0])
    high = int(h[h['rule_id'].isin(D.PRIORITY_RULES)][['source', 'session_id']].drop_duplicates().shape[0])
    reasons = []
    if len(br['new_servers']):
        reasons.append(f"새 다운로드 서버 {len(br['new_servers'])}개")
    if s01:
        reasons.append(f'내려받아 실행 {s01}세션')
    if len(br['new_hashes']):
        reasons.append(f"새 파일 해시 {len(br['new_hashes'])}개")
    if reasons:
        return '위험', '#fb7185', reasons, s01, high
    if high or len(br['new_danger_ips']):
        return '주의', '#fbbf24', [f'위험도 높음 행동 {high}세션'] + (
            [f"새 위험 IP {len(br['new_danger_ips'])}개"] if len(br['new_danger_ips']) else []), s01, high
    return '안정', '#34d399', ['위험도 높음 행동이 관측되지 않음'], s01, high


def briefing(ds, rules, f):
    """새로 나타난 것: 처음 보는 파일 해시·다운로드 서버·위험 IP·행동, 그리고 접속량 변화."""
    wf, label = briefing_window(ds, f)
    sc = D.scope(ds, wf)
    lo, _ = wf.bounds()
    before = D.Filters(wf.sources, wf.protocols, D.data_range(ds)[0], (lo - pd.Timedelta(days=1)).date(), False)
    old = D.scope(ds, before) if before.start <= before.end else None

    new_hash = set(sc.files['shasum'].dropna()) - (set(old.files['shasum'].dropna()) if old else set())
    servers = download_servers(ds, sc)
    old_servers = set(download_servers(ds, old)['host']) if old else set()
    new_servers = servers[~servers['host'].isin(old_servers) & (servers['kind'] != '루프백(무시)')]
    ipi = ip_intel(ds, sc, rules)
    old_ips = set(old.sessions['src_ip']) if old else set()
    new_danger_ips = ipi[(~ipi['src_ip'].isin(old_ips)) & (ipi['danger'] >= 3)]
    seen_rules = set(sc.hits['rule_id']) - (set(old.hits['rule_id']) if old else set())
    names = D.rule_names(rules)
    k_now = D.kpis(sc)
    prev = D.compare(ds, wf)
    change = D.change(k_now['sessions'], prev['sessions']) if prev else None
    out = {'label': label, 'window': wf, 'new_hashes': sorted(new_hash), 'new_servers': new_servers,
            'new_danger_ips': new_danger_ips, 'new_rules': [(r, names.get(r, r)) for r in sorted(seen_rules)],
            'sessions': k_now['sessions'], 'change': change}
    out['level'], out['color'], out['reasons'], out['s01'], out['high'] = threat_level(out, sc, rules)
    return out


# ---------------------------------------------------------------- 허니팟 상태

def health_daily(sc):
    """일별: 세션 수, 로그인 후 명령 없이 끊은 비율(허니팟을 알아챘을 가능성 신호), 세션당 명령 수."""
    s = sc.sessions
    if s.empty:
        return pd.DataFrame()
    d = s.assign(day=s['start'].dt.floor('D').dt.tz_localize(None))
    g = d.groupby('day').agg(sessions=('session_id', 'size'), logins=('login_success', 'sum'),
                             bail=('n_commands', lambda n: 0), cmd=('n_commands', 'sum')).reset_index()
    ok = d[d['login_success'] == 1]
    bail = ok.groupby('day').apply(lambda x: (x['n_commands'] == 0).mean() * 100, include_groups=False)
    g['bail'] = g['day'].map(bail).fillna(0.0)
    g['cmd_per_login'] = (g['cmd'] / g['logins'].where(g['logins'] > 0)).fillna(0.0)
    g['reliable'] = g['logins'] >= 30   # 로그인 30건 미만인 날은 비율이 크게 흔들린다
    return g


# ---------------------------------------------------------------- 보고서

def report_markdown(ds, rules, f):
    sc = D.scope(ds, f)
    k = D.kpis(sc)
    fn, early, pop = X.funnel(sc, rules)
    full = int(fn.loc[fn['level'] == 4, 'sessions'].iloc[0]) if pop else 0
    bl = blocklist(ip_intel(ds, sc, rules))
    servers = download_servers(ds, sc)
    servers = servers[servers['kind'] != '루프백(무시)']
    fs = D.file_summary(sc)
    top = X.danger_table(sc, rules)
    top = top[top['sessions'] > 0].head(5)
    br = briefing(ds, rules, f)
    period = f'{f.start:%Y-%m-%d} ~ {f.end:%Y-%m-%d} (KST)'
    lines = [f'# 허니팟 보고서 · {period}', '',
             f"허니팟: {', '.join(D.SOURCE_NAMES.get(s, s) for s in f.sources)} · 프로토콜: {', '.join(f.protocols)}", '',
             '## 1. 규모',
             f"- 접속 세션 {k['sessions']:,} · 고유 IP {k['ips']:,} · 명령 입력 {k['commands']:,}줄({k['command_sessions']:,}세션)",
             f"- 인증 시도 {k['auth']:,} (성공 {k['auth_success']:,})" if k['auth'] is not None else '- 인증 시도: 미수집',
             f'- 끝까지 실행(내려받아 실행)까지 간 세션 {full:,} · 초기 단계에서 멈춘 세션 {early:,}', '',
             '## 2. 주요 위협 (위험도 순)']
    lines += [f"- [{r.danger_name}] {r.plain} — {r.sessions:,}세션 ({r.rule_id})" for r in top.itertuples()]
    lines += ['', '## 3. 위협 정보 (IOC)',
              f'- 차단 후보 IP {len(bl):,}개 · 다운로드 서버 {len(servers):,}개 · 파일 해시 {fs["unique_hashes"]:,}개',
              f"- {br['label']} 새로 나타남: 파일 해시 {len(br['new_hashes'])} · 다운로드 서버 {len(br['new_servers'])} · "
              f"위험 행동 IP {len(br['new_danger_ips'])}", '',
              '### 차단 후보 IP 상위 10']
    lines += [f"- {r.src_ip} ({r.country or '?'}) — {', '.join(r.reasons)} · 세션 {r.sessions:,}" for r in bl.head(10).itertuples()]
    lines += ['', '### 다운로드 서버 상위 10 (링크 아님)']
    lines += [f"- {r.host} ({r.kind}) — 세션 {r.sessions:,} · {D.defang(r.urls[0], 120, False)}" for r in servers.head(10).itertuples()]
    lines += ['', '## 4. 권장 조치']
    lines += [f'- {a}: {c} (근거: {b})' for a, b, c in exposure_checks(ds, sc, rules).itertuples(index=False)]
    lines += ['- 차단 후보 IP·다운로드 서버를 방화벽/프록시 차단 목록에 검토 후 반영',
              '- 파일 해시를 백신·EDR에 등록하고 내부 서버에서 같은 파일 검색', '',
              '> 모든 수치는 허니팟에 입력된 명령의 관측이며 실행 성공·악성 여부를 확정하지 않습니다.']
    return '\n'.join(lines)


def to_csv(df):
    return df.to_csv(index=False).encode('utf-8-sig')
