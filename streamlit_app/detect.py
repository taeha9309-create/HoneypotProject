"""탐지 분석 페이지용 집계. 어떤 공격 행동이 얼마나, 어떻게 관측됐나.

- 행동 = behavior 규칙 1개. 세션 수는 그 규칙이 걸린 고유 세션 수(한 세션이 여러 행동에 중복).
- 비율의 분모 = 조회 범위에서 명령을 입력한 세션 수.
- 탐지 시각 = 규칙이 그 세션에서 처음 걸린 시각(hits.first_ts).
- 규칙에 안 걸린 입력은 story.explain의 화면용 추정으로 묶는다(탐지 건수에는 넣지 않는다).
"""
from collections import defaultdict

import pandas as pd

import data as D
import story as S

# 단계별로 "왜 신경 써야 하나" (보안을 잘 모르는 사람용)
STEP_WHY = {
    'login': '아이디·비밀번호를 넣어 보는 단계입니다. 흔한 비밀번호를 쓰면 실제 서버도 이렇게 뚫립니다.',
    'shell': '봇이 명령을 내릴 준비를 하는 단계로, 거의 모든 자동 공격에서 나타납니다. 이것만으로는 위험도가 낮습니다.',
    'recon': '공격 전에 장비 종류와 환경을 확인해 맞는 악성코드를 고르려는 단계입니다.',
    'scan': '셸 명령이 아니라 다른 서비스를 찾는 스캐너가 보낸 요청입니다.',
    'account': '관리자를 내쫓거나 계속 쓰려고 계정·비밀번호를 바꾸는 단계입니다.',
    'tool': '악성 프로그램을 서버로 들여오는 단계입니다. 실제 서버라면 감염 직전입니다.',
    'run': '들여온 프로그램을 실행하는 단계입니다. 실제 서버라면 이 순간 감염됩니다.',
    'persist': '재부팅이나 비밀번호 변경 뒤에도 다시 들어오기 위한 장치를 심는 단계입니다.',
    'hide': '관리자가 침입을 알아채지 못하게 기록·로그·방화벽을 건드리는 단계입니다.',
    'impact': '서버 자원을 쓰거나 다른 프로그램을 방해하는 실제 피해 단계입니다.',
    'other': '의미를 판단하기 어려운 입력입니다.',
}


def rule_step(rules, rule_id):
    meta = {r['id']: r for r in rules}
    return S.STEP_OVERRIDE.get(rule_id) or S.RULE_STAGE.get(meta.get(rule_id, {}).get('stage'), 'other')


def behavior_rules(rules):
    return [r for r in rules if r['type'] == 'behavior']


def command_sessions(sc):
    return int(sc.commands[['source', 'session_id']].drop_duplicates().shape[0])


def behavior_stats(sc, rules):
    """규칙(행동)별 세션 수·비율·마지막 탐지. 관측 안 된 규칙도 0으로 남긴다."""
    pop = command_sessions(sc)
    h = sc.hits
    rows = []
    for r in behavior_rules(rules):
        g = h[h['rule_id'] == r['id']]
        step = rule_step(rules, r['id'])
        rows.append({'rule_id': r['id'], 'name': r.get('name', r['id']), 'plain': S.PLAIN.get(r['id'], r.get('name', '')),
                     'step': step, 'step_name': S.STEPS[step][0], 'stage': r.get('stage', ''),
                     'attack': str(r.get('attack', '') or ''), 'note': r.get('note', '') or '',
                     'sessions': int(g[['source', 'session_id']].drop_duplicates().shape[0]),
                     'hits': int(g['n_hits'].sum()), 'last': g['time'].max() if len(g) else pd.NaT,
                     'priority': r['id'] in D.PRIORITY_RULES})
    out = pd.DataFrame(rows)
    out['percent'] = out['sessions'] / pop * 100 if pop else 0.0
    out['step_order'] = out['step'].map(list(S.STEPS).index)
    return out.sort_values(['sessions', 'step_order'], ascending=[False, True]).reset_index(drop=True)


def campaign_stats(sc, rules):
    rows = []
    for r in rules:
        if r['type'] != 'campaign':
            continue
        g = sc.hits[sc.hits['rule_id'] == r['id']]
        rows.append({'rule_id': r['id'], 'name': r.get('name', r['id']),
                     'sessions': int(g[['source', 'session_id']].drop_duplicates().shape[0]),
                     'last': g['time'].max() if len(g) else pd.NaT})
    return pd.DataFrame(rows)


def step_sessions(sc, rules):
    """단계별로 그 단계의 행동이 하나라도 관측된 세션 수 (세션은 여러 단계에 중복)."""
    ids = {r['id'] for r in behavior_rules(rules)}
    h = sc.hits[sc.hits['rule_id'].isin(ids)].copy()
    h['step'] = h['rule_id'].map(lambda r: rule_step(rules, r))
    g = h.drop_duplicates(['source', 'session_id', 'step']).groupby('step').size()
    pop = command_sessions(sc)
    keys = [k for k in S.STEPS if k not in ('login', 'scan', 'other')]
    return pd.DataFrame({'step': keys, 'name': [S.STEPS[k][0] for k in keys],
                         'sessions': [int(g.get(k, 0)) for k in keys],
                         'percent': [g.get(k, 0) / pop * 100 if pop else 0 for k in keys],
                         'order': range(len(keys))})


def step_daily(sc, rules, exclude_steps=('shell',)):
    """일별로 단계별 탐지 세션 수 (탐지 시각 기준). 흔한 '명령창 열기'는 기본으로 뺀다."""
    ids = {r['id'] for r in behavior_rules(rules)}
    h = sc.hits[sc.hits['rule_id'].isin(ids)].copy()
    h['step'] = h['rule_id'].map(lambda r: rule_step(rules, r))
    h = h[~h['step'].isin(exclude_steps)]
    h['day'] = h['time'].dt.floor('D').dt.tz_localize(None)
    g = h.drop_duplicates(['source', 'session_id', 'step']).groupby(['day', 'step']).size().rename('sessions').reset_index()
    g['name'] = g['step'].map(lambda k: S.STEPS[k][0])
    return g


def rule_sessions(sc, rule_id):
    keys = sc.hits[sc.hits['rule_id'] == rule_id][['source', 'session_id', 'time', 'n_hits']]
    out = keys.merge(sc.sessions[['source', 'session_id', 'src_ip', 'ip_masked', 'protocol', 'country', 'n_commands']],
                     on=['source', 'session_id'])
    return out.sort_values('time', ascending=False).reset_index(drop=True)


def rule_examples(ds, sc, rule_id, limit=12):
    """이 규칙에 실제로 걸린 명령 원문 (서로 다른 형태 위주, 많이 나온 순)."""
    sess = rule_sessions(sc, rule_id)
    if sess.empty:
        return pd.DataFrame(columns=['command', 'count', 'sessions'])
    keys = pd.MultiIndex.from_frame(sess[['source', 'session_id']])
    c = sc.commands[pd.MultiIndex.from_frame(sc.commands[['source', 'session_id']]).isin(keys)]
    counts, sess_of = defaultdict(int), defaultdict(set)
    hit_cache = {}
    for src, sid, cmd in zip(c['source'], c['session_id'], c['command']):
        if cmd not in hit_cache:
            hit_cache[cmd] = any(l['rule_id'] == rule_id for l in D.label_command(ds.rules, cmd))
        if hit_cache[cmd]:
            counts[cmd] += 1
            sess_of[cmd].add((src, sid))
    rows = sorted(counts.items(), key=lambda kv: -kv[1])[:limit]
    return pd.DataFrame({'command': [D.defang(k, 300) for k, _ in rows], 'count': [v for _, v in rows],
                         'sessions': [len(sess_of[k]) for k, _ in rows]})


def linked_flows(ds, sc):
    """S01(같은 파일 다운로드→권한→실행)과 S02(디코딩→인터프리터)를 대상별로 묶는다."""
    if ds.flows is not None:
        hits = sc.hits[sc.hits['rule_id'].isin(['S01', 'S02'])][['source', 'session_id', 'rule_id', 'time']]
        df = ds.flows.merge(hits, on=['source', 'session_id', 'rule_id'])
        df = df.merge(sc.sessions[['source', 'session_id', 'src_ip']], on=['source', 'session_id'])
        if df.empty:
            return pd.DataFrame(columns=['rule_id', 'target', 'sessions', 'ips', 'first', 'last']), pd.DataFrame()
        g = (df.groupby(['rule_id', 'target']).agg(sessions=('session_id', 'nunique'), ips=('src_ip', 'nunique'),
                                                   first=('time', 'min'), last=('time', 'max'))
             .reset_index().sort_values(['sessions', 'last'], ascending=False).reset_index(drop=True))
        return g, df
    rows = []
    want = sc.hits[sc.hits['rule_id'].isin(['S01', 'S02'])][['source', 'session_id']].drop_duplicates()
    keys = pd.MultiIndex.from_frame(want)
    sub = ds.commands[pd.MultiIndex.from_frame(ds.commands[['source', 'session_id']]).isin(keys)].sort_values('ts')
    by_session = {k: list(zip(g['ts'], g['command'])) for k, g in sub.groupby(['source', 'session_id'])}
    explained = {}
    for rid in ('S01', 'S02'):
        sess = rule_sessions(sc, rid)
        for r in sess.itertuples():
            key = (r.source, r.session_id)
            if key not in explained:
                explained[key] = D.explain_session(ds.rules, by_session.get(key, []))['matches']
            ev = explained[key]
            for item in ev:
                if item['rule_id'] != rid:
                    continue
                for e in item['evidence']:
                    if e['relationship'] == 'ordered_same_literal_file':
                        target = e['target'].rsplit('/', 1)[-1]
                    elif e['relationship'] == 'decoder_stdout_to_interpreter_stdin':
                        target = f"base64 → {e['interpreter']}"
                    else:
                        continue
                    rows.append({'rule_id': rid, 'target': target, 'source': r.source, 'session_id': r.session_id,
                                 'src_ip': r.src_ip, 'time': r.time})
    if not rows:
        return pd.DataFrame(columns=['rule_id', 'target', 'sessions', 'ips', 'first', 'last']), pd.DataFrame()
    df = pd.DataFrame(rows).drop_duplicates(['rule_id', 'target', 'source', 'session_id'])
    g = (df.groupby(['rule_id', 'target']).agg(sessions=('session_id', 'nunique'), ips=('src_ip', 'nunique'),
                                               first=('time', 'min'), last=('time', 'max'))
         .reset_index().sort_values(['sessions', 'last'], ascending=False).reset_index(drop=True))
    return g, df


def unmatched_inputs(ds, sc, top=30):
    """어떤 규칙에도 안 걸린 명령. 화면용 추정 설명별로 묶고, 많이 나온 원문을 보여 준다."""
    cmds = sc.commands
    if cmds.empty:
        return pd.DataFrame(), pd.DataFrame(), 0
    expl = {}
    for cmd in cmds['command'].unique():
        step, text, basis, ids = S.explain(ds.rules, cmd)
        if not ids:
            expl[cmd] = (step, text, basis)
    m = cmds[cmds['command'].isin(expl)]
    m = m.assign(step=m['command'].map(lambda c: expl[c][0]), text=m['command'].map(lambda c: expl[c][1]),
                 basis=m['command'].map(lambda c: expl[c][2]))
    groups = (m.groupby(['text', 'step', 'basis']).agg(lines=('command', 'size'), kinds=('command', 'nunique'),
                                                      sessions=('session_id', 'nunique'))
              .reset_index().sort_values('lines', ascending=False).reset_index(drop=True))
    groups['step_name'] = groups['step'].map(lambda k: S.STEPS[k][0])
    raws = (m.groupby(['command', 'text', 'basis']).agg(lines=('command', 'size'), sessions=('session_id', 'nunique'))
            .reset_index().sort_values('lines', ascending=False).head(top).reset_index(drop=True))
    raws['command'] = raws['command'].map(lambda c: D.defang(c, 200))
    share = len(m) / len(cmds) * 100
    return groups, raws, share


# ---------------------------------------------------------------- 위험도와 진행 단계 (쉬운 화면용)

# 위험도: 실제 서버였다면 피해로 이어질 가능성. 기획서 4절의 우선 확인 규칙은 모두 '높음'.
DANGER = {
    'S01': 3, 'S02': 3, 'B04': 3, 'B05': 3, 'B06': 3, 'B07': 3, 'B15': 3, 'B12': 3, 'B13': 3,
    'B03': 2, 'B08': 2, 'B09': 2, 'B10': 2, 'B11': 2, 'B14': 2,
    'B01': 1, 'B02': 1, 'B16': 1, 'B17': 1, 'B18': 1, 'B19': 1, 'B20': 1,
}
DANGER_NAMES = {3: '높음', 2: '중간', 1: '낮음'}
DANGER_COLORS = {3: '#fb7185', 2: '#fbbf24', 1: '#7d8590'}
DANGER_HELP = ('높음: 실제 서버였다면 감염·장악으로 이어지는 행동(내려받아 실행, 열쇠·예약 작업 심기, 기록·로그·방화벽 지우기, '
               '다른 프로그램 종료·채굴). 중간: 파일을 들여오거나 실행하려는 시도, 비밀번호 변경. '
               '낮음: 명령창 열기·장비 확인 같은 탐색.')

# 진행 단계: 세션이 '어디까지 갔나'. 숫자가 클수록 더 깊이 들어간 것.
FUNNEL = [(0, '명령 입력', '명령을 하나라도 입력한 세션'),
          (1, '정보 수집', '장비 종류·환경을 살펴봄'),
          (2, '파일 들여오기 시도', '외부에서 파일을 받거나 직접 만들려 함'),
          (3, '실행 시도', '실행 권한을 주거나 스크립트를 실행하려 함'),
          (4, '끝까지 실행', '같은 파일을 받아 권한을 주고 실행까지, 또는 숨긴 코드를 풀어 바로 실행')]
_LEVEL = {'recon': 1, 'account': 2, 'tool': 2, 'run': 3}


def danger_table(sc, rules):
    st_ = behavior_stats(sc, rules)
    st_['danger'] = st_['rule_id'].map(lambda r: DANGER.get(r, 1))
    st_['danger_name'] = st_['danger'].map(DANGER_NAMES)
    return st_.sort_values(['danger', 'sessions'], ascending=[False, False]).reset_index(drop=True)


def funnel(sc, rules):
    """세션별로 가장 깊이 간 단계를 구하고, 각 단계 '이상'까지 간 세션 수를 센다."""
    pop = sc.commands[['source', 'session_id']].drop_duplicates()
    level = {k: 0 for k in zip(pop['source'], pop['session_id'])}
    for src, sid, rid in zip(sc.hits['source'], sc.hits['session_id'], sc.hits['rule_id']):
        key = (src, sid)
        if key not in level:
            continue
        lv = 4 if rid in ('S01', 'S02') else _LEVEL.get(rule_step(rules, rid), 0)
        if lv > level[key]:
            level[key] = lv
    levels = pd.Series(list(level.values()), dtype=int)
    total = len(levels)
    rows = [{'level': lv, 'name': name, 'desc': desc, 'sessions': int((levels >= lv).sum()),
             'percent': (levels >= lv).mean() * 100 if total else 0.0} for lv, name, desc in FUNNEL]
    stopped_early = int((levels <= 1).sum())
    return pd.DataFrame(rows), stopped_early, total
