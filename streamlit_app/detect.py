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
    rows = []
    for rid in ('S01', 'S02'):
        sess = rule_sessions(sc, rid)
        for r in sess.itertuples():
            cmds = ds.commands[(ds.commands['source'] == r.source) & (ds.commands['session_id'] == r.session_id)]
            cmds = cmds.sort_values('ts')
            ev = D.explain_session(ds.rules, list(zip(cmds['ts'], cmds['command'])))['matches']
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
