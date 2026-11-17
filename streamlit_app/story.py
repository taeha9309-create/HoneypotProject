"""세션을 보안을 잘 모르는 사람도 읽을 수 있게 풀어 쓴다.

- 단계(STEPS): 접속부터 피해 행위까지, 공격이 보통 거치는 순서를 쉬운 이름으로 나눈 것.
- 쉬운 설명(PLAIN): 규칙·추정 행동마다 "무엇을 하려 했나"를 한 문장으로.
- 흐름(flow): 같은 행동이 연달아 나오면 한 줄로 묶고, 실패 조각은 해당 명령 줄에 붙인다.

설명은 입력된 명령을 보고 붙인 것이며, 실제로 실행에 성공했는지는 확인하지 않는다.
"""
from collections import OrderedDict

import pandas as pd

import data as D

# (키, 화면 이름, 한 줄 설명) — 공격이 보통 진행되는 순서
STEPS = OrderedDict([
    ('login', ('로그인 시도', '아이디·비밀번호를 넣어 들어오려 함')),
    ('shell', ('명령창 열기', '명령을 입력할 수 있는 화면(셸)을 열려 함')),
    ('recon', ('정보 수집', '서버가 어떤 장비인지, 무엇이 있는지 살펴봄')),
    ('scan', ('다른 용도의 접속', '셸 명령이 아닌 웹·전화(SIP) 스캐너 요청')),
    ('account', ('계정 조작', '비밀번호를 바꾸는 등 계정을 건드림')),
    ('tool', ('파일 들여오기', '외부에서 파일을 내려받거나 직접 만들어 넣음')),
    ('run', ('실행', '파일에 실행 권한을 주고 실행함')),
    ('persist', ('계속 머무르기', '다음에도 쉽게 들어오도록 열쇠·예약 작업을 심음')),
    ('hide', ('흔적 숨기기', '명령 기록·로그·방화벽을 지움')),
    ('impact', ('피해 행위', '다른 프로그램을 죽이거나 채굴 등 자원을 씀')),
    ('other', ('기타 입력', '의미를 판단하기 어려운 입력')),
])

STEP_COLORS = {'login': '#f472b6', 'shell': '#9aa3ad', 'recon': '#22d3ee', 'scan': '#7d8590', 'account': '#fbbf24',
               'tool': '#fb923c', 'run': '#fb7185', 'persist': '#ef4444', 'hide': '#c084fc', 'impact': '#ef4444',
               'other': '#4b5563'}

# 규칙 파일의 단계(ATT&CK 기준) 중 일반인에게 헷갈리는 것은 화면용으로 바꾼다.
# B11(chmod 실행 권한)은 ATT&CK상 방어 회피지만, 읽는 사람에게는 '실행 준비'가 자연스럽다.
STEP_OVERRIDE = {'B19': 'shell', 'B11': 'run'}
RULE_STAGE = {'정찰': 'recon', '계정 장악': 'account', '지속성': 'persist', '방어 회피': 'hide',
              '도구 반입': 'tool', '실행': 'run', '영향': 'impact'}

PLAIN = {
    'B01': '서버의 사양(CPU·운영체제)을 알아보려 함', 'B02': '지금 누가 접속해 있는지 확인함',
    'B03': '비밀번호를 바꾸려 함', 'B04': '다음에 비밀번호 없이 들어오도록 SSH 열쇠를 심으려 함',
    'B05': '정해진 시간마다 자동 실행되도록 예약 작업을 등록하려 함', 'B06': '입력한 명령 기록이 남지 않게 하려 함',
    'B07': '접속 기록(로그)을 지우려 함', 'B08': '외부 서버에서 파일을 내려받으려 함',
    'B09': '숨겨 둔(인코딩된) 코드를 풀려 함', 'B10': '스크립트 파일을 실행하려 함',
    'B11': '파일을 실행할 수 있게 권한을 바꾸려 함', 'B12': '서버에 있던 다른 악성 프로그램을 종료시키려 함',
    'B13': '가상화폐 채굴 프로그램 흔적', 'B14': '16진수 문자로 파일을 직접 써서 만들려 함',
    'B15': '방화벽 규칙을 지워 접속을 막지 못하게 하려 함', 'B16': '파일을 써 보고 지우며 쓸 수 있는 위치를 찾음',
    'B17': '특정 프로그램이 설치돼 있는지 확인함', 'B18': '서버의 계정 목록을 확인함',
    'B19': '명령을 입력할 수 있는 셸을 열려 함', 'B20': '폴더 안 파일 목록을 확인함',
    'S01': '파일을 내려받아 실행 권한을 주고 실행까지 이어감', 'S02': '숨긴 코드를 풀어서 바로 실행하려 함',
}
REVIEW_PLAIN = {
    'device_cli_entry_candidate': ('shell', '공유기·IoT 장비의 관리자 명령 모드로 들어가려 함'),
    'protocol_header_candidate': ('scan', '셸 명령이 아닌 웹·전화(SIP) 스캐너가 보낸 요청'),
    'process_cmdline_read_candidate': ('recon', '실행 중인 프로그램 정보를 확인함'),
    'hostname_read_candidate': ('recon', '서버 이름을 확인함'),
    'busybox_probe_candidate': ('recon', 'IoT 장비용 도구(busybox)가 있는지 확인함'),
    'empty_input': ('other', '빈 입력(엔터만 누름)'),
    'other_unmodeled_input': ('other', '의미를 판단하기 어려운 입력'),
}
# 한 명령에 여러 규칙이 걸리면 더 진행된(위험한) 단계를 대표로 쓴다
STEP_RANK = {k: i for i, k in enumerate(['other', 'scan', 'shell', 'recon', 'account', 'tool', 'run',
                                        'hide', 'persist', 'impact'])}  # 뒤로 갈수록 대표 단계로 우선


def explain(rules, command):
    """명령 한 줄 → (단계 키, 쉬운 설명, 근거 종류, 규칙 ID 목록)."""
    meta = {r['id']: r for r in rules}
    labels = D.label_command(rules, command)
    if labels:
        ids = [l['rule_id'] for l in labels]
        steps = [STEP_OVERRIDE.get(i) or RULE_STAGE.get(meta.get(i, {}).get('stage'), 'other') for i in ids]
        step = max(steps, key=lambda s: STEP_RANK[s])
        # 설명은 진행 순서(내려받기 → 권한 → 실행)대로, 대표 단계는 가장 진행된 것
        order = sorted(zip(ids, steps), key=lambda p: (STEP_RANK[p[1]], p[0]))
        text = ' → '.join(dict.fromkeys(PLAIN.get(i, meta[i].get('name', i)) for i, _ in order[-3:]))
        return step, text, '규칙 일치', ids
    reasons = D.review_unclassified([(None, command)])
    step, text = REVIEW_PLAIN.get(reasons[0], ('other', '의미를 판단하기 어려운 입력'))
    return step, text, ('근거 부족' if step == 'other' else '입력 기반 추정'), []


def flow(ds, source, session_id, rules):
    """세션의 흐름을 사람이 읽기 좋은 단위로 묶는다. 같은 행동이 연달아 나오면 한 줄로 합친다."""
    def own(df):
        return df[(df['source'] == source) & (df['session_id'] == session_id)]
    rows = []
    for r in own(ds.logins).itertuples():
        ok = bool(r.success)
        rows.append({'time': r.time, 'order': 0, 'step': 'login', 'kind': 'auth',
                     'text': '로그인 성공' if ok else '로그인 실패',
                     'raw': f'{D.defang(r.username, 30, False)} / {D.defang(r.password, 30, False)}',
                     'basis': '', 'rules': [], 'ok': ok, 'index': None})
    cmds = own(ds.commands).sort_values('ts').reset_index(drop=True)
    failed = own(ds.failed)
    failed_text = list(failed['command'])
    for i, r in cmds.iterrows():
        step, text, basis, ids = explain(rules, r['command'])
        bad = any(fr and fr in r['command'] for fr in failed_text)
        rows.append({'time': r['time'], 'order': 1, 'step': step, 'kind': 'cmd', 'text': text,
                     'raw': D.defang(r['command'], mask_ips=False), 'basis': basis, 'rules': ids,
                     'ok': not bad, 'index': i})
    for r in own(ds.files).itertuples():
        kind = {'download': '파일을 내려받음', 'download_failed': '파일 내려받기 실패', 'upload': '파일이 올라옴'}[r.kind]
        name = D.file_name(r.url, r.filename)
        rows.append({'time': r.time, 'order': 2, 'step': 'tool', 'kind': 'file', 'text': f'{kind}: {name}',
                     'raw': D.defang(r.url, mask_ips=False) or '(URL 없음)', 'basis': '관측',
                     'rules': [], 'ok': r.kind != 'download_failed', 'index': None})
    if not rows:
        return []
    rows.sort(key=lambda x: (x['time'], x['order'], x['index'] if x['index'] is not None else -1))

    groups = []
    for r in rows:
        last = groups[-1] if groups else None
        same = last and last['kind'] == r['kind'] and r['kind'] != 'file' and (
            last['step'] == r['step'] if r['kind'] == 'cmd' else last['text'] == r['text'])
        if same:
            if r['text'] not in last['texts']:
                last['texts'].append(r['text'])
            if r['basis'] == '규칙 일치':
                last['basis'] = '규칙 일치'
            last['rules'] = sorted(set(last['rules']) | set(r['rules']))
            last['count'] += 1
            last['raws'].append(r['raw'])
            last['end'] = r['time']
            last['ok'] = last['ok'] and r['ok']
            last['failed'] += 0 if r['ok'] else 1
            if r['index'] is not None:
                last['indexes'].append(r['index'])
            continue
        groups.append({**r, 'count': 1, 'texts': [r['text']], 'raws': [r['raw']], 'end': r['time'],
                       'failed': 0 if r['ok'] else 1,
                       'indexes': [r['index']] if r['index'] is not None else []})
    return groups


def summary(ds, source, session_id, rules, groups):
    """한눈에 보기: 한두 문장 요약과 단계 칩 정보."""
    s = ds.sessions[(ds.sessions['source'] == source) & (ds.sessions['session_id'] == session_id)].iloc[0]
    lg = ds.logins[(ds.logins['source'] == source) & (ds.logins['session_id'] == session_id)]
    fails, oks = int((lg['success'] == 0).sum()), lg[lg['success'] == 1]
    steps_seen = list(dict.fromkeys(g['step'] for g in groups if g['step'] not in ('other',)))
    if s['login_success'] and 'login' not in steps_seen:  # 원본 로그가 없어도 로그인 성공은 세션에 남아 있다
        steps_seen.insert(0, 'login')
    n_cmd = sum(g['count'] for g in groups if g['kind'] == 'cmd')
    files = [g for g in groups if g['kind'] == 'file']
    end = max([g['end'] for g in groups], default=s['start'])
    secs = max(0, int((end - s['start']).total_seconds()))
    dur = f'{secs}초' if secs < 120 else f'{secs // 60}분 {secs % 60}초'
    proto = (s['protocol'] or '').upper()

    parts = []
    if source in ds.raw_sources:
        if len(oks):
            first = oks.iloc[0]
            cred = f"`{D.defang(first['username'], 20, False)} / {D.defang(first['password'], 20, False)}`"
            parts.append((f'로그인을 {fails}번 실패한 뒤 ' if fails else '') + f'{cred}로 로그인에 성공했습니다.')
        elif fails:
            parts.append(f'로그인을 {fails}번 시도했지만 모두 실패했습니다.')
    elif s['login_success']:
        parts.append(f"`{D.defang(s['username'], 20, False)} / {D.defang(s['password'], 20, False)}`로 로그인에 성공했습니다.")
    if n_cmd:
        acts = [STEPS[k][0] for k in steps_seen if k not in ('login',)]
        parts.append(f'명령 {n_cmd}줄을 입력했고, ' + ' → '.join(acts) + ' 순서로 움직였습니다.' if acts
                     else f'명령 {n_cmd}줄을 입력했습니다.')
    elif not parts:
        parts.append('접속만 하고 로그인이나 명령 없이 끊었습니다.')
    if files:
        ok = sum(1 for g in files if g['ok'])
        parts.append(f'파일 관련 기록 {len(files)}건(성공 {ok}건)이 있습니다.')
    hits = ds.hits[(ds.hits['source'] == source) & (ds.hits['session_id'] == session_id)]
    danger = [D.PRIORITY_RULES[r] for r in D.PRIORITY_RULES if r in set(hits['rule_id'])]
    return {'sentence': f'{proto}로 접속해 {dur} 동안 머물렀습니다. ' + ' '.join(parts),
            'steps': steps_seen, 'danger': danger, 'duration': dur, 'commands': n_cmd}


def flow_table(groups, limit=200):
    """flow 결과를 표로. '무엇을 했나'가 중심이고 원문은 짧게 붙인다."""
    out = []
    for g in groups[:limit]:
        raw = g['raws'][0]
        if g['count'] > 1:
            uniq = list(dict.fromkeys(g['raws']))
            raw = ', '.join(uniq[:3]) + (f' 외 {len(uniq) - 3}종' if len(uniq) > 3 else '')
        idx = ''
        if g['indexes']:
            idx = f"#{g['indexes'][0]}" + (f"~#{g['indexes'][-1]}" if len(g['indexes']) > 1 else '')
        status = '실패' if not g['ok'] and g['kind'] != 'cmd' else ('일부 실행 실패' if g['failed'] else '')
        out.append({'시각': g['time'].strftime('%H:%M:%S'), '단계': STEPS[g['step']][0],
                    '무엇을 했나': ' / '.join(g['texts'][:2]) + (f" 외 {len(g['texts']) - 2}가지" if len(g['texts']) > 2 else '')
                                   + (f"  (명령 {g['count']}줄)" if g['count'] > 1 else ''),
                    '근거': g['basis'], '상태': status, '입력 원문': D.defang(raw, 160, False) if g['kind'] != 'cmd' else raw[:160],
                    '#': idx, 'step': g['step']})
    return pd.DataFrame(out)


def chips_html(seen, danger):
    """공격 단계 칩. 관측된 단계만 색을 켠다. 문자열은 모두 고정 문구."""
    from html import escape
    keys = [k for k in STEPS if k not in ('other', 'scan') or k in seen]
    out = []
    for k in keys:
        name, desc = STEPS[k]
        on = k in seen
        color = STEP_COLORS[k] if on else '#2a3038'
        out.append(f'<span class="hp-chip{" on" if on else ""}" style="border-color:{color};'
                   f'{"color:" + color if on else ""}" title="{escape(desc)}">{escape(name)}</span>')
    html = '<div class="hp-chips">' + '<span class="arrow">›</span>'.join(out) + '</div>'
    if danger:
        html += ('<div class="hp-danger">⚠ 우선 확인할 행동: ' + ', '.join(escape(d) for d in danger) + '</div>')
    return html


def flow_html(groups, limit=40):
    """세로 타임라인. 공격자 입력(원문)은 escape해서 고정폭 회색 글씨로만 넣는다."""
    from html import escape
    rows = []
    for g in groups[:limit]:
        color = STEP_COLORS[g['step']]
        what = ' / '.join(g['texts'][:2]) + (f' 외 {len(g["texts"]) - 2}가지' if len(g['texts']) > 2 else '')
        uniq = list(dict.fromkeys(g['raws']))
        raw = '\n'.join(uniq[:4]) + (f'\n… 외 {len(uniq) - 4}종' if len(uniq) > 4 else '')
        meta = []
        if g['count'] > 1:
            meta.append(f'명령 {g["count"]}줄')
        if g['indexes']:
            meta.append(f"#{g['indexes'][0]}" + (f"~#{g['indexes'][-1]}" if len(g['indexes']) > 1 else ''))
        if g['basis']:
            cls = {'규칙 일치': 'rule', '입력 기반 추정': 'guess', '근거 부족': 'none', '관측': 'obs'}.get(g['basis'], 'none')
            meta.append(f'<span class="b {cls}">{escape(g["basis"])}</span>')
        if not g['ok']:
            meta.append('<span class="b fail">실패</span>' if g['kind'] != 'cmd' else '<span class="b fail">일부 실행 실패</span>')
        rows.append(
            f'<div class="hp-flow-row"><div class="t">{g["time"].strftime("%H:%M:%S")}</div>'
            f'<div class="rail"><span class="dot" style="background:{color}"></span></div>'
            f'<div class="body"><div class="head"><span class="step" style="color:{color}">{escape(STEPS[g["step"]][0])}</span>'
            f'<span class="what">{escape(what)}</span></div>'
            f'<div class="meta">{" · ".join(m if m.startswith("<span") else escape(m) for m in meta)}</div>'
            f'<div class="raw">{escape(raw)}</div></div></div>')
    more = f'<div class="hp-flow-more">… 이후 {len(groups) - limit}단계는 생략했습니다. 아래 원문 전체에서 확인하세요.</div>'         if len(groups) > limit else ''
    return '<div class="hp-flow">' + ''.join(rows) + more + '</div>'
