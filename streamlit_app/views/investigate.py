"""세션 조사: 이 접속(세션·IP·파일)에서 무슨 일이 있었나 (Q4, Q6, Q7).

목록에서는 IP를 가리고, 고른 세션·IP의 상세에서만 전체 IP를 보여 준다.
공격자 입력은 실행하지 않고 HTML로 해석하지 않는다(st.dataframe / st.code로만 표시).
"""
from html import escape
import re

import altair as alt
import pandas as pd
import streamlit as st

import common as C
import data as D
import story as S

C.inject_css()
ds, f = C.dataset(), C.filters()
rules = ds.rules
names = C.country_names()
rule_label = {r['id']: f"{r['id']} {r.get('name', '')}" for r in rules}

if not f.sources or not f.protocols:
    st.info('허니팟과 프로토콜을 하나 이상 고르세요.')
    st.stop()
sc = D.scope(ds, f)

scope_kind = '전체 기간' if f.full_period else ('하루' if f.days == 1 else '선택 기간')
period = f'{f.start:%m-%d}' if f.days == 1 else f'{f.start:%m-%d} ~ {f.end:%m-%d}'
C.page_header('Investigate', f'{scope_kind} {period} KST',
              '세션 · IP · 수집 파일을 조사합니다. 목록은 사이드바 조회 범위를 따르고, 상세는 전체 보유 데이터 기준입니다.')

# 다른 화면에서 넘어올 때 고를 탭 (위젯이 만들어지기 전에만 값을 바꿀 수 있다)
if '_goto_tab' in st.session_state:
    st.session_state['inv_tab'] = st.session_state.pop('_goto_tab')
st.session_state.setdefault('inv_tab', '세션')
tab = st.segmented_control('보기', ['세션', 'IP', '수집 파일'], key='inv_tab',
                           label_visibility='collapsed') or '세션'
target = st.session_state.get('detail') or {}


def goto(tab_name, **kw):
    st.session_state['detail'] = kw
    st.session_state['_goto_tab'] = tab_name
    st.rerun()


# ---------------------------------------------------------------- 세션 상세

def show_session(source, session_id):
    d = D.session_detail(ds, source, session_id)
    if d is None:
        st.warning('세션을 찾을 수 없습니다.')
        return
    m = d['meta']
    groups = S.flow(ds, source, session_id, rules)
    sm = S.summary(ds, source, session_id, rules, groups)

    # ---- 한눈에 보기: 쉬운 요약 + 공격 단계 칩
    with C.card(f"한눈에 보기 · 세션 {session_id} ({D.SOURCE_NAMES.get(source, source)})",
                help='입력된 명령을 보고 쉬운 말로 풀어 쓴 요약입니다. 실제로 실행에 성공했는지는 확인하지 않았습니다.'):
        story = re.sub(r'`([^`]*)`', r'<code>\1</code>', escape(sm['sentence']))
        st.markdown(f'<div class="hp-story">{story}</div>', unsafe_allow_html=True)
        st.markdown(S.chips_html(sm['steps'], sm['danger']), unsafe_allow_html=True)
        st.caption(f"IP {m['src_ip'] or '-'} · {names.get(m['country'], m['country'] or '위치 미상')} · "
                   f"시작 {C.fmt_dt(m['start'], '%Y-%m-%d %H:%M:%S')} KST · 머문 시간 {sm['duration']} · "
                   f"센서 {m.get('sensor') or '-'} · 클라이언트 {D.defang(m.get('client_version'), 60, False) or '-'}")
        if st.button('이 IP의 전체 활동 보기 →', key=f'ip_of_{session_id}'):
            goto('IP', ip=m['src_ip'])

    left, right = st.columns([1.7, 1])
    with left:
        with C.card('무슨 일이 있었나 (시간순)',
                    help='같은 단계의 명령이 이어지면 한 줄로 묶었습니다. 배지: 규칙 일치(탐지 규칙에 걸림), '
                         '입력 기반 추정(명령 모양으로 짐작한 설명, 탐지 건수에는 안 들어감), 근거 부족, 관측(파일 기록). '
                         '회색 상자는 공격자가 실제로 입력한 원문입니다.'):
            if not d['raw_known']:
                st.caption('원본 로그가 없는 출처라 로그인 시도·파일 실패 기록은 미수집입니다.')
            if not groups:
                st.caption('기록된 행동이 없습니다. 접속만 하고 끊은 세션입니다.')
            else:
                st.markdown(S.flow_html(groups), unsafe_allow_html=True)
                if d['commands']:
                    with st.expander(f"입력 원문 전체 보기 (명령 {len(d['commands'])}줄, #번호)"):
                        st.code('\n'.join(f'#{i:<3} {D.defang(c, mask_ips=False)}' for i, c in enumerate(d['commands'])),
                                language=None, wrap_lines=True)
    with right:
        with C.card('탐지 근거 (전문가용)', help='시그니처 규칙 ID와 처음 걸린 시각입니다.'):
            h = d['hits']
            if h.empty:
                st.caption('일치한 규칙이 없습니다.')
            else:
                st.dataframe(pd.DataFrame({'규칙': h['rule_id'], '이름': h['name'],
                                           '처음 일치': h['time'].dt.strftime('%H:%M:%S'), '횟수': h['n_hits']}),
                             hide_index=True, width='stretch')
        if d['evidence']:
            with C.card('연결 근거 (S01 · S02)', help='같은 파일을 다운로드→실행 권한→실행한 순서, 또는 디코딩 결과를 인터프리터로 '
                                                   '넘긴 구문입니다. 입력 관측이며 실행 성공은 확인하지 않았습니다.'):
                cmds = d['commands']
                for item in d['evidence']:
                    st.markdown(f"`{item['rule_id']}` {item['name']} · 경로 {item['n_hits']}개")
                    for e in item['evidence']:
                        if e['relationship'] == 'ordered_same_literal_file':
                            steps = ' → '.join(f"{s['action']}[#{s['command_index']}]" for s in e['steps'])
                            used = sorted({s['command_index'] for s in e['steps']})
                            st.code(f"대상 파일: {e['target']}\n단계: {steps}\n\n"
                                    + '\n'.join(f'[#{i}] {D.defang(cmds[i], mask_ips=False)}' for i in used),
                                    language=None, wrap_lines=True)
                        elif e['relationship'] == 'decoder_stdout_to_interpreter_stdin':
                            cmd = cmds[e['command_index']]
                            (a, b), (c, dd) = e['decoder_span'], e['interpreter_span']
                            st.code(f"[#{e['command_index']}] 디코더: {D.defang(cmd[a:b], mask_ips=False)}\n"
                                    f"  → 인터프리터({e['interpreter']}): {D.defang(cmd[c:dd], mask_ips=False)}",
                                    language=None, wrap_lines=True)


# ---------------------------------------------------------------- IP 상세

def show_ip(ip):
    d = D.ip_detail(ds, ip)
    if d is None:
        st.warning('이 IP의 세션이 없습니다.')
        return
    with C.card(f'IP {ip}'):
        cols = st.columns(5)
        with cols[0]:
            C.kpi('국가', names.get(d['country'], d['country'] or '위치 미상'), C.VIOLET)
        with cols[1]:
            C.kpi('세션', f"{len(d['sessions']):,}", C.CYAN)
        with cols[2]:
            C.kpi('활동일', f"{d['days']}일", C.LIME)
        with cols[3]:
            C.kpi('처음 ~ 마지막', f"{C.fmt_dt(d['first'], '%m-%d')} ~ {C.fmt_dt(d['last'], '%m-%d')}", C.AMBER)
        with cols[4]:
            C.kpi('허니팟', ', '.join(D.SOURCE_NAMES.get(s, s) for s in d['sources']), C.GREEN,
                  '서울·시드니 모두 방문' if len(d['sources']) > 1 else '')
        daily = D.ip_daily(ds, ip)
        names_ = [n for n in C.SOURCE_COLORS if n in set(daily['source'])]
        C.chart(alt.Chart(daily).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
            x=alt.X('day:T', title=None, axis=alt.Axis(format='%m-%d', labelAngle=0, grid=False)),
            y=alt.Y('sessions:Q', title=None, stack=True, axis=alt.Axis(domain=False, ticks=False, format='~s')),
            color=alt.Color('source:N', title=None, legend=alt.Legend(orient='right'),
                            scale=alt.Scale(domain=names_, range=[C.SOURCE_COLORS[n] for n in names_])),
            tooltip=[alt.Tooltip('day:T', title='날짜', format='%m-%d'), alt.Tooltip('source:N', title='허니팟'),
                     alt.Tooltip('sessions:Q', title='세션', format=',')]).properties(height=140))
    left, right = st.columns([1.6, 1])
    with left:
        with C.card('세션 목록', help='행을 클릭하면 세션 탭에서 상세를 엽니다.'):
            s = d['sessions'].sort_values('start', ascending=False)
            view = pd.DataFrame({'시작 (KST)': s['start'].dt.strftime('%m-%d %H:%M:%S'),
                                 '허니팟': s['source'].map(lambda x: D.SOURCE_NAMES.get(x, x)),
                                 '프로토콜': s['protocol'], '로그인': s['login_success'].map({1: '성공', 0: '-'}),
                                 '명령 수': s['n_commands'], '세션 ID': s['session_id']})
            ev = st.dataframe(view, hide_index=True, width='stretch', height=360, on_select='rerun',
                              selection_mode='single-row', key=f'ip_sessions_{ip}')
            if ev.selection.rows:
                r = s.iloc[ev.selection.rows[0]]
                goto('세션', source=r['source'], session=r['session_id'])
    with right:
        with C.card('탐지된 행동'):
            b = d['behaviors']
            if b.empty:
                st.caption('일치한 규칙이 없습니다.')
            else:
                st.dataframe(pd.DataFrame({'규칙': b['rule_id'], '이름': b['name'], '세션': b['sessions']}),
                             hide_index=True, width='stretch')
        with C.card('사용한 계정'):
            lg = d['logins']
            if not d['raw_known']:
                st.caption('원본 로그가 없는 출처라 미수집입니다.')
            elif lg.empty:
                st.caption('인증 이벤트가 없습니다.')
            else:
                pairs = (lg['username'].fillna('') + ' / ' + lg['password'].fillna('')).map(lambda v: D.defang(v, 50, False))
                g = pd.DataFrame({'계정': pairs, '성공': lg['success']}).groupby('계정').agg(
                    시도=('성공', 'size'), 성공=('성공', 'sum')).sort_values('시도', ascending=False).reset_index()
                st.dataframe(g.head(15), hide_index=True, width='stretch')


# ---------------------------------------------------------------- 탭: 세션

if tab == '세션':
    with C.card('세션 찾기', help='사이드바의 기간·허니팟·프로토콜 범위 안에서 더 좁힙니다.'):
        a, b, c = st.columns([1.2, 1.6, 1])
        ip_q = a.text_input('IP 포함', key='s_ip', placeholder='예: 221.161')
        picked_rules = b.multiselect('탐지 규칙', [r['id'] for r in rules], key='s_rules',
                                     format_func=lambda x: rule_label[x])
        login_opt = c.selectbox('로그인', ['전체', '성공', '실패/없음'], key='s_login')
        a, b, c = st.columns([1, 1, 2])
        pr_only = a.toggle('우선 확인만', key='s_prio')
        cmd_only = b.toggle('명령 있는 세션만', key='s_cmd')
        sid_q = c.text_input('세션 ID로 바로 열기', key='s_sid', placeholder='예: 4903d12354b6')
    if sid_q.strip():
        hit = ds.sessions[ds.sessions['session_id'] == sid_q.strip()]
        if hit.empty:
            st.warning('해당 세션 ID가 없습니다.')
        else:
            target = {'source': hit['source'].iloc[0], 'session': sid_q.strip()}
    lst = D.session_list(sc, rules, ip_q, pr_only, cmd_only, tuple(picked_rules),
                         None if login_opt == '전체' else login_opt == '성공')
    with C.card(f'세션 목록 · {len(lst):,}개' + (' (최근 500개 표시)' if len(lst) > 500 else ''),
                help='행을 클릭하면 아래에 상세를 엽니다.'):
        shown = lst.head(500)
        view = pd.DataFrame({'시작 (KST)': shown['start'].dt.strftime('%m-%d %H:%M:%S'),
                             '허니팟': shown['source'].map(lambda x: D.SOURCE_NAMES.get(x, x)),
                             '프로토콜': shown['protocol'], 'IP': shown['ip_masked'],
                             '국가': shown['country'].map(lambda x: names.get(x, x) if isinstance(x, str) else '위치 미상'),
                             '로그인': shown['login_success'].map({1: '성공', 0: '-'}), '명령 수': shown['n_commands'],
                             '우선 확인': shown['behaviors'], '탐지 규칙': shown['rules']})
        styled = (view.style.map(lambda v: f'color: {C.AXIS}', subset=['시작 (KST)'])
                  .map(lambda v: f"color: {C.PROTOCOL_COLORS.get(v, C.INK)}; font-weight: 600", subset=['프로토콜'])
                  .map(lambda v: f'color: {C.VIOLET}', subset=['IP'])
                  .map(lambda v: f'color: {C.RED}; font-weight: 600' if v else '', subset=['우선 확인'])
                  .map(lambda v: f'color: {C.CYAN}', subset=['탐지 규칙']))
        ev = st.dataframe(styled, hide_index=True, width='stretch', height=360, on_select='rerun',
                          selection_mode='single-row', key='s_list')
        if ev.selection.rows:
            r = shown.iloc[ev.selection.rows[0]]
            target = {'source': r['source'], 'session': r['session_id']}
            st.session_state['detail'] = target
    if target.get('source') and target.get('session'):
        show_session(target['source'], target['session'])
    else:
        st.caption('목록에서 세션을 고르면 인증·명령 타임라인과 탐지 근거가 나옵니다.')

# ---------------------------------------------------------------- 탭: IP

elif tab == 'IP':
    a, b = st.columns([1, 2])
    ip_q = a.text_input('IP 포함', key='i_ip', placeholder='예: 221.161')
    ips = D.ip_list(sc, ip_q)
    with C.card(f'IP 목록 · {len(ips):,}개', help='조회 범위 안의 세션 수 순서. 행을 클릭하면 아래에 IP 상세를 엽니다.'):
        shown = ips.head(500)
        view = pd.DataFrame({'IP': shown['src_ip'].map(D.mask_ip),
                             '국가': shown['country'].map(lambda x: names.get(x, x) if isinstance(x, str) else '위치 미상'),
                             '세션': shown['sessions'], '활동일': shown['days'], '허니팟': shown['sources'],
                             '로그인 성공': shown['logins'], '명령 수': shown['commands'],
                             '처음': shown['first'].dt.strftime('%m-%d %H:%M'), '마지막': shown['last'].dt.strftime('%m-%d %H:%M')})
        ev = st.dataframe(view, hide_index=True, width='stretch', height=330, on_select='rerun',
                          selection_mode='single-row', key='i_list',
                          column_config={'세션': st.column_config.ProgressColumn(
                              '세션', format='%d', min_value=0, max_value=int(shown['sessions'].max() or 1))})
        if ev.selection.rows:
            target = {'ip': shown.iloc[ev.selection.rows[0]]['src_ip']}
            st.session_state['detail'] = target
    if target.get('ip'):
        show_ip(target['ip'])
    else:
        st.caption('목록에서 IP를 고르면 접속 이력과 행동이 나옵니다.')

# ---------------------------------------------------------------- 탭: 수집 파일

else:
    fs = D.file_summary(sc)
    with C.card('수집 파일 요약', help='Cowrie가 기록한 다운로드·업로드 이벤트입니다. 악성 여부는 확인하지 않았고, URL은 링크가 아닌 hxxp 형식입니다.'):
        cols = st.columns(4)
        for col, (lab, val, color) in zip(cols, (('다운로드', fs['downloads'], C.CYAN), ('업로드', fs['uploads'], C.VIOLET),
                                                 ('다운로드 실패', fs['failed'], C.RED), ('고유 해시', fs['unique_hashes'], C.LIME))):
            with col:
                C.kpi(lab, f'{val:,}', color)
        if not sc.raw_selected or sc.raw_partial:
            st.caption('원본 로그가 없는 출처(시드니 사본)는 성공한 다운로드만 있고 실패·업로드는 미수집입니다.')
    cat = D.file_catalog(sc)
    left, right = st.columns([1.5, 1])
    with left:
        with C.card(f'파일 목록 · {len(cat):,}개', help='해시 기준으로 묶었습니다. 실물 보관 여부는 서버 다운로드 폴더를 확인해야 해서 '
                                                     '지금은 "미확인"입니다. 행을 클릭하면 관측 기록을 엽니다.'):
            if cat.empty:
                st.caption('이 범위에서 수집된 파일이 없습니다.')
                picked = None
            else:
                view = pd.DataFrame({'파일': cat['name'], '종류': cat['kinds'], '세션': cat['sessions'], 'IP': cat['ips'],
                                     '처음': cat['first'].dt.strftime('%m-%d %H:%M'),
                                     '최근': cat['last'].dt.strftime('%m-%d %H:%M'),
                                     'SHA-256': cat['shasum'].map(D.short_hash), '실물 보관': '미확인'})
                ev = st.dataframe(view, hide_index=True, width='stretch', height=380, on_select='rerun',
                                  selection_mode='single-row', key='f_list')
                picked = cat.iloc[ev.selection.rows[0]] if ev.selection.rows else None
    with right:
        with C.card('파일 관측 기록', help='고른 파일이 관측된 세션입니다. 행을 클릭하면 세션 상세로 이동합니다.'):
            if picked is None:
                st.caption('왼쪽에서 파일을 고르세요.')
            else:
                st.code(f"SHA-256: {picked['shasum'] or '(없음)'}\nURL: {D.defang(picked['url'], mask_ips=False) or '(없음)'}"
                        + (f"\n서로 다른 URL {picked['urls']}개" if picked['urls'] > 1 else ''),
                        language=None, wrap_lines=True)
                obs = D.file_observations(sc, picked['key'])
                v = pd.DataFrame({'시각': obs['time'].dt.strftime('%m-%d %H:%M'), '종류': obs['kind'].map(D.FILE_KINDS),
                                  'IP': obs['src_ip'].map(D.mask_ip), '세션 ID': obs['session_id']})
                ev2 = st.dataframe(v, hide_index=True, width='stretch', height=250, on_select='rerun',
                                   selection_mode='single-row', key='f_obs')
                if ev2.selection.rows:
                    r = obs.iloc[ev2.selection.rows[0]]
                    goto('세션', source=r['source'], session=r['session_id'])
    fails = D.failed_downloads(sc)
    with C.card(f'다운로드 실패 · {len(fails):,}건', help='해시가 없어서 특정 파일과 연결하지 않습니다. 행을 클릭하면 세션 상세로 이동합니다.'):
        if fails.empty:
            st.caption('이 범위에서 다운로드 실패가 없습니다.')
        else:
            v = pd.DataFrame({'시각': fails['time'].dt.strftime('%m-%d %H:%M:%S'), 'IP': fails['src_ip'].map(D.mask_ip),
                              'URL': fails['url'].map(lambda u: D.defang(u)), '오류': fails['error'].map(lambda e: D.defang(e, 80))})
            ev3 = st.dataframe(v, hide_index=True, width='stretch', height=300, on_select='rerun',
                               selection_mode='single-row', key='f_fail',
                               column_config={'URL': st.column_config.TextColumn(width='large')})
            if ev3.selection.rows:
                r = fails.iloc[ev3.selection.rows[0]]
                goto('세션', source=r['source'], session=r['session_id'])
