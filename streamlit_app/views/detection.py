"""탐지 분석: 어떤 공격 행동이 얼마나, 어떻게 관측됐나 (Q2, Q3)."""
from html import escape

import altair as alt
import pandas as pd
import streamlit as st

import common as C
import data as D
import detect as X
import story as S

C.inject_css()
ds, f = C.dataset(), C.filters()
rules = ds.rules

if not f.sources or not f.protocols:
    st.info('허니팟과 프로토콜을 하나 이상 고르세요.')
    st.stop()
sc = D.scope(ds, f)

scope_kind = '전체 기간' if f.full_period else ('하루' if f.days == 1 else '선택 기간')
period = f'{f.start:%m-%d}' if f.days == 1 else f'{f.start:%m-%d} ~ {f.end:%m-%d}'
C.page_header('Detection', f'{scope_kind} {period} KST',
              '공격자가 입력한 명령에서 어떤 공격 행동이 관측됐는지 봅니다. 입력 관측이며 실행 성공은 확인하지 않았습니다.')


@st.cache_data(show_spinner='연결된 실행 흐름 찾는 중…')
def flows_cached(version, filters):
    return X.linked_flows(C.dataset(), D.scope(C.dataset(), filters))


@st.cache_data(show_spinner='규칙에 안 걸린 입력 정리 중…')
def unmatched_cached(version, filters):
    return X.unmatched_inputs(C.dataset(), D.scope(C.dataset(), filters))


version = C._version()
stats = X.behavior_stats(sc, rules)
steps = X.step_sessions(sc, rules)
pop = X.command_sessions(sc)
detected = int(sc.hits[sc.hits['rule_id'].isin(set(stats['rule_id']))][['source', 'session_id']].drop_duplicates().shape[0])
flows, flow_rows = flows_cached(version, f)
groups, raws, unmatched_share = unmatched_cached(version, f)

# ---------------------------------------------------------------- 1. 요약 숫자
with C.card('DETECTION SUMMARY', help='명령을 입력한 세션 기준입니다. 한 세션에서 여러 행동이 동시에 관측될 수 있습니다.'):
    cols = st.columns(5)
    with cols[0]:
        C.kpi('명령 입력 세션', f'{pop:,}', C.CYAN, '탐지 비율의 분모')
    with cols[1]:
        C.kpi('행동이 탐지된 세션', f'{detected:,}', C.LIME, f'{detected / pop * 100:.0f}%' if pop else '')
    with cols[2]:
        seen = int((stats['sessions'] > 0).sum())
        C.kpi('관측된 행동 종류', f'{seen} / {len(stats)}', C.VIOLET, '탐지 규칙 기준')
    with cols[3]:
        linked = int(flow_rows[['source', 'session_id']].drop_duplicates().shape[0]) if len(flow_rows) else 0
        C.kpi('끝까지 이어진 흐름', f'{linked:,}', C.RED, '다운로드→실행 / 디코딩→실행')
    with cols[4]:
        C.kpi('규칙에 안 걸린 입력', f'{unmatched_share:.0f}%', C.AMBER, '명령 줄 기준')

if pop == 0:
    st.info('이 범위에 명령을 입력한 세션이 없습니다.')
    st.stop()

# ---------------------------------------------------------------- 2. 단계별 + 추이
left, right = st.columns([1, 1.3])
with left:
    with C.card('공격 단계별 세션', height=360,
                help='각 단계의 행동이 하나라도 관측된 세션 수입니다. 위에서 아래로 공격이 진행되는 순서입니다.'):
        steps['text'] = steps.apply(lambda r: f"{r['sessions']:,} ({r['percent']:.0f}%)", axis=1)
        steps['color'] = steps['step'].map(S.STEP_COLORS)
        base = alt.Chart(steps).encode(
            y=alt.Y('name:N', sort=list(steps['name']), title=None, axis=alt.Axis(labelLimit=200, domain=False, ticks=False)),
            x=alt.X('sessions:Q', title=None, axis=alt.Axis(grid=True, domain=False, ticks=False, format='~s'),
                    scale=alt.Scale(domain=[0, max(1, steps['sessions'].max()) * 1.35], nice=False)),
            tooltip=[alt.Tooltip('name:N', title='단계'), alt.Tooltip('sessions:Q', title='세션', format=','),
                     alt.Tooltip('percent:Q', title='명령 세션 대비(%)', format='.1f')])
        C.chart((base.mark_bar(cornerRadiusTopRight=3, cornerRadiusBottomRight=3, height={'band': 0.62}).encode(
                    color=alt.Color('color:N', scale=None))
                 + base.mark_text(align='left', dx=5, fontSize=11, color='#cbd2d9').encode(text='text:N'))
                .properties(height=280))
with right:
    daily = X.step_daily(sc, rules)
    with C.card('일별 탐지 추이 (명령창 열기 제외)', height=360,
                help='단계별로 그날 처음 탐지된 세션 수입니다. 거의 모든 봇에 나오는 "명령창 열기"는 빼고 봅니다.'):
        if daily.empty:
            st.caption('이 범위에 탐지가 없습니다.')
        else:
            names_ = [S.STEPS[k][0] for k in S.STEPS if S.STEPS[k][0] in set(daily['name'])]
            C.chart(alt.Chart(daily).mark_bar().encode(
                x=alt.X('day:T', title=None, axis=alt.Axis(format='%m-%d', labelAngle=0, grid=False)),
                y=alt.Y('sessions:Q', title=None, stack=True, axis=alt.Axis(domain=False, ticks=False, format='~s')),
                color=alt.Color('name:N', title=None, legend=alt.Legend(orient='bottom', columns=4),
                                scale=alt.Scale(domain=names_, range=[S.STEP_COLORS[k] for k in S.STEPS
                                                                     if S.STEPS[k][0] in names_])),
                tooltip=[alt.Tooltip('day:T', title='날짜', format='%m-%d'), alt.Tooltip('name:N', title='단계'),
                         alt.Tooltip('sessions:Q', title='세션', format=',')]).properties(height=260))

# ---------------------------------------------------------------- 3. 행동 목록 + 상세
with C.card('공격 행동 목록', help='행을 클릭하면 아래에 이 행동의 설명, 실제 명령 예시, 관련 세션이 나옵니다. '
                              '빨간 점은 우선 확인할 행동입니다.'):
    only_seen = st.toggle('관측된 행동만', value=True, key='d_seen')
    shown = stats[stats['sessions'] > 0] if only_seen else stats
    shown = shown.reset_index(drop=True)
    view = pd.DataFrame({'': shown['priority'].map({True: '●', False: ''}),
                         '단계': shown['step_name'], '무엇을 하려 했나': shown['plain'],
                         '세션': shown['sessions'], '명령 세션 대비': shown['percent'],
                         '마지막 탐지': shown['last'].map(lambda t: C.fmt_dt(t)), '규칙': shown['rule_id']})
    color_of = {S.STEPS[k][0]: c for k, c in S.STEP_COLORS.items()}
    styled = (view.style.map(lambda v: f'color: {C.RED}', subset=[''])
              .map(lambda v: f"color: {color_of.get(v, C.INK)}; font-weight: 700", subset=['단계'])
              .map(lambda v: 'color: #f3f4f6', subset=['무엇을 하려 했나'])
              .map(lambda v: f'color: {C.AXIS}', subset=['마지막 탐지', '규칙']))
    ev = st.dataframe(styled, hide_index=True, width='stretch', height=min(460, 38 + 35 * len(view)),
                      on_select='rerun', selection_mode='single-row', key='d_rules',
                      column_config={'': st.column_config.TextColumn(width=30),
                                     '세션': st.column_config.NumberColumn(format='%d'),
                                     '명령 세션 대비': st.column_config.ProgressColumn(format='%.1f%%', min_value=0,
                                                                                 max_value=100),
                                     '무엇을 하려 했나': st.column_config.TextColumn(width='large')})
    picked = shown.iloc[ev.selection.rows[0]] if ev.selection.rows else None

if picked is not None:
    rid = picked['rule_id']
    left, right = st.columns([1.2, 1])
    with left:
        with C.card(f"{picked['plain']}"):
            color = S.STEP_COLORS[picked['step']]
            st.markdown(
                f'<div class="hp-story">'
                f'<span class="hp-chip on" style="border-color:{color};color:{color}">{escape(picked["step_name"])}</span> '
                f'{escape(X.STEP_WHY.get(picked["step"], ""))}</div>'
                + (f'<div class="hp-danger">⚠ 우선 확인할 행동입니다: {escape(D.PRIORITY_RULES[rid])}</div>'
                   if rid in D.PRIORITY_RULES else ''), unsafe_allow_html=True)
            st.caption(f"{picked['sessions']:,}개 세션 (명령 입력 세션의 {picked['percent']:.1f}%) · "
                       f"마지막 탐지 {C.fmt_dt(picked['last'], '%Y-%m-%d %H:%M')} KST")
            ex = X.rule_examples(ds, sc, rid)
            st.markdown('**실제로 걸린 입력** (많이 나온 순, 원문)')
            if ex.empty:
                st.caption('예시가 없습니다.' + (' 이 규칙은 여러 줄의 순서로 판단하는 흐름 규칙이라 아래 "연결된 실행 흐름"을 보세요.'
                                             if rid in ('S01', 'S02') else ''))
            else:
                st.dataframe(ex.rename(columns={'command': '입력 원문', 'count': '횟수', 'sessions': '세션'}),
                             hide_index=True, width='stretch', height=min(320, 38 + 35 * len(ex)),
                             column_config={'입력 원문': st.column_config.TextColumn(width='large')})
            with st.expander('전문가용 정보'):
                st.markdown(f"- 규칙 `{rid}` {escape(picked['name'])}\n- 단계(규칙 파일): {escape(picked['stage'])}"
                            f"\n- MITRE ATT&CK: `{escape(picked['attack'])}`")
                if picked['note']:
                    st.caption(picked['note'])
    with right:
        sess = X.rule_sessions(sc, rid)
        with C.card(f'관련 세션 · {len(sess):,}개', help='행을 클릭하면 세션 조사 화면에서 이 세션을 엽니다.'):
            v = pd.DataFrame({'탐지 (KST)': sess['time'].dt.strftime('%m-%d %H:%M'), 'IP': sess['ip_masked'],
                              '프로토콜': sess['protocol'], '명령 수': sess['n_commands'], '세션 ID': sess['session_id']})
            ev2 = st.dataframe(v.head(500), hide_index=True, width='stretch', height=420, on_select='rerun',
                               selection_mode='single-row', key=f'd_sess_{rid}')
            if ev2.selection.rows:
                r = sess.iloc[ev2.selection.rows[0]]
                C.open_detail(source=r['source'], session=r['session_id'])
else:
    st.caption('위 목록에서 행동을 고르면 설명과 실제 명령, 관련 세션이 나옵니다.')

# ---------------------------------------------------------------- 4. 연결된 실행 흐름
left, right = st.columns([1, 1])
with left:
    with C.card('끝까지 이어진 실행 흐름', height=430,
                help='S01: 같은 이름의 파일을 내려받고 → 실행 권한을 주고 → 실행한 순서가 한 세션에서 관측됨. '
                     'S02: 숨긴(base64) 코드를 풀어 바로 셸·인터프리터에 넘김. 대상별로 묶었습니다. 행을 클릭하면 세션 목록이 나옵니다.'):
        if flows.empty:
            st.caption('이 범위에서 끝까지 이어진 흐름이 없습니다.')
            fpick = None
        else:
            fv = pd.DataFrame({'흐름': flows['rule_id'].map({'S01': '내려받아 실행', 'S02': '숨긴 코드 실행'}),
                               '대상 파일': flows['target'].map(lambda t: D.defang(t, 60, False)),
                               '세션': flows['sessions'], 'IP': flows['ips'],
                               '처음': flows['first'].dt.strftime('%m-%d %H:%M'),
                               '마지막': flows['last'].dt.strftime('%m-%d %H:%M')})
            evf = st.dataframe(fv, hide_index=True, width='stretch', height=340, on_select='rerun',
                               selection_mode='single-row', key='d_flows')
            fpick = flows.iloc[evf.selection.rows[0]] if evf.selection.rows else None
with right:
    with C.card('흐름이 관측된 세션', height=430, help='행을 클릭하면 세션 조사 화면에서 이 세션을 엽니다.'):
        if fpick is None:
            st.caption('왼쪽에서 흐름을 고르세요.')
        else:
            fs = flow_rows[(flow_rows['rule_id'] == fpick['rule_id']) & (flow_rows['target'] == fpick['target'])]
            fs = fs.sort_values('time', ascending=False).reset_index(drop=True)
            v = pd.DataFrame({'탐지 (KST)': fs['time'].dt.strftime('%m-%d %H:%M'), 'IP': fs['src_ip'].map(D.mask_ip),
                              '허니팟': fs['source'].map(lambda s: D.SOURCE_NAMES.get(s, s)), '세션 ID': fs['session_id']})
            evs = st.dataframe(v, hide_index=True, width='stretch', height=340, on_select='rerun',
                               selection_mode='single-row', key='d_flow_sess')
            if evs.selection.rows:
                r = fs.iloc[evs.selection.rows[0]]
                C.open_detail(source=r['source'], session=r['session_id'])

# ---------------------------------------------------------------- 5. 규칙에 안 걸린 입력
with C.card(f'규칙에 안 걸린 입력 · 명령 줄의 {unmatched_share:.0f}%',
            help='어떤 탐지 규칙에도 걸리지 않은 명령입니다. 명령 모양으로 짐작한 설명(입력 기반 추정)으로 묶었습니다. '
                 '자주 나오는데 의미 있는 행동이라면 새 규칙 후보입니다. 탐지 건수에는 들어가지 않습니다.'):
    if groups.empty:
        st.caption('규칙에 안 걸린 입력이 없습니다.')
    else:
        left, right = st.columns([1, 1.3])
        with left:
            gv = pd.DataFrame({'짐작한 행동': groups['text'], '단계': groups['step_name'], '근거': groups['basis'],
                               '명령 줄': groups['lines'], '세션': groups['sessions'], '형태': groups['kinds']})
            st.dataframe(C.style_commands(gv.rename(columns={'짐작한 행동': '행동 설명'})), hide_index=True,
                         width='stretch', height=min(330, 38 + 35 * len(gv)))
        with right:
            rv = pd.DataFrame({'명령': raws['command'], '행동 설명': raws['text'], '근거': raws['basis'],
                               '명령 줄': raws['lines'], '세션': raws['sessions']})
            st.dataframe(C.style_commands(rv), hide_index=True, width='stretch', height=330,
                         column_config={'명령': st.column_config.TextColumn(width='large')})

cs = X.campaign_stats(sc, rules)
if not cs.empty and cs['sessions'].sum() > 0:
    with st.expander('알려진 공격 도구 흔적 (캠페인 규칙)'):
        st.caption('특정 공격 도구·집단에서 자주 보이는 이름이나 파일입니다. 공격 단계가 아니라 "누가 썼나"의 단서입니다.')
        st.dataframe(pd.DataFrame({'규칙': cs['rule_id'], '이름': cs['name'], '세션': cs['sessions'],
                                   '마지막': cs['last'].map(lambda t: C.fmt_dt(t))}), hide_index=True, width='stretch')
