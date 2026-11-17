"""탐지 분석: 공격은 어디까지 갔고, 어떤 행동이 있었나.

화면은 세 부분만 둔다. ① 한 줄 결론 ② 어디까지 갔나(그래프 하나) ③ 어떤 행동이 있었나(위험한 것부터).
규칙 ID·흐름 대상·규칙에 안 걸린 입력 같은 전문가용 내용은 맨 아래 접힌 영역에 둔다.
표는 내용 높이에 맞추고(안쪽 스크롤 없음), 길면 '더 보기'로 늘린다.
"""
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
              '공격자가 입력한 명령을 보고 어떤 공격을 하려 했는지 정리했습니다. 실제로 성공했는지는 확인하지 않았습니다.')


def more_table(df, key, step=10, **kw):
    """처음 step줄만 보여 주고 '더 보기'로 늘린다. 표 높이는 내용에 맞춘다(안쪽 스크롤 없음)."""
    n = st.session_state.get(key, step)
    ev = st.dataframe(df.head(n), hide_index=True, width='stretch', height='content', key=f'{key}_tbl', **kw)
    if len(df) > n:
        if st.button(f'더 보기 ({len(df) - n:,}개 더 있음)', key=f'{key}_more'):
            st.session_state[key] = n + step * 2
            st.rerun()
    return ev


@st.cache_data(show_spinner='끝까지 이어진 흐름 찾는 중…')
def flows_cached(version, filters):
    return X.linked_flows(C.dataset(), D.scope(C.dataset(), filters))


@st.cache_data(show_spinner='규칙에 안 걸린 입력 정리 중…')
def unmatched_cached(version, filters):
    return X.unmatched_inputs(C.dataset(), D.scope(C.dataset(), filters))


fn, stopped_early, pop = X.funnel(sc, rules)
if pop == 0:
    st.info('이 범위에 명령을 입력한 세션이 없습니다.')
    st.stop()
table = X.danger_table(sc, rules)
full = int(fn.loc[fn['level'] == 4, 'sessions'].iloc[0])
high = table[(table['danger'] == 3) & (table['sessions'] > 0)]
high_sessions = int(sc.hits[sc.hits['rule_id'].isin(set(high['rule_id']))][['source', 'session_id']]
                    .drop_duplicates().shape[0])

# ---------------------------------------------------------------- ① 한 줄 결론
with C.card('한 줄 요약'):
    st.markdown(
        f'<div class="hp-story">명령을 입력한 <b>{pop:,}개</b> 세션 중 '
        f'<b style="color:{C.RED}">{full:,}개</b>가 파일을 내려받아 <b>실행까지</b> 갔습니다. '
        f'<b>{stopped_early / pop * 100:.0f}%</b>({stopped_early:,}개)는 명령창을 열거나 장비를 확인하는 단계에서 멈췄습니다. '
        f'위험도 <b style="color:{C.RED}">높음</b> 행동이 나온 세션은 <b>{high_sessions:,}개</b>입니다.</div>',
        unsafe_allow_html=True)

# ---------------------------------------------------------------- ② 어디까지 갔나
with C.card('공격은 어디까지 갔나',
            help='세션마다 가장 깊이 간 단계를 구해서, 각 단계 "이상"까지 간 세션 수를 셌습니다. '
                 '아래로 갈수록 실제 감염에 가까운 단계입니다.'):
    fn['text'] = fn.apply(lambda r: f"{r['sessions']:,}개 ({r['percent']:.0f}%)", axis=1)
    fn['color'] = [C.CYAN, '#38bdf8', C.AMBER, C.ORANGE, C.RED]
    base = alt.Chart(fn).encode(
        y=alt.Y('name:N', sort=list(fn['name']), title=None,
                axis=alt.Axis(labelLimit=200, domain=False, ticks=False, labelFontSize=13, labelColor='#e6e8eb')),
        x=alt.X('sessions:Q', title=None, axis=None, scale=alt.Scale(domain=[0, pop * 1.6], nice=False)),
        tooltip=[alt.Tooltip('name:N', title='단계'), alt.Tooltip('desc:N', title='뜻'),
                 alt.Tooltip('sessions:Q', title='세션', format=','), alt.Tooltip('percent:Q', title='비율(%)', format='.1f')])
    C.chart((base.mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, height={'band': 0.7})
             .encode(color=alt.Color('color:N', scale=None))
             + base.mark_text(align='left', dx=6, fontSize=13, fontWeight='bold', color='#e6e8eb').encode(text='text:N'))
            .properties(height=56 * len(fn)))
    st.caption(' · '.join(f"**{r.name}**: {r.desc}" for r in fn.itertuples()))

# ---------------------------------------------------------------- ③ 어떤 행동이 있었나
with C.card('어떤 행동이 있었나 (위험한 것부터)', help=X.DANGER_HELP + ' 행을 누르면 아래에 설명과 실제 명령, 관련 세션이 나옵니다.'):
    show_all = st.toggle('한 번도 관측 안 된 행동도 보기', value=False, key='d_all')
    rows = (table if show_all else table[table['sessions'] > 0]).reset_index(drop=True)
    view = pd.DataFrame({'위험도': rows['danger_name'], '무엇을 하려 했나': rows['plain'],
                         '세션': rows['sessions'], '마지막': rows['last'].map(lambda t: C.fmt_dt(t))})
    danger_color = {X.DANGER_NAMES[k]: c for k, c in X.DANGER_COLORS.items()}
    styled = (view.style.map(lambda v: f"color: {danger_color.get(v, C.INK)}; font-weight: 800", subset=['위험도'])
              .map(lambda v: 'color: #f3f4f6', subset=['무엇을 하려 했나'])
              .map(lambda v: f'color: {C.AXIS}', subset=['마지막']))
    ev = st.dataframe(styled, hide_index=True, width='stretch', height='content', on_select='rerun',
                      selection_mode='single-row', key='d_list',
                      column_config={'위험도': st.column_config.TextColumn(width='small'),
                                     '무엇을 하려 했나': st.column_config.TextColumn(width='large'),
                                     '세션': st.column_config.NumberColumn(format='%d', width='small'),
                                     '마지막': st.column_config.TextColumn(width='small')})
    picked = rows.iloc[ev.selection.rows[0]] if ev.selection.rows else None

if picked is not None:
    rid, lv = picked['rule_id'], X.DANGER.get(picked['rule_id'], 1)
    with C.card(picked['plain']):
        color = X.DANGER_COLORS[lv]
        st.markdown(f'<div class="hp-story"><span class="hp-chip on" style="border-color:{color};color:{color}">'
                    f'위험도 {X.DANGER_NAMES[lv]}</span> {escape(X.STEP_WHY.get(picked["step"], ""))}</div>',
                    unsafe_allow_html=True)
        st.caption(f"{picked['sessions']:,}개 세션 · 명령 입력 세션의 {picked['percent']:.1f}% · "
                   f"마지막 {C.fmt_dt(picked['last'], '%Y-%m-%d %H:%M')} KST")
        left, right = st.columns([1.3, 1])
        with left:
            st.markdown('**실제로 입력된 명령** (많이 나온 순)')
            ex = X.rule_examples(ds, sc, rid, limit=30)
            if ex.empty:
                st.caption('한 줄짜리 명령이 아니라 여러 명령의 순서로 판단한 행동입니다. 오른쪽 세션을 열어 흐름을 보세요.'
                           if rid in ('S01', 'S02') else '예시가 없습니다.')
            else:
                more_table(ex.rename(columns={'command': '명령', 'count': '횟수', 'sessions': '세션'}), f'd_ex_{rid}', 5,
                           column_config={'명령': st.column_config.TextColumn(width='large')})
        with right:
            sess = X.rule_sessions(sc, rid)
            st.markdown(f'**이 행동이 나온 세션** · {len(sess):,}개 (누르면 세션 조사로 이동)')
            v = pd.DataFrame({'시각': sess['time'].dt.strftime('%m-%d %H:%M'), 'IP': sess['ip_masked'],
                              '허니팟': sess['source'].map(lambda s: D.SOURCE_NAMES.get(s, s))})
            n = st.session_state.get(f'd_ss_{rid}', 8)
            ev2 = st.dataframe(v.head(n), hide_index=True, width='stretch', height='content', on_select='rerun',
                               selection_mode='single-row', key=f'd_sess_{rid}')
            if len(v) > n and st.button(f'더 보기 ({len(v) - n:,}개 더 있음)', key=f'd_ss_more_{rid}'):
                st.session_state[f'd_ss_{rid}'] = n + 16
                st.rerun()
            if ev2.selection.rows:
                r = sess.iloc[ev2.selection.rows[0]]
                C.open_detail(source=r['source'], session=r['session_id'])
else:
    st.caption('위 목록에서 행동을 누르면 설명, 실제 명령, 관련 세션이 나옵니다.')

# ---------------------------------------------------------------- 전문가용 더 보기
# 접힌 상태에서는 계산하지 않도록 expander 대신 토글을 쓴다 (흐름 찾기가 수 초 걸림)
expert = st.toggle('전문가용 더 보기 — 흐름 대상 파일 · 규칙에 안 걸린 입력 · 규칙 정보', key='d_expert')
if expert:
    version = C._version()
    t1, t2, t3 = st.tabs(['끝까지 이어진 흐름', '규칙에 안 걸린 입력', '규칙 정보'])
    with t1:
        flows, flow_rows = flows_cached(version, f)
        st.caption('S01: 같은 이름의 파일을 내려받고 → 실행 권한을 주고 → 실행한 순서가 한 세션에서 관측됨. '
                   'S02: 숨긴(base64) 코드를 풀어 바로 셸에 넘김. 대상 파일별로 묶었습니다.')
        if flows.empty:
            st.caption('이 범위에서 끝까지 이어진 흐름이 없습니다.')
        else:
            more_table(pd.DataFrame({
                '규칙': flows['rule_id'], '대상 파일': flows['target'].map(lambda t: D.defang(t, 60, False)),
                '세션': flows['sessions'], 'IP': flows['ips'], '처음': flows['first'].dt.strftime('%m-%d %H:%M'),
                '마지막': flows['last'].dt.strftime('%m-%d %H:%M')}), 'd_flows', 10)
    with t2:
        groups, raws, share = unmatched_cached(version, f)
        st.caption(f'어떤 탐지 규칙에도 걸리지 않은 명령 줄이 {share:.0f}%입니다. 명령 모양으로 짐작한 설명이며 탐지 건수에는 '
                   '넣지 않습니다. 자주 나오는데 의미 있는 행동이면 새 규칙 후보입니다.')
        if not groups.empty:
            more_table(pd.DataFrame({'짐작한 행동': groups['text'], '근거': groups['basis'], '명령 줄': groups['lines'],
                                     '세션': groups['sessions'], '형태': groups['kinds']}), 'd_un_g', 8)
            more_table(pd.DataFrame({'명령': raws['command'], '짐작한 행동': raws['text'], '명령 줄': raws['lines'],
                                     '세션': raws['sessions']}), 'd_un_r', 10,
                       column_config={'명령': st.column_config.TextColumn(width='large')})
    with t3:
        st.caption('화면의 쉬운 설명과 실제 탐지 규칙의 대응표입니다. 단계는 규칙 파일(MITRE ATT&CK 기준) 그대로입니다.')
        more_table(pd.DataFrame({'규칙': table['rule_id'], '규칙 이름': table['name'], '위험도': table['danger_name'],
                                 '단계(규칙 파일)': table['stage'], 'ATT&CK': table['attack'], '세션': table['sessions']}),
                   'd_rules', 25)
        cs = X.campaign_stats(sc, rules)
        if not cs.empty and cs['sessions'].sum() > 0:
            st.markdown('**알려진 공격 도구 흔적 (캠페인 규칙)**')
            st.dataframe(pd.DataFrame({'규칙': cs['rule_id'], '이름': cs['name'], '세션': cs['sessions'],
                                       '마지막': cs['last'].map(lambda t: C.fmt_dt(t))}),
                         hide_index=True, width='stretch', height='content')
