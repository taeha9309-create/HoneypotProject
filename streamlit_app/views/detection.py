"""탐지 분석: 어떤 공격 행동이 관측됐고, 어디까지 진행됐나 (관리자·분석가용).

배치: ① KPI 한 줄 ② 진행 단계(왼쪽) + 위험도 순 행동 목록(오른쪽)
     ③ 고른 행동의 상세(설명·규칙 정보 / 실제 입력 / 세션) ④ 하단 분석(흐름 대상 · 규칙 미해당 입력 · 캠페인)
표는 내용 높이에 맞추고(안쪽 스크롤 없음), 길면 '더 보기'로 늘린다.
"""
from html import escape

import altair as alt
import pandas as pd
import streamlit as st

import common as C
import data as D
import detect as X

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
              '명령 입력에서 관측된 공격 행동 (시그니처 규칙 기준). 입력 관측이며 실행 성공은 확인하지 않았습니다.')


def compact(df, key, step=10, **kw):
    """처음 step줄만, 높이는 내용에 맞춤. 남으면 '더 보기'."""
    n = st.session_state.get(key, step)
    ev = st.dataframe(df.head(n), hide_index=True, width='stretch', height='content', key=f'{key}_tbl', **kw)
    if len(df) > n and st.button(f'더 보기 · {len(df) - n:,}개', key=f'{key}_more', type='tertiary'):
        st.session_state[key] = n + step * 2
        st.rerun()
    return ev


@st.cache_data(show_spinner='S01·S02 흐름 대상 찾는 중…')
def flows_cached(version, filters):
    return X.linked_flows(C.dataset(), D.scope(C.dataset(), filters))


@st.cache_data(show_spinner='규칙 미해당 입력 정리 중…')
def unmatched_cached(version, filters):
    return X.unmatched_inputs(C.dataset(), D.scope(C.dataset(), filters))


fn, stopped_early, pop = X.funnel(sc, rules)
if pop == 0:
    st.info('이 범위에 명령을 입력한 세션이 없습니다.')
    st.stop()
table = X.danger_table(sc, rules)
behavior_ids = set(table['rule_id'])
detected = int(sc.hits[sc.hits['rule_id'].isin(behavior_ids)][['source', 'session_id']].drop_duplicates().shape[0])
high_ids = set(table.loc[table['danger'] == 3, 'rule_id'])
high_sessions = int(sc.hits[sc.hits['rule_id'].isin(high_ids)][['source', 'session_id']].drop_duplicates().shape[0])
full = int(fn.loc[fn['level'] == 4, 'sessions'].iloc[0])

# ---------------------------------------------------------------- ① KPI
with C.card('DETECTION SUMMARY', help='분모는 조회 범위에서 명령을 입력한 세션입니다. ' + X.DANGER_HELP):
    cols = st.columns(5)
    kp = [('명령 입력 세션', f'{pop:,}', C.CYAN, ''),
          ('규칙 탐지 세션', f'{detected:,}', C.LIME, f'{detected / pop * 100:.0f}%'),
          ('위험도 높음 세션', f'{high_sessions:,}', C.RED, f'{high_sessions / pop * 100:.1f}%'),
          ('끝까지 실행 (S01·S02)', f'{full:,}', C.ORANGE, f'{full / pop * 100:.1f}%'),
          ('초기 단계에서 멈춤', f'{stopped_early / pop * 100:.0f}%', '#9aa3ad', f'{stopped_early:,}개 · 셸 진입·정보 수집까지')]
    for col, (lab, val, color, sub) in zip(cols, kp):
        with col:
            C.kpi(lab, val, color, sub)

# ---------------------------------------------------------------- ② 진행 단계 + 행동 목록
left, right = st.columns([1, 1.9])
with left:
    with C.card('진행 단계', help='세션별로 가장 깊이 간 단계를 구해 각 단계 "이상"까지 간 세션 수를 셌습니다. '
                                 + ' / '.join(f'{n}: {d}' for _, n, d in X.FUNNEL)):
        fn['text'] = fn.apply(lambda r: f"{r['sessions']:,} · {r['percent']:.0f}%", axis=1)
        fn['color'] = [C.CYAN, '#38bdf8', C.AMBER, C.ORANGE, C.RED]
        base = alt.Chart(fn).encode(
            y=alt.Y('name:N', sort=list(fn['name']), title=None, axis=alt.Axis(labelLimit=140, domain=False, ticks=False)),
            x=alt.X('sessions:Q', title=None, axis=None, scale=alt.Scale(domain=[0, pop * 1.55], nice=False)),
            tooltip=[alt.Tooltip('name:N', title='단계'), alt.Tooltip('desc:N', title='뜻'),
                     alt.Tooltip('sessions:Q', title='세션', format=','),
                     alt.Tooltip('percent:Q', title='비율(%)', format='.1f')])
        C.chart((base.mark_bar(cornerRadiusTopRight=3, cornerRadiusBottomRight=3, height={'band': 0.6})
                 .encode(color=alt.Color('color:N', scale=None))
                 + base.mark_text(align='left', dx=5, fontSize=11, color='#cbd2d9').encode(text='text:N'))
                .properties(height=32 * len(fn)))
        daily = X.step_daily(sc, rules, exclude_steps=('shell', 'recon'))
        if not daily.empty:
            per_day = daily.groupby('day')['sessions'].sum().reset_index()
            st.caption('일별 · 파일 들여오기 이상 단계가 탐지된 세션')
            C.chart(alt.Chart(per_day).mark_bar(color=C.ORANGE, cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
                x=alt.X('day:T', title=None, axis=alt.Axis(format='%m-%d', labelAngle=0, grid=False, labelFontSize=10)),
                y=alt.Y('sessions:Q', title=None, axis=alt.Axis(domain=False, ticks=False, format='~s', tickCount=3)),
                tooltip=[alt.Tooltip('day:T', title='날짜', format='%m-%d'),
                         alt.Tooltip('sessions:Q', title='세션', format=',')]).properties(height=110))
with right:
    with C.card('행동 목록 · 위험도 순', help=X.DANGER_HELP + ' 행을 누르면 아래에 상세가 열립니다.'):
        show_all = st.toggle('미관측 규칙 포함', value=False, key='d_all')
        rows = (table if show_all else table[table['sessions'] > 0]).reset_index(drop=True)
        view = pd.DataFrame({'위험': rows['danger_name'], '규칙': rows['rule_id'], '행동': rows['plain'],
                             '세션': rows['sessions'], '비율': rows['percent'], 'ATT&CK': rows['attack'],
                             '마지막': rows['last'].map(lambda t: C.fmt_dt(t))})
        danger_color = {X.DANGER_NAMES[k]: c for k, c in X.DANGER_COLORS.items()}
        styled = (view.style.map(lambda v: f"color: {danger_color.get(v, C.INK)}; font-weight: 800", subset=['위험'])
                  .map(lambda v: f'color: {C.CYAN}', subset=['규칙'])
                  .map(lambda v: f'color: {C.AXIS}', subset=['ATT&CK', '마지막']))
        ev = st.dataframe(styled, hide_index=True, width='stretch', height='content', on_select='rerun',
                          selection_mode='single-row', key='d_list',
                          column_config={'위험': st.column_config.TextColumn(width=48),
                                         '규칙': st.column_config.TextColumn(width=48),
                                         '행동': st.column_config.TextColumn(width='large'),
                                         '세션': st.column_config.NumberColumn(format='%d', width=60),
                                         '비율': st.column_config.ProgressColumn(format='%.1f%%', min_value=0,
                                                                               max_value=100, width=90),
                                         'ATT&CK': st.column_config.TextColumn(width=80),
                                         '마지막': st.column_config.TextColumn(width=90)})
        picked = rows.iloc[ev.selection.rows[0]] if ev.selection.rows else None

# ---------------------------------------------------------------- ③ 고른 행동 상세
if picked is not None:
    rid, lv = picked['rule_id'], X.DANGER.get(picked['rule_id'], 1)
    with C.card(f"{rid} · {picked['name']}"):
        a, b, c = st.columns([1, 1.5, 1.1])
        with a:
            color = X.DANGER_COLORS[lv]
            st.markdown(f'<span class="hp-chip on" style="border-color:{color};color:{color}">위험도 '
                        f'{X.DANGER_NAMES[lv]}</span>', unsafe_allow_html=True)
            st.markdown(f"**{escape(picked['plain'])}**")
            st.caption(X.STEP_WHY.get(picked['step'], ''))
            st.caption(f"세션 {picked['sessions']:,} ({picked['percent']:.1f}%) · 일치 {picked['hits']:,}회 · "
                       f"마지막 {C.fmt_dt(picked['last'], '%m-%d %H:%M')}")
            st.caption(f"규칙 단계: {picked['stage']} · ATT&CK {picked['attack']}")
            if picked['note']:
                st.caption(f"규칙 메모: {picked['note']}")
        with b:
            st.markdown('**일치한 입력** · 많이 나온 순')
            ex = X.rule_examples(ds, sc, rid, limit=40)
            if ex.empty:
                st.caption('여러 명령의 순서로 판단하는 규칙입니다. 아래 "흐름 대상"과 세션 상세를 보세요.'
                           if rid in ('S01', 'S02') else '예시가 없습니다.')
            else:
                compact(ex.rename(columns={'command': '명령', 'count': '횟수', 'sessions': '세션'}), f'd_ex_{rid}', 6,
                        column_config={'명령': st.column_config.TextColumn(width='large'),
                                       '횟수': st.column_config.NumberColumn(width=50),
                                       '세션': st.column_config.NumberColumn(width=50)})
        with c:
            sess = X.rule_sessions(sc, rid)
            st.markdown(f'**세션** · {len(sess):,}개 · 누르면 세션 조사')
            v = pd.DataFrame({'시각': sess['time'].dt.strftime('%m-%d %H:%M'), 'IP': sess['ip_masked'],
                              '허니팟': sess['source'].map(lambda s: D.SOURCE_NAMES.get(s, s))})
            n = st.session_state.get(f'd_ss_{rid}', 6)
            ev2 = st.dataframe(v.head(n), hide_index=True, width='stretch', height='content', on_select='rerun',
                               selection_mode='single-row', key=f'd_sess_{rid}')
            if len(v) > n and st.button(f'더 보기 · {len(v) - n:,}개', key=f'd_ss_more_{rid}', type='tertiary'):
                st.session_state[f'd_ss_{rid}'] = n + 12
                st.rerun()
            if ev2.selection.rows:
                r = sess.iloc[ev2.selection.rows[0]]
                C.open_detail(source=r['source'], session=r['session_id'])

# ---------------------------------------------------------------- ④ 하단 분석
with C.card('추가 분석'):
    pick = st.segmented_control('보기', ['S01·S02 흐름 대상', '규칙 미해당 입력', '캠페인 흔적'],
                                default='S01·S02 흐름 대상', key='d_bottom', label_visibility='collapsed') \
        or 'S01·S02 흐름 대상'
    version = C._version()
    if pick == 'S01·S02 흐름 대상':
        flows, _ = flows_cached(version, f)
        st.caption('S01: 같은 파일을 내려받고 → 실행 권한 → 실행. S02: base64 디코딩 결과를 인터프리터로 직접 전달. 대상별 집계.')
        if flows.empty:
            st.caption('이 범위에서 관측된 흐름이 없습니다.')
        else:
            compact(pd.DataFrame({
                '규칙': flows['rule_id'], '대상': flows['target'].map(lambda t: D.defang(t, 60, False)),
                '세션': flows['sessions'], 'IP': flows['ips'], '처음': flows['first'].dt.strftime('%m-%d %H:%M'),
                '마지막': flows['last'].dt.strftime('%m-%d %H:%M')}), 'd_flows', 8)
    elif pick == '규칙 미해당 입력':
        groups, raws, share = unmatched_cached(version, f)
        st.caption(f'어떤 탐지 규칙에도 걸리지 않은 명령 줄 {share:.0f}%. 입력 형태 기반 추정으로 묶었으며 탐지 건수에는 포함하지 '
                   '않습니다. 규칙 추가 후보 검토용입니다.')
        if not groups.empty:
            g1, g2 = st.columns([1, 1.4])
            with g1:
                compact(pd.DataFrame({'추정': groups['text'], '근거': groups['basis'], '줄': groups['lines'],
                                      '세션': groups['sessions'], '형태': groups['kinds']}), 'd_un_g', 8)
            with g2:
                compact(pd.DataFrame({'명령': raws['command'], '추정': raws['text'], '줄': raws['lines'],
                                      '세션': raws['sessions']}), 'd_un_r', 8,
                        column_config={'명령': st.column_config.TextColumn(width='large')})
    else:
        cs = X.campaign_stats(sc, rules)
        st.caption('특정 공격 도구·집단에서 쓰는 고유 문자열·파일명 규칙(C01~). 공격 단계가 아니라 출처 단서입니다.')
        compact(pd.DataFrame({'규칙': cs['rule_id'], '이름': cs['name'], '세션': cs['sessions'],
                              '마지막': cs['last'].map(lambda t: C.fmt_dt(t))}), 'd_camp', 10)
