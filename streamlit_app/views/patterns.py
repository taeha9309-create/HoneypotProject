"""패턴 분석(ML): 비슷한 공격은 어떻게 반복되나.

명령 시퀀스를 정규화해 TF-IDF → SVD → HDBSCAN(팀의 ml/cluster.py)으로 묶은 결과를 보여 준다.
서울+시드니를 합친 대시보드 전용 학습(build_ml.py)이며, 군집 번호는 이 학습에서만 의미가 있다.
"""
from html import escape

import altair as alt
import pandas as pd
import streamlit as st

import common as C
import data as D
import detect as X
import patterns as P

C.inject_css()
ds, f = C.dataset(), C.filters()
rules = ds.rules
names = C.country_names()

if not f.sources or not f.protocols:
    st.info('허니팟과 프로토콜을 하나 이상 고르세요.')
    st.stop()
sc = D.scope(ds, f)

scope_kind = '전체 기간' if f.full_period else ('하루' if f.days == 1 else '선택 기간')
period = f'{f.start:%m-%d}' if f.days == 1 else f'{f.start:%m-%d} ~ {f.end:%m-%d}'
C.page_header('Patterns', f'{scope_kind} {period} KST',
              '명령 흐름이 비슷한 세션을 자동으로 묶었습니다(머신러닝 군집). 같은 군집 = 같은 봇·도구일 가능성이 높습니다.')


@st.cache_resource(show_spinner='군집 결과 불러오는 중…')
def ml_data(version):
    return P.load(C.DATA_DIR)


ml_version = (C.DATA_DIR / 'ml.db').stat().st_mtime_ns if (C.DATA_DIR / 'ml.db').exists() else 0
ml = ml_data(ml_version)
if ml is None:
    st.info('군집 결과(ml.db)가 없습니다. 아래 명령으로 학습한 뒤 새로고침하세요.')
    st.code('python streamlit_app/build_ml.py', language='bash')
    st.stop()


@st.cache_data(show_spinner='군집 정리 중…')
def table_cached(version, ml_version, filters):
    d = C.dataset()
    return P.cluster_table(ml_data(ml_version), d, D.scope(d, filters), d.rules)


ct = table_cached(C._version(), ml_version, f)
if ct.empty:
    st.info('이 범위에 군집 결과가 있는 세션이 없습니다.')
    st.stop()

# ---------------------------------------------------------------- 요약
real = ct[ct['cluster_id'] >= 0]
noise = int(ct.loc[ct['cluster_id'] == -1, 'sessions'].sum())
total = int(ct['sessions'].sum())
top3 = real.sort_values('sessions', ascending=False).head(3)['sessions'].sum()
nv = P.novel_view(ml, sc)
with C.card('PATTERN SUMMARY', help=f"학습: {ml.meta.get('trained_at', '?')} UTC · {ml.meta.get('params', '')} · "
                                    '서울+시드니 합본. 대상은 명령을 입력한 세션(테스트 IP 제외). 노이즈 = 어느 군집에도 안 맞는 세션.'):
    cols = st.columns(5)
    by_proto = real.groupby('protocol').size()
    kp = [('군집 대상 세션', f'{total:,}', C.CYAN, '명령을 입력한 세션'),
          ('군집 수', f'{len(real):,}', C.VIOLET, ' · '.join(f'{p.upper()} {n}' for p, n in by_proto.items())),
          ('상위 3개 군집 비중', f'{top3 / max(total, 1) * 100:.0f}%', C.AMBER, '소수의 봇이 대부분을 차지'),
          ('노이즈 세션', f'{noise:,}', '#9aa3ad', f'{noise / max(total, 1) * 100:.1f}% · 드문 공격·스캐너'),
          ('신규 패턴 후보', f'{len(nv):,}종', C.RED, f"{int(nv['sessions'].sum()) if len(nv) else 0}세션 · 노이즈·이상치")]
    for col, (lab, val, color, sub) in zip(cols, kp):
        with col:
            C.kpi(lab, val, color, sub)

# ---------------------------------------------------------------- 군집 지도 + 목록
proto_opts = [p for p in ('telnet', 'ssh') if p in set(ct['protocol'])]
proto = st.segmented_control('프로토콜', proto_opts, default=proto_opts[0], key='p_proto',
                             format_func=str.upper, label_visibility='collapsed') or proto_opts[0]
cp = ct[ct['protocol'] == proto].reset_index(drop=True)
palette = ['#22d3ee', '#fb923c', '#c084fc', '#bef264', '#f472b6', '#fbbf24', '#38bdf8', '#34d399']
big = cp[cp['cluster_id'] >= 0].head(len(palette))
color_of = {r.label: palette[i] for i, r in enumerate(big.itertuples())}

left, right = st.columns([1, 1.25])
with left:
    with C.card('군집 지도', help='점 하나 = 정규화한 명령 흐름 하나, 크기 = 세션 수. 가까운 점일수록 명령 흐름이 비슷합니다. '
                                 '색은 큰 군집 8개, 회색은 나머지·노이즈입니다.'):
        pts = P.points_in_scope(ml, sc)
        pts = pts[pts['protocol'] == proto].copy()
        lab = dict(zip(cp['cluster_id'], cp['label']))
        pts['label'] = pts['cluster_id'].map(lambda c: lab.get(c, f'{proto.upper()} {c}'))
        pts['group'] = pts['label'].map(lambda l: l if l in color_of else '기타·노이즈')
        pts['preview'] = pts['preview'].map(lambda t: D.defang(t, 160))
        domain = list(color_of) + ['기타·노이즈']
        C.chart(alt.Chart(pts).mark_circle(opacity=0.85, stroke='#0f1317', strokeWidth=0.6).encode(
            x=alt.X('x:Q', title=None, axis=None), y=alt.Y('y:Q', title=None, axis=None),
            size=alt.Size('in_scope:Q', legend=None, scale=alt.Scale(type='sqrt', range=[25, 1400])),
            color=alt.Color('group:N', title=None, scale=alt.Scale(domain=domain, range=list(color_of.values()) + ['#4b5563']),
                            legend=alt.Legend(orient='bottom', columns=3, labelLimit=160)),
            tooltip=[alt.Tooltip('label:N', title='군집'), alt.Tooltip('in_scope:Q', title='세션', format=','),
                     alt.Tooltip('preview:N', title='명령 흐름')]).properties(height=330))
with right:
    with C.card(f'군집 목록 · {proto.upper()}', help='세션 수 순. 이름은 대표 명령의 표식(busybox 이름, 숨김 파일 등)과 군집 세션 절반 '
                                                    '이상에서 관측된 공격 단계로 자동으로 붙였습니다. 행을 누르면 아래에 상세가 나옵니다.'):
        view = pd.DataFrame({'군집': cp['label'], '이름': cp['name'], '세션': cp['sessions'], 'IP': cp['ips'],
                             '서울': cp['seoul'], '시드니': cp['syd'], '활동일': cp['days'],
                             '위험': cp['danger'].map(lambda d: X.DANGER_NAMES.get(d, '-'))})
        danger_color = {X.DANGER_NAMES[k]: c for k, c in X.DANGER_COLORS.items()}
        styled = (view.style.map(lambda v: f"color: {color_of.get(v, '#9aa3ad')}; font-weight: 800", subset=['군집'])
                  .map(lambda v: f"color: {danger_color.get(v, '#4b5563')}; font-weight: 700", subset=['위험']))
        ev = st.dataframe(styled, hide_index=True, width='stretch', height='content', on_select='rerun',
                          selection_mode='single-row', key=f'p_list_{proto}',
                          column_config={'이름': st.column_config.TextColumn(width='large'),
                                         '세션': st.column_config.ProgressColumn(format='%d', min_value=0,
                                                                               max_value=C.max_or_one(cp['sessions']))})
        picked = cp.iloc[ev.selection.rows[0]] if ev.selection.rows else cp.iloc[0]

# ---------------------------------------------------------------- 군집 상세
cid = int(picked['cluster_id'])
with C.card(f"{picked['label']} · {picked['name']}"):
    st.caption(f"세션 {picked['sessions']:,} · IP {picked['ips']:,} (1위 IP 비중 {picked['top_ip_share']:.0f}%) · "
               f"서울 {picked['seoul']:,} / 시드니 {picked['syd']:,} · 활동일 {picked['days']}일 · "
               f"{C.fmt_dt(picked['first'])} ~ {C.fmt_dt(picked['last'])} KST"
               + (f" · 대표 흐름과 같은 세션 {picked['rep_share'] * 100:.0f}%" if picked['rep_share'] is not None else ''))
    a, b, c = st.columns([1.4, 1, 1])
    with a:
        st.markdown('**대표 명령 흐름** (정규화: 숫자·IP·URL·임의 파일명 치환)')
        st.code(D.defang(picked['representative'], 1500).replace(' ; ', '\n'), language=None, wrap_lines=True, height=260)
        if picked['top_commands']:
            st.caption('자주 나온 명령: ' + D.defang(picked['top_commands'], 300))
    with b:
        st.markdown('**관측된 행동** (군집 세션 대비)')
        cr = P.cluster_rules(ml, sc, rules, proto, cid).head(8)
        if cr.empty:
            st.caption('탐지 규칙에 걸린 행동이 없습니다.')
        else:
            C.bar_list([(r.plain, r.percent, f'{r.percent:.0f}%', X.DANGER_COLORS.get(r.danger, '#7d8590'))
                        for r in cr.itertuples()])
        sv = P.cluster_servers(ds, sc, ml, proto, cid)
        if len(sv):
            st.markdown('**쓴 다운로드 서버**')
            st.dataframe(pd.DataFrame({'서버': sv['host'], '세션': sv['sessions'], '종류': sv['kind']}),
                         hide_index=True, width='stretch', height='content')
    with c:
        st.markdown('**일별 세션** (허니팟별)')
        dd = P.cluster_daily(ml, sc, proto, cid)
        groups_ = [n for n in C.SOURCE_COLORS if n in set(dd['name'])]
        C.chart(alt.Chart(dd).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
            x=alt.X('day:T', title=None, axis=alt.Axis(format='%m-%d', labelAngle=0, grid=False, labelFontSize=10)),
            y=alt.Y('sessions:Q', title=None, stack=True, axis=alt.Axis(domain=False, ticks=False, format='~s', tickCount=3)),
            color=alt.Color('name:N', title=None, scale=alt.Scale(domain=groups_, range=[C.SOURCE_COLORS[n] for n in groups_]),
                            legend=alt.Legend(orient='top')),
            tooltip=[alt.Tooltip('day:T', title='날짜', format='%m-%d'), alt.Tooltip('name:N', title='허니팟'),
                     alt.Tooltip('sessions:Q', title='세션', format=',')]).properties(height=150))
        st.markdown('**세션** (누르면 세션 조사)')
        ss = P.cluster_sessions(ml, sc, proto, cid)
        ev2 = C.compact(pd.DataFrame({'시각': C.dtfmt(ss['start'], '%m-%d %H:%M'), 'IP': ss['ip_masked'],
                                      '허니팟': ss['source'].map(lambda s: D.SOURCE_NAMES.get(s, s))}),
                        f'p_sess_{proto}_{cid}', 6, on_select='rerun')
        if ev2.selection.rows:
            r = ss.iloc[ev2.selection.rows[0]]
            C.open_detail(source=r['source'], session=r['session_id'])

# ---------------------------------------------------------------- 신규 패턴 후보
with C.card(f'신규 패턴 후보 · {len(nv):,}종', help='노이즈이거나 군집 중심에서 멀리 떨어진(이상 점수 상위 5%) 흐름입니다. '
                                                '새 도구·새 변종일 수 있어 사람이 검토할 대상입니다. 행을 누르면 세션 조사로 이동합니다.'):
    if nv.empty:
        st.caption('이 범위에 신규 패턴 후보가 없습니다.')
    else:
        view = pd.DataFrame({'이상 점수': nv['outlier'], '프로토콜': nv['protocol'].str.upper(), '세션': nv['sessions'],
                             '다운로드': nv['downloaded'].map({1: '예', 0: ''}), '처음': C.dtfmt(nv['first'], '%m-%d %H:%M'),
                             '명령 흐름': nv['normalized_seq'].map(lambda t: D.defang(t, 160))})
        ev3 = C.compact(view, 'p_novel', 10, on_select='rerun',
                        column_config={'이상 점수': st.column_config.ProgressColumn(min_value=0, max_value=1, format='%.2f'),
                                       '명령 흐름': st.column_config.TextColumn(width='large')})
        if ev3.selection.rows:
            r = nv.iloc[ev3.selection.rows[0]]
            C.open_detail(source=r['source'], session=r['session_id'])
