"""홈: 발표·첫인상용 한 장 요약. 처음 보는 사람이 1분 안에 '무슨 일이 일어나고 있나'를 이해하도록 칸을 줄였다.

위에서 아래로: ① 상황 한 줄 ② 큰 숫자 4개 ③ 3D 지구본 + AI가 묶은 공격 유형 + 위험 행동 ④ 추이 + 지금 할 일.
자세한 표·필터는 '상세 현황'(overview.py)과 다른 페이지에 그대로 있다. 숫자는 모두 같은 계산(data·intel·patterns)을 쓴다.
지구본의 선은 수집된 로그의 국가별 접속을 보여 주는 연출이며 실시간이 아니다.
"""
from html import escape

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

import common as C
import data as D
import detect as X
import globe as G
import intel as I
import patterns as P

C.inject_css()
ds, f = C.dataset(), C.filters()
names = C.country_names()

if not f.sources or not f.protocols:
    st.info('허니팟과 프로토콜을 하나 이상 고르세요.')
    st.stop()

sc = D.scope(ds, f)
scope_kind = '전체 기간' if f.full_period else ('하루' if f.days == 1 else '선택 기간')
period = f'{f.start:%m-%d}' if f.days == 1 else f'{f.start:%m-%d} ~ {f.end:%m-%d}'
C.page_header('Home', f'{scope_kind} {period} KST', '일부러 열어 둔 가짜 서버(허니팟)에 들어온 해킹 시도를 모아, AI로 비슷한 것끼리 분류했습니다.')
version = C._version()

# 큰 숫자·카드 제목을 발표 화면에 맞게 키운다 (이 페이지에서만)
st.markdown("""<style>
.hp-kpi .val {font-size: clamp(2.2rem, 4vw, 3.4rem) !important; line-height: 1.1;}
.hp-kpi .lab {font-size: .95rem !important;}
.hp-kpi .sub {font-size: .9rem !important;}
.hp-title {font-size: .85rem !important;}
.hp-sent {font-size: 1.02rem; color: var(--ink-2); margin: .1rem 0 .6rem 0; line-height: 1.55;}
.hp-sent b {color: var(--ink);}
.hp-kpi .sub {color: var(--ink-2) !important; font-size: 1rem !important;}
.hp-banner {border-color: var(--line-2) !important; background: var(--surface) !important;}
</style>""", unsafe_allow_html=True)


@st.cache_data(show_spinner='상황 정리 중…')
def board(version, filters):
    d = C.dataset()
    s = D.scope(d, filters)
    ipi = I.ip_intel(d, s, d.rules)
    bl = I.blocklist(ipi)
    servers = I.download_servers(d, s)
    return {'brief': I.briefing(d, d.rules, filters), 'blocklist': bl,
            'servers': servers[servers['kind'] != '루프백(무시)'], 'danger': X.danger_table(s, d.rules),
            'files': D.file_summary(s)}


@st.cache_resource(show_spinner='군집 결과 불러오는 중…')
def ml_data(version):
    return P.load(C.DATA_DIR)


@st.cache_data(show_spinner='군집 정리 중…')
def clusters_cached(version, ml_version, filters):
    d = C.dataset()
    m = ml_data(ml_version)
    return pd.DataFrame() if m is None else P.cluster_table(m, d, D.scope(d, filters), d.rules)


@st.cache_resource(show_spinner=False)
def land():
    return G.land_rings(C.world())


b = board(version, f)
br = b['brief']
k, prev = D.kpis(sc), D.compare(ds, f)
if k['sessions'] == 0:
    st.info('이 범위에 접속 세션이 없습니다.')
    st.stop()

# ---------------------------------------------------------------- ① 상황 한 줄
st.markdown(
    f'<div class="hp-banner" style="--sev:{br["color"]}"><div class="lvl">{escape(br["level"])}</div>'
    f'<div class="txt"><div class="t1">{escape(br["label"])} 상황: {escape(" · ".join(br["reasons"]))} (수집 로그 기준)</div>'
    f'<div class="t2">위험도 높은 행동이 관측된 세션 {br["high"]:,}개 · 내려받아 실행 시도 {br["s01"]:,}세션</div></div></div>',
    unsafe_allow_html=True)

# ---------------------------------------------------------------- ② 큰 숫자 4개
sess = sc.sessions
countries = sess['country'].dropna()
n_countries = int(countries[countries != '??'].nunique())
cmp_note = f'직전 {f.days}일 대비' if prev else ''


def delta(key):
    return None if prev is None or k[key] is None else D.change(k[key], prev[key])


cols = st.columns(4)
tiles = [('접속 세션', f"{k['sessions']:,}", C.CYAN, cmp_note or '접속 시도 횟수', delta('sessions')),
         ('공격 IP', f"{k['ips']:,}", C.VIOLET, '고유 주소 수', delta('ips')),
         ('출발 국가', f'{n_countries:,}', C.PINK, 'IP 기반 추정', None),
         ('우선 확인 세션', f"{k['priority']:,}", C.RED, '위험도 높음 행동', delta('priority'))]
for col, (lab, val, color, sub, dl) in zip(cols, tiles):
    with col:
        C.kpi(lab, val, color, sub, dl)

# ---------------------------------------------------------------- ③ 지구본 + AI 유형 + 위험 행동
left, right = st.columns([1.55, 1])
with left:
    with C.card('공격은 어디서 오나', help='IP 기반 국가 추정(DB-IP Country Lite)이며 실제 위치가 아닙니다. 선은 조회 기간에 관측된 '
                                       '국가별 접속이 어느 허니팟으로 향했는지를 보여 주는 연출이며 실시간이 아닙니다. 드래그해서 돌릴 수 있습니다.'):
        ct_ = D.countries(sc)
        ct_ = ct_[ct_['country'] != '??'].sort_values('sessions', ascending=False)
        centers = {c['code']: (c['lon'], c['lat'], c['name']) for c in C.world() if c['code'] and c['code'] != '-99'}
        hp_pos = {'seoul': (126.98, 37.57, '서울', C.SOURCE_COLORS['서울']), 'syd': (151.21, -33.87, '시드니', C.SOURCE_COLORS['시드니'])}
        hps = [{'n': hp_pos[s][2], 'lon': hp_pos[s][0], 'lat': hp_pos[s][1], 'c': hp_pos[s][3]}
               for s in f.sources if s in hp_pos]
        pts = [{'n': centers[r.country][2], 'lon': centers[r.country][0], 'lat': centers[r.country][1], 'v': int(r.ips)}
               for r in ct_.itertuples() if r.country in centers]
        arcs = G.arcs_from(sess, centers, {s: hp_pos[s] for s in f.sources if s in hp_pos})
        start = 105   # 유라시아가 가운데 오도록(육지가 많이 보임). 버튼으로 허니팟 위치로 이동
        components.html(G.globe_html(land(), pts, arcs, hps, height=740, start_lon=start), height=746)
        top = ct_.sort_values('ips', ascending=False).head(5)
        legend = ' &nbsp; '.join(f'<span style="color:{h["c"]}">●</span> {escape(h["n"])} 허니팟으로 향하는 선' for h in hps)
        st.markdown(f'<div class="hp-sent" style="margin-bottom:.2rem">{legend}</div>', unsafe_allow_html=True)
        st.caption('IP 수 기준 상위: ' + ' · '.join(f"{names.get(r.country, r.country)} {r.ips:,}" for r in top.itertuples())
                   + ' · 점 크기 = IP 수 · 국가는 IP 기반 추정')
with right:
    ml_version = (C.DATA_DIR / 'ml.db').stat().st_mtime_ns if (C.DATA_DIR / 'ml.db').exists() else 0
    ct = clusters_cached(version, ml_version, f)
    with C.card('AI가 묶은 공격 유형', help='명령 입력 흐름이 비슷한 세션을 머신러닝(군집화)이 사람 없이 묶은 결과입니다. 이름은 자동으로 붙인 것이며 '
                                      '검증된 공격 분류가 아닙니다. 군집 번호는 학습 때마다 바뀝니다.'):
        if ct.empty:
            st.caption('군집 결과가 없습니다. (패턴 분석 페이지 참고)')
        else:
            real = ct[ct['cluster_id'] >= 0].sort_values('sessions', ascending=False)
            noise = int(ct.loc[ct['cluster_id'] == -1, 'sessions'].sum())
            total = int(ct['sessions'].sum())
            st.markdown(f'<div class="hp-sent"><b>{len(real)}개 유형</b>으로 {total - noise:,}개 세션을 묶었고, '
                        f'어디에도 안 맞는 세션은 {noise / max(total, 1) * 100:.1f}%입니다.</div>', unsafe_allow_html=True)
            # 같은 쉬운 이름이 여러 군집에 걸치면 합쳐서 보여 준다 (세션 수 합, 위험도는 가장 높은 것)
            g = (real.groupby('plain').agg(sessions=('sessions', 'sum'), n=('cluster_id', 'size'), danger=('danger', 'max'))
                 .sort_values('sessions', ascending=False).head(5).reset_index())
            C.bar_list([(r.plain + (f' ({r.n}개 군집)' if r.n > 1 else ''), r.sessions, f'{r.sessions:,}',
                         C.RED if r.danger >= 3 else (C.AMBER if r.danger == 2 else C.CYAN)) for r in g.itertuples()],
                       note='세션 수. 빨강=위험도 높은 행동 포함 · 노랑=중간. 이름은 입력을 보고 붙인 추정입니다. 군집 번호·근거는 패턴 분석(ML)')
    dt = b['danger']
    dt = dt[(dt['sessions'] > 0) & (dt['rule_id'] != 'B19')].head(4).reset_index(drop=True)
    with C.card('위험 행동 Top', help=X.DANGER_HELP + ' 셸 진입 요청(B19)은 거의 모든 봇에 나와 뺐습니다.'):
        if dt.empty:
            st.caption('이 범위에서 관측된 위험 행동이 없습니다.')
        else:
            C.bar_list([(r.plain, r.sessions, f'{r.sessions:,}', X.DANGER_COLORS[r.danger]) for r in dt.itertuples()],
                       note='세션 수 · 빨강=높음 · 노랑=중간 · 회색=낮음')
    with C.card(f"새로 나타난 것 · {br['label']}", help='그 기간 전까지의 보유 데이터에 없던 항목만 셉니다.'):
        rows = [('새 다운로드 서버', len(br['new_servers']), C.ORANGE), ('새 파일 해시', len(br['new_hashes']), C.LIME),
                ('새 위험 행동 IP', len(br['new_danger_ips']), C.RED), ('처음 관측된 행동', len(br['new_rules']), C.VIOLET)]
        st.markdown('<div class="hp-new">' + ''.join(
            f'<div class="row"><div class="n" style="color:{c if n else C.MUTED}">{n:,}</div>'
            f'<div><div class="a">{escape(lab)}</div></div></div>' for lab, n, c in rows) + '</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------- ④ 추이 + 지금 할 일
left, right = st.columns([1.55, 1])
with left:
    with C.card(f'{"시간별" if f.days == 1 else "일별"} 접속', help='막대 = 접속 세션 수(KST). 세션 수는 소수 IP의 반복에 크게 좌우되므로 '
                                                             '고유 IP 수로도 볼 수 있습니다.'):
        metric = st.segmented_control('지표', ['세션 수', '고유 IP 수'], default='세션 수', key='home_metric',
                                      label_visibility='collapsed') or '세션 수'
        hourly = f.days == 1
        s_ = sess.assign(bucket=sess['start'].dt.floor('h' if hourly else 'D').dt.tz_localize(None))
        g = (s_.groupby('bucket').size() if metric == '세션 수' else s_.groupby('bucket')['src_ip'].nunique()).rename('value').reset_index()
        peak = g.loc[g['value'].idxmax()]
        unit = '시' if hourly else ''
        fmt = '%m-%d %H시' if hourly else '%m-%d'
        st.markdown(f'<div class="hp-sent">가장 많았던 {"시간" if hourly else "날"}은 <b>{peak["bucket"]:{fmt}}{unit}</b> '
                    f'({peak["value"]:,.0f}{"세션" if metric == "세션 수" else "개 IP"}), 평균은 {g["value"].mean():,.0f}입니다.</div>',
                    unsafe_allow_html=True)
        color = C.CYAN if metric == '세션 수' else C.VIOLET
        base = alt.Chart(g)
        bars = base.mark_bar(color=color, cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
            x=alt.X('bucket:T', title=None, axis=alt.Axis(format='%H시' if hourly else '%m-%d', labelAngle=0, grid=False,
                                                         labelFontSize=12)),
            y=alt.Y('value:Q', title=None, axis=alt.Axis(domain=False, ticks=False, format=',.0f', labelFontSize=12, title=None)),
            tooltip=[alt.Tooltip('bucket:T', title='시각', format='%m-%d %H:00' if hourly else '%m-%d'),
                     alt.Tooltip('value:Q', title=metric, format=',')])
        mark = (alt.Chart(pd.DataFrame({'bucket': [peak['bucket']], 'value': [peak['value']]}))
                .mark_point(color=C.RED, size=90, filled=True).encode(x='bucket:T', y='value:Q'))
        C.chart((bars + mark).properties(height=250))
with right:
    bl = b['blocklist']
    fs = b['files']
    with C.card('지금 할 일', help='허니팟 관측을 근거로 실제 환경에 적용할 조치입니다. 목록·CSV는 위협 정보(IOC) 페이지에 있습니다.'):
        todo = [('차단', C.RED, f'위험 IP {int((bl["tier"] == 1).sum()):,}개 방화벽 차단',
                 f'내려받아 실행·다운로드·흔적 삭제를 한 IP (검토 대상 {int((bl["tier"] == 2).sum()):,}개 별도)'),
                ('차단', C.RED, f'다운로드 서버 {len(b["servers"]):,}개로 나가는 연결 확인', '우리 서버가 접속한 기록이 있으면 감염 의심'),
                ('등록', C.CYAN, f'파일 해시 {fs["unique_hashes"]:,}개 백신·EDR 등록', '내부 서버에서 같은 파일 검색')]
        st.markdown('<div class="hp-todo">' + ''.join(
            f'<div class="row"><span class="act" style="--c:{c}">{k_}</span><div><div class="a">{escape(a)}</div>'
            f'<div class="b">{escape(d_)}</div></div></div>' for k_, c, a, d_ in todo) + '</div>', unsafe_allow_html=True)
        st.page_link(st.session_state['pages']['intel'], label='위협 정보(IOC)에서 목록·CSV 보기 →')
        st.page_link(st.session_state['pages']['overview'], label='더 자세한 현황 보기 →')

# ---------------------------------------------------------------- ⑤ 더 깊이: 진행 단계 · 시간대 · 비율
st.markdown('<div class="hp-title" style="margin:1.1rem 0 .1rem 0">더 깊이 보기</div>', unsafe_allow_html=True)
c1, c2, c3 = st.columns([1.1, 1.2, 0.9])
with c1:
    fn, stopped_early, pop = X.funnel(sc, ds.rules)
    with C.card('공격은 어디까지 갔나', help='명령을 입력한 세션마다 가장 깊이 간 단계를 구해, 각 단계 "이상"까지 간 세션 수를 셌습니다. '
                                          + ' / '.join(f'{n}: {d}' for _, n, d in X.FUNNEL)):
        if not pop:
            st.caption('이 범위에 명령을 입력한 세션이 없습니다.')
        else:
            pct = dict(zip(fn['name'], fn['percent']))
            names_ = list(fn['name'])
            st.markdown(f'<div class="hp-sent">명령을 입력한 <b>{pop:,}세션</b> 중 <b>{pct[names_[2]]:.0f}%</b>가 {names_[2]} 이상, '
                        f'<b>{pct[names_[3]]:.0f}%</b>가 {names_[3]} 이상까지 갔고, {names_[4]}까지 간 것은 {pct[names_[4]]:.1f}%입니다.</div>',
                        unsafe_allow_html=True)
            fn = fn.assign(text=fn.apply(lambda r: f"{r['sessions']:,} · {r['percent']:.0f}%", axis=1),
                           color=[C.CYAN, C.BLUE, C.AMBER, C.ORANGE, C.RED][:len(fn)])
            base = alt.Chart(fn).encode(
                y=alt.Y('name:N', sort=list(fn['name']), title=None,
                        axis=alt.Axis(labelLimit=150, domain=False, ticks=False, labelFontSize=13)),
                x=alt.X('sessions:Q', title=None, axis=None, scale=alt.Scale(domain=[0, pop * 1.5], nice=False)),
                tooltip=[alt.Tooltip('name:N', title='단계'), alt.Tooltip('desc:N', title='뜻'),
                         alt.Tooltip('sessions:Q', title='세션', format=','), alt.Tooltip('percent:Q', title='비율(%)', format='.1f')])
            C.chart((base.mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, height={'band': 0.62})
                     .encode(color=alt.Color('color:N', scale=None))
                     + base.mark_text(align='left', dx=6, fontSize=13, color='#e6ebf0').encode(text='text:N'))
                    .properties(height=44 * len(fn)))
with c2:
    with C.card('공격이 몰리는 시간대', help='접속이 시작된 시각(KST) 기준 시간대별 세션 수입니다. 소수 IP의 반복이 큰 영향을 줄 수 있습니다.'):
        wh = D.weekday_hour(sc)
        hh = wh.groupby('hour')['sessions'].sum().reindex(range(24), fill_value=0).rename('sessions').reset_index()
        top3 = set(hh.nlargest(3, 'sessions')['hour'])
        hh['강조'] = hh['hour'].map(lambda h: h in top3)
        busiest = ', '.join(f'{int(h)}시' for h in sorted(top3))
        st.markdown(f'<div class="hp-sent">가장 붐비는 시간대는 <b>{busiest}</b> (한국 시각)입니다.</div>', unsafe_allow_html=True)
        C.chart(alt.Chart(hh).mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
            x=alt.X('hour:O', title=None, axis=alt.Axis(labelAngle=0, labelFontSize=12, grid=False,
                                                       values=list(range(0, 24, 3)), labelExpr="datum.value + '시'")),
            y=alt.Y('sessions:Q', title=None, axis=alt.Axis(domain=False, ticks=False, format=',.0f', labelFontSize=12)),
            color=alt.condition('datum.강조', alt.value(C.AMBER), alt.value('#2f8f9b')),
            tooltip=[alt.Tooltip('hour:O', title='시(KST)'), alt.Tooltip('sessions:Q', title='세션', format=',')]
        ).properties(height=250))
with c3:
    with C.card('접속은 어떻게 나뉘나', help='세션 기준 비율입니다. 상위 IP가 차지하는 비율이 높으면 소수 IP의 반복이 숫자를 키운 것입니다.'):
        proto = D.protocol_split(sc)
        C.share_bar('프로토콜', [(r.protocol.upper(), r.percent, C.PROTOCOL_COLORS.get(r.protocol, C.MUTED),
                                f'{r.protocol.upper()} {r.sessions:,} ({r.percent:.0f}%)') for r in proto.itertuples()])
        src = D.source_split(sc)
        C.share_bar('허니팟', [(r.name, r.percent, C.SOURCE_COLORS.get(r.name, C.MUTED), f'{r.name} {r.sessions:,} ({r.percent:.0f}%)')
                              for r in src.itertuples()])
        conc = D.ip_concentration(sc)
        if conc['total']:
            pc = conc['parts']['percent'].tolist()
            C.share_bar('IP 집중도 (상위 IP가 차지한 세션)', [
                ('1위', pc[0], C.RED, f"1위 {D.mask_ip(conc['top1_ip'])} {pc[0]:.0f}%"),
                ('2~3위', pc[1], C.AMBER, f'2~3위 {pc[1]:.0f}%'),
                ('나머지', pc[2], C.MUTED, f"나머지 {max(conc['ips'] - 3, 0):,}개 IP {pc[2]:.0f}%")])

# ---------------------------------------------------------------- ⑥ 유형별 추이 · 비밀번호
c1, c2 = st.columns([1.55, 1])
with c1:
    with C.card('AI가 묶은 유형별 일별 추이', help='위 "AI가 묶은 공격 유형"의 상위 5개 이름별 일별 세션 수입니다. 나머지는 "기타"로 묶었습니다. '
                                              '이름은 입력을 보고 붙인 추정입니다.'):
        m = ml_data(ml_version)
        if m is None or ct.empty:
            st.caption('군집 결과가 없어 표시할 수 없습니다.')
        else:
            name_of = {(r.protocol, int(r.cluster_id)): r.plain for r in ct.itertuples() if r.cluster_id >= 0}
            cl = m.clusters.merge(sess[['source', 'session_id', 'start']], on=['source', 'session_id'])
            cl = cl[cl['cluster_id'] >= 0]
            if cl.empty:
                st.caption('이 범위에 군집 결과가 있는 세션이 없습니다.')
            else:
                cl['유형'] = [name_of.get((p, int(c)), '기타') for p, c in zip(cl['protocol'], cl['cluster_id'])]
                keep = list(cl['유형'].value_counts().index[:5])
                cl['유형'] = cl['유형'].where(cl['유형'].isin(keep), '기타')
                grain = 'h' if f.days == 1 else 'D'
                cl['bucket'] = cl['start'].dt.floor(grain).dt.tz_localize(None)
                gd = cl.groupby(['bucket', '유형']).size().rename('sessions').reset_index()
                has_other = bool((gd['유형'] == '기타').any()) and '기타' not in keep
                domain = keep + (['기타'] if has_other else [])
                colors = [C.CYAN, C.VIOLET, C.ORANGE, C.GREEN, C.PINK][:len(keep)] + (['#56626f'] if has_other else [])
                C.chart(alt.Chart(gd).mark_bar().encode(
                    x=alt.X('bucket:T', title=None, axis=alt.Axis(format='%H시' if grain == 'h' else '%m-%d', labelAngle=0,
                                                                 grid=False, labelFontSize=12)),
                    y=alt.Y('sessions:Q', title=None, stack=True,
                            axis=alt.Axis(domain=False, ticks=False, format=',.0f', labelFontSize=12)),
                    color=alt.Color('유형:N', title=None, scale=alt.Scale(domain=domain, range=colors),
                                    legend=alt.Legend(orient='bottom', columns=1, labelLimit=420, labelFontSize=12,
                                                      symbolType='square')),
                    order=alt.Order('유형:N', sort='ascending'),
                    tooltip=[alt.Tooltip('bucket:T', title='시각', format='%m-%d %H:00' if grain == 'h' else '%m-%d'),
                             alt.Tooltip('유형:N', title='유형'), alt.Tooltip('sessions:Q', title='세션', format=',')]
                ).properties(height=300))
with c2:
    with C.card('가장 많이 시도된 비밀번호', help='원본 로그의 로그인 시도(성공·실패 포함)입니다. 원본 로그가 없는 허니팟은 미수집입니다. '
                                              '공격자가 시도한 값이며 실제 계정 정보가 아닙니다.'):
        au = D.auth_summary(sc, top=6)
        if au is None:
            st.caption('선택한 허니팟에 원본 인증 로그가 없어 미수집입니다.')
        else:
            st.markdown(f'<div class="hp-sent">로그인 시도 <b>{au["total"]:,}건</b> 중 성공은 {au["success"]:,}건입니다.</div>',
                        unsafe_allow_html=True)
            C.bar_list([(v, n, f'{n:,}', C.PINK) for v, n in zip(au['passwords']['value'], au['passwords']['count'])],
                   note='많이 시도된 순')

st.caption('탐지는 허니팟에 입력된 명령을 보고 판단한 것이며, 실제로 실행에 성공했는지는 확인하지 않았습니다. 국가는 IP 기반 추정입니다.')
