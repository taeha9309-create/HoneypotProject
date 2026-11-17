"""Overview: 얼마나 들어왔나 → 무엇을 확인할까 → 근거는 무엇인가."""
from html import escape
import time

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

import common as C
import data as D

C.inject_css()
ds, f = C.dataset(), C.filters()
rules = ds.rules
names = C.country_names()

if not f.sources or not f.protocols:
    st.info('허니팟과 프로토콜을 하나 이상 고르세요.')
    st.stop()

sc = D.scope(ds, f)

# ---------------------------------------------------------------- 머리말: 조회 범위 + 데이터 상태
scope_kind = '전체 기간' if f.full_period else ('하루' if f.days == 1 else '선택 기간')
period = f'{f.start:%m-%d}' if f.days == 1 else f'{f.start:%m-%d} ~ {f.end:%m-%d}'
C.page_header('Overview', f'{scope_kind} {period} KST',
              ' · '.join(D.SOURCE_NAMES.get(s, s) for s in f.sources) + ' · ' + ' / '.join(p.upper() for p in f.protocols)
              + ' · 테스트 접속 제외 · 탐지는 입력 관측(실행 성공 미확인)')

status = D.source_status(ds, f)
items = []
for s in status:
    ok = s['has_raw_logs']
    dot = C.LIME if ok else C.AMBER
    gap = f"수집 공백 {s['empty_hours']}시간" if ok else '원본 로그 없음 · 인증/파일 실패 미수집'
    items.append(f'<div><span class="hp-dot" style="background:{dot}"></span><b>{escape(s["name"])}</b> '
                 f'마지막 이벤트 {C.fmt_dt(s["last_event"])} · 가져온 시각 {C.fmt_dt(s["imported_at"])} · {escape(gap)}</div>')
st.markdown(f'<div class="hp-status">{"".join(items)}</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------- 1. 핵심 숫자 (Q1, Q2)
k, prev = D.kpis(sc), D.compare(ds, f)
ni = D.new_items(ds, sc)


def delta(key):
    if prev is None or k[key] is None:
        return None
    return D.change(k[key], prev[key])


rate = f"성공률 {k['auth_success'] / k['auth'] * 100:.1f}%" if k['auth'] else ''
auth_note = ' · '.join(x for x in (rate, '원본 로그 있는 출처만' if sc.raw_partial else '') if x) \
    if k['auth'] is not None else '원본 로그 있는 출처 미선택'
cmp_note = f'직전 {f.days}일 대비' if prev else ''
KPI_H = None  # 내용 높이에 맞춘다 (좁은 화면에서 숫자가 잘리지 않게)
left, right = st.columns(2)
with left:
    with C.card('Traffic', height=KPI_H, help='세션은 시작 시각, 인증은 이벤트 시각 기준. 변화율은 직전 같은 길이 기간 대비입니다. '
                                       '아래 막대는 허니팟별 세션 비율입니다.'):
        a, b, c = st.columns(3)
        with a:
            C.kpi('접속 세션', f"{k['sessions']:,}", C.CYAN, cmp_note, delta('sessions'))
        with b:
            C.kpi('고유 IP', f"{k['ips']:,}", C.VIOLET, cmp_note, delta('ips'))
        with c:
            C.kpi('인증 시도', '미수집' if k['auth'] is None else f"{k['auth']:,}", C.PINK, auth_note, delta('auth'))
        src = D.source_split(sc)
        C.share_bar('허니팟별 접속 비율 (세션 기준)',
                    [(r.name, r.percent, C.SOURCE_COLORS.get(r.name, C.MUTED), f'{r.name} {r.sessions:,}세션 ({r.percent:.1f}%)')
                     for r in src.itertuples()])
with right:
    with C.card('Activity', height=KPI_H, help='우선 확인 세션: 다운로드 후 실행·디코딩 후 실행·SSH 키·예약 작업·기록 끄기·로그 삭제·방화벽 해제 중 '
                                 '하나라도 관측된 고유 세션. 신규: 기간 선택 시 그 이전 보유 데이터에 없던 IP (전체 기간은 누적). '
                                 '아래 막대는 세션이 상위 IP에 얼마나 몰렸는지(IP 집중도)입니다. 집중도가 높으면 세션 수와 국가 순위가 '
                                 '소수 IP의 반복을 크게 반영합니다.'):
        a, b, c = st.columns(3)
        with a:
            C.kpi('명령 입력', f"{k['commands']:,}", C.LIME, f"{k['command_sessions']:,}개 세션", delta('commands'))
        with b:
            C.kpi('우선 확인', f"{k['priority']:,}", C.RED, cmp_note, delta('priority'))
        with c:
            C.kpi(f"{ni['mode']} IP", f"{ni['ips']:,}", C.AMBER,
                  f"명령 원문 {ni['commands']:,} · 파일 해시 {ni['hashes']:,}")
        conc = D.ip_concentration(sc)
        if conc['total']:
            pc = conc['parts']['percent'].tolist()
            C.share_bar('IP 집중도 (전체 세션 중 상위 IP가 차지하는 비율)', [
                ('1위 IP', pc[0], C.RED, f"1위 IP {D.mask_ip(conc['top1_ip'])} {pc[0]:.0f}%"),
                ('2~3위', pc[1], C.AMBER, f'2~3위 IP {pc[1]:.0f}%'),
                ('나머지', pc[2], C.MUTED, f"나머지 {max(conc['ips'] - 3, 0):,}개 IP {pc[2]:.0f}%")],
                note='상위 IP 몇 개가 크면 세션 수·국가 순위는 소수 IP의 반복을 크게 반영합니다.')

partial = [s['name'] for s in status if s['last_event'] is not None and s['last_event'].date() <= f.end]
if partial and not f.full_period:
    st.caption(f"⚠ {', '.join(partial)}의 마지막 수집일은 하루치가 다 들어오지 않아 변화율이 실제보다 낮게 보일 수 있습니다.")

if k['sessions'] == 0:
    st.info('이 범위에 접속 세션이 없습니다.')
    st.stop()

# ---------------------------------------------------------------- 2. 추이 + 지도
# 같은 줄 카드의 높이 (px). 하루 조회 때는 지도 재생 조작부만큼 더 높인다.
ROW2 = 500 if f.days == 1 else 440
ROW3, ROW4 = 490, 470

left, right = st.columns([1.15, 1])
with left:
    with C.card(f'{"시간별" if f.days == 1 else "일별"} 접속', height=ROW2,
                help='막대는 세션 수(KST), 점선은 구간 평균입니다. 프로토콜 또는 허니팟별로 나눠 볼 수 있습니다.'):
        split_by = st.segmented_control('구분', ['프로토콜', '허니팟'], default='프로토콜', key='tl_split',
                                        label_visibility='collapsed') or '프로토콜'
        by = 'protocol' if split_by == '프로토콜' else 'source'
        tl, grain = D.timeline(sc, by)
        tl = tl.rename(columns={by: 'group'})
        unit = '시간' if grain == 'h' else '일'
        palette = C.PROTOCOL_COLORS if by == 'protocol' else C.SOURCE_COLORS
        protos = [p for p in palette if p in set(tl['group'])]
        per = tl.groupby('bucket')['sessions'].sum()
        avg = float(per.mean()) if len(per) else 0.0
        bars = alt.Chart(tl).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
            x=alt.X('bucket:T', title=None, axis=alt.Axis(format='%H시' if grain == 'h' else '%m-%d', labelAngle=0,
                                                         grid=False, domainColor=C.GRID)),
            y=alt.Y('sessions:Q', title=None, stack=True, axis=alt.Axis(domain=False, ticks=False, format='~s')),
            color=alt.Color('group:N', title=None,
                            legend=alt.Legend(orient='bottom',
                                              labelExpr='upper(datum.label)' if by == 'protocol' else 'datum.label'),
                            scale=alt.Scale(domain=protos, range=[palette[p] for p in protos])),
            tooltip=[alt.Tooltip('bucket:T', title='시각', format='%m-%d %H:00' if grain == 'h' else '%m-%d'),
                     alt.Tooltip('group:N', title=split_by), alt.Tooltip('sessions:Q', title='세션', format=',')])
        rule = alt.Chart(pd.DataFrame({'avg': [avg]})).mark_rule(color='#9fb3c8', strokeDash=[4, 4]).encode(y='avg:Q')
        label = alt.Chart(pd.DataFrame({'avg': [avg], 'text': [f'평균 {avg:,.0f}세션/{unit}']})).mark_text(
            align='left', dx=4, dy=-7, color='#9fb3c8', fontSize=11).encode(
            y='avg:Q', x=alt.value(0), text='text:N')
        C.chart((bars + rule + label).properties(height=250))
        split = D.protocol_split(sc)
        st.caption(' · '.join(f"{r.protocol.upper()} {r.sessions:,} ({r.percent:.1f}%)" for r in split.itertuples()))
with right:
    ct = D.countries(sc)
    unknown = int(ct.loc[ct['country'] == '??', 'sessions'].sum())
    with C.card('공격 출발 국가', height=ROW2, help='국가는 IP 기반 추정(DB-IP Country Lite)이며 공격자의 실제 위치가 아닙니다. '
                                    '원 크기는 세션 수 또는 고유 IP 수입니다. 한 IP가 많이 반복하면 두 값이 크게 다릅니다.'):
        metric = st.segmented_control('기준', ['세션 수', 'IP 수'], default='세션 수', key='map_metric',
                                      label_visibility='collapsed') or '세션 수'
        col = 'sessions' if metric == '세션 수' else 'ips'
        holder = st.empty()
        if f.days == 1:
            day_s = sc.sessions.assign(hour=sc.sessions['start'].dt.hour, country=sc.sessions['country'].fillna('??'))
            hour = st.slider('시각 (KST, 누적)', 0, 23, 23, key='replay_hour')
            play = st.button('▶ 하루 재생', help='0시부터 23시까지 누적 접속을 순서대로 보여 줍니다. 실시간 데이터가 아닙니다.')
            for h in (range(24) if play else [hour]):
                upto = day_s[day_s['hour'] <= h].groupby('country')
                cur = (upto.size() if col == 'sessions' else upto['src_ip'].nunique()).to_dict()
                with holder:
                    components.html(C.world_svg(cur, height=250), height=258)
                if play:
                    time.sleep(0.35)
        else:
            with holder:
                components.html(C.world_svg(dict(zip(ct['country'], ct[col])), height=250), height=258)
        top = ct[ct['country'] != '??'].sort_values(col, ascending=False).head(5)
        st.caption(' · '.join(f"{names.get(r.country, r.country)} 세션 {r.sessions:,} · IP {r.ips:,}" for r in top.itertuples())
                   + (f' · 위치 미상 {unknown:,}' if unknown else '') + ' · IP Geolocation by [DB-IP](https://db-ip.com)')

# ---------------------------------------------------------------- 3. 확인할 행동 (Q2, Q3, Q5)
c1, c2, c3 = st.columns(3)
with c1:
    table, recent = D.priority_summary(sc, rules)
    with C.card('우선 확인할 행동', height=ROW3, help='행동별 세션 수이며 한 세션이 여러 행동에 걸릴 수 있습니다. '
                                      '입력 관측이며 실행 성공은 확인하지 않았습니다.'):
        C.chart(C.hbar(table, 'label', 'sessions', text='sessions:Q', color=C.RED, sort=None,
                       tooltip=[alt.Tooltip('label:N', title='행동'), alt.Tooltip('rule_id:N', title='규칙'),
                                alt.Tooltip('rule_name:N', title='규칙 이름'), alt.Tooltip('sessions:Q', title='세션')]))
        if recent.empty:
            st.caption('이 범위에서 우선 확인 세션이 없습니다.')
        else:
            view = pd.DataFrame({'시각': recent['time'].dt.strftime('%m-%d %H:%M'), 'IP': recent['ip_masked'],
                                 '행동': recent['behaviors']})
            ev = st.dataframe(view, hide_index=True, width='stretch', on_select='rerun',
                              selection_mode='single-row', key='prio_pick')
            st.caption('행을 클릭하면 세션 상세로 이동합니다.')
            if ev.selection.rows:
                r = recent.iloc[ev.selection.rows[0]]
                C.open_detail(source=r['source'], session=r['session_id'])
with c2:
    bt = D.behavior_top(sc, rules, exclude=D.COMMON_RULES)
    with C.card('주요 탐지 행동 Top 5', height=ROW3, help='명령을 입력한 세션 중 각 규칙이 걸린 세션 비율. '
                                         '셸 진입 요청(B19)은 거의 모든 Telnet 봇에 걸려 순위에서 빼고 아래에 따로 표시합니다.'):
        bt['text'] = bt['percent'].map(lambda v: f'{v:.0f}%')
        C.chart(C.hbar(bt, 'label', 'sessions', text='text:N', color=C.CYAN,
                       tooltip=[alt.Tooltip('label:N', title='행동'), alt.Tooltip('rule_id:N', title='규칙'),
                                alt.Tooltip('stage:N', title='단계'), alt.Tooltip('attack:N', title='ATT&CK'),
                                alt.Tooltip('sessions:Q', title='세션', format=','),
                                alt.Tooltip('percent:Q', title='명령 세션 대비(%)', format='.1f')]))
        for r in D.common_rule_share(sc, rules):
            st.caption(f"순위 제외 · {r['rule_id']} {r['name']}: {r['sessions']:,}세션 ({r['percent']:.0f}%). "
                       '거의 모든 봇이 처음에 보내는 입력이라 구분에 쓰지 않습니다.')
with c3:
    au = D.auth_summary(sc)
    with C.card('인증', height=ROW3, help='원본 로그의 로그인 성공·실패 이벤트(세션·시간·IP가 맞는 것). '
                           '원본 로그가 없는 출처(시드니 사본)는 미수집입니다.'):
        if au is None:
            st.info('선택한 출처에 원본 인증 로그가 없어 미수집입니다.')
        else:
            a, b = st.columns(2)
            with a:
                C.kpi('성공', f"{au['success']:,}", C.PINK, f"{au['success'] / max(au['total'], 1) * 100:.1f}%")
            with b:
                C.kpi('실패', f"{au['failed']:,}", '#9aa3ad', f"{au['failed'] / max(au['total'], 1) * 100:.1f}%"
                      + (' · 원본 로그 출처만' if sc.raw_partial else ''))
            t1, t2, t3 = st.tabs(['아이디/비밀번호', '아이디', '비밀번호'])
            for tab, key in ((t1, 'pairs'), (t2, 'users'), (t3, 'passwords')):
                with tab:
                    C.chart(C.hbar(au[key], 'value', 'count', text='count:Q', row=20, color=C.PINK,
                                   tooltip=[alt.Tooltip('value:N', title='값'),
                                            alt.Tooltip('count:Q', title='시도', format=',')]))

# ---------------------------------------------------------------- 4. 파일·반복 IP (Q4, Q6)
c1, c2 = st.columns(2)
with c1:
    fs = D.file_summary(sc)
    with C.card('수집 파일', height=ROW4, help='다운로드·업로드 관측. 실패는 해시가 없어 따로 셉니다. URL은 링크가 아니며 hxxp로 표시합니다. '
                               '악성 여부는 확인하지 않았습니다.'):
        a, b, c, d = st.columns(4)
        for col, (lab, val, color) in zip((a, b, c, d), (('다운로드', fs['downloads'], C.CYAN), ('업로드', fs['uploads'], C.VIOLET),
                                                         ('실패', fs['failed'], '#9aa3ad'), ('고유 해시', fs['unique_hashes'], C.LIME))):
            with col:
                C.kpi(lab, f'{val:,}', color)
        files = fs['files'].head(6)
        if files.empty:
            st.caption('이 범위에서 수집된 파일이 없습니다.')
        else:
            st.dataframe(pd.DataFrame({
                '파일': files['name'], '종류': files['kind'].map({'download': '다운로드', 'upload': '업로드'}),
                '세션': files['sessions'], '최근 관측': files['last'].dt.strftime('%m-%d %H:%M'),
                'SHA-256': files['shasum'].map(D.short_hash)}), hide_index=True, width='stretch')
            with st.expander('전체 해시·URL'):
                st.code('\n'.join(f"{r.shasum or '(해시 없음)'}  {D.defang(r.url, mask_ips=False)}"
                                  for r in fs['files'].itertuples()), language=None, wrap_lines=True)
with c2:
    ri = D.repeat_ips(sc, rules, top=10)
    with C.card('반복 접속 IP', height=ROW4, help='세션 수 순위. 활동일은 접속한 날짜 수, 대표 행동은 B19(셸 진입)를 뺀 가장 흔한 탐지입니다. '
                                 '클릭하면 IP 상세로 이동합니다.'):
        view = pd.DataFrame({'IP': ri['ip_masked'],
                             '국가': ri['country'].map(lambda c: names.get(c, c) if isinstance(c, str) else '위치 미상'),
                             '세션': ri['sessions'], '활동일': ri['days'], '대표 행동': ri['behavior'],
                             '마지막': ri['last'].dt.strftime('%m-%d %H:%M')})
        ev = st.dataframe(view, hide_index=True, width='stretch', on_select='rerun', selection_mode='single-row',
                          height=388, key='ip_pick', column_config={'세션': st.column_config.ProgressColumn(
                              '세션', format='%d', min_value=0, max_value=int(ri['sessions'].max() or 1))})
        if ev.selection.rows:
            C.open_detail(ip=ri.iloc[ev.selection.rows[0]]['src_ip'])

# ---------------------------------------------------------------- 5. 최근 입력 명령 (Q3, Q7)
rc = D.recent_commands(sc, rules, limit=20)
with C.card('최근 입력 명령', help='행동 설명은 화면용 쉬운 이름입니다. 근거가 "규칙 일치"일 때만 시그니처 탐지이고, '
                              '"입력 기반 추정"은 탐지 건수에 들어가지 않습니다. 클릭하면 세션 상세로 이동합니다.'):
    view = pd.DataFrame({'시각': rc['time'].dt.strftime('%m-%d %H:%M:%S'), 'IP': rc['ip_masked'],
                         '프로토콜': rc['protocol'], '명령': rc['command_view'], '행동 설명': rc['behavior'],
                         '근거': rc['basis'], '탐지 규칙': rc['rules']})
    st.markdown(' '.join(f'<span style="color:{c};font-size:.75rem;margin-right:.8rem">● {escape(b)}</span>'
                         for b, c in C.BASIS_COLORS.items()), unsafe_allow_html=True)
    ev = st.dataframe(C.style_commands(view), hide_index=True, width='stretch', on_select='rerun',
                      selection_mode='single-row', key='cmd_pick', height=560,
                      column_config={'명령': st.column_config.TextColumn(width='large')})
    if ev.selection.rows:
        r = rc.iloc[ev.selection.rows[0]]
        C.open_detail(source=r['source'], session=r['session_id'])
