"""Overview: 상황판. 위에서 아래로 '지금 상태 → 할 일 → 규모·추이 → 무엇을 했나 → 허니팟 상태'.

중소기업 보안 관리자가 아침에 열어서 1분 안에 판단하도록:
① 상황 등급(위험/주의/안정)과 이유 ② 지금 할 일(차단·등록·점검, 위협 정보 페이지로 연결)
③ 새로 나타난 것 ④ 규모(KPI)·추이·출발지 ⑤ 위험 행동·인증·파일 ⑥ 반복 IP·최근 명령 ⑦ 허니팟 상태.
무거운 계산은 조회 범위별로 캐시한다. 표는 내용 높이에 맞추고 안쪽 스크롤을 쓰지 않는다.
"""
from html import escape
import time

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

import common as C
import data as D
import detect as X
import intel as I

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
C.page_header('Overview', f'{scope_kind} {period} KST',
              ' · '.join(D.SOURCE_NAMES.get(s, s) for s in f.sources) + ' · ' + ' / '.join(p.upper() for p in f.protocols)
              + ' · 테스트 접속 제외 · 탐지는 입력 관측(실행 성공 미확인)')
version = C._version()


@st.cache_data(show_spinner='상황 정리 중…')
def board(version, filters):
    d = C.dataset()
    s = D.scope(d, filters)
    ipi = I.ip_intel(d, s, d.rules)
    bl = I.blocklist(ipi)
    servers = I.download_servers(d, s)
    return {'brief': I.briefing(d, d.rules, filters), 'blocklist': bl,
            'servers': servers[servers['kind'] != '루프백(무시)'],
            'checks': I.exposure_checks(d, s, d.rules), 'danger': X.danger_table(s, d.rules),
            'recent': D.recent_commands(s, d.rules, limit=8), 'repeat': D.repeat_ips(s, d.rules, top=8),
            'auth': D.auth_summary(s), 'files': D.file_summary(s), 'health': I.health_daily(s),
            'conc': D.ip_concentration(s)}


@st.cache_data(show_spinner='보고서 만드는 중…')
def report_cached(version, filters):
    return I.report_markdown(C.dataset(), C.dataset().rules, filters)


b = board(version, f)
br = b['brief']
status = D.source_status(ds, f)

# ---------------------------------------------------------------- ① 상황 등급
st.markdown(
    f'<div class="hp-banner" style="--sev:{br["color"]}">'
    f'<div class="lvl">{escape(br["level"])}</div>'
    f'<div class="txt"><div class="t1">{escape(br["label"])} 상황: {escape(" · ".join(br["reasons"]))}</div>'
    f'<div class="t2">접속 {br["sessions"]:,}세션'
    + (f' (직전 같은 기간 대비 {br["change"]:+.0f}%)' if br['change'] is not None else '')
    + f' · 위험도 높음 행동 {br["high"]:,}세션 · 내려받아 실행 {br["s01"]:,}세션</div></div></div>',
    unsafe_allow_html=True)
items = []
for s_ in status:
    ok = s_['has_raw_logs']
    gap = f"수집 공백 {s_['empty_hours']}시간" if ok else '원본 로그 없음(인증·파일 실패 미수집)'
    items.append(f'<div><span class="hp-dot" style="background:{C.LIME if ok else C.AMBER}"></span><b>{escape(s_["name"])}</b> '
                 f'마지막 이벤트 {C.fmt_dt(s_["last_event"])} · {escape(gap)}</div>')
st.markdown(f'<div class="hp-status">{"".join(items)}</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------- ② 지금 할 일 + ③ 새로 나타난 것
left, right = st.columns([1.35, 1])
with left:
    with C.card('지금 할 일', help='허니팟 관측을 근거로 실제 회사 환경에 적용할 조치입니다. 숫자는 현재 조회 범위 기준이며, '
                                  '목록과 CSV는 위협 정보(IOC) 페이지에 있습니다.'):
        bl = b['blocklist']
        t1 = int((bl['tier'] == 1).sum())
        fs = b['files']
        checks = b['checks']
        telnet = checks[checks['점검 항목'].str.startswith('외부에 열린 Telnet')]
        # (조치 종류, 색, 할 일, 설명): 차단은 위험색, 등록·점검·반영은 다른 색으로 한눈에 구분
        todo = [('차단', C.RED, f'1순위 IP {t1:,}개 방화벽 차단',
                 f'내려받아 실행·다운로드·흔적 삭제를 한 IP (2순위 {int((bl["tier"] == 2).sum()):,}개는 검토)'),
                ('차단', C.RED, f'다운로드 서버 {len(b["servers"]):,}개로 나가는 연결 차단·확인',
                 '우리 서버에서 이 주소로 접속한 기록이 있으면 감염 의심'),
                ('등록', C.CYAN, f'파일 해시 {fs["unique_hashes"]:,}개 백신·EDR 등록', '내부 서버에서 같은 파일 검색'),
                ('점검', C.AMBER, '외부에 열린 Telnet·IoT 장비 점검',
                 telnet['근거'].iloc[0] if len(telnet) else 'Telnet 접속 비율 확인'),
                ('반영', C.VIOLET, '비밀번호 금지 목록 반영', '공격에 쓰인 아이디·비밀번호와 같은 계정이 없는지 점검')]
        st.markdown('<div class="hp-todo">' + ''.join(
            f'<div class="row"><span class="act" style="--c:{c}">{k_}</span><div><div class="a">{escape(a)}</div>'
            f'<div class="b">{escape(d_)}</div></div></div>' for k_, c, a, d_ in todo) + '</div>', unsafe_allow_html=True)
        a, b_ = st.columns(2)
        with a:
            st.page_link(st.session_state['pages']['intel'], label='위협 정보(IOC)에서 목록·CSV 보기 →')
        with b_:
            _ver, _f = version, f
            st.download_button('보고서 내려받기 (Markdown)', lambda: report_cached(_ver, _f).encode('utf-8'),
                               file_name=f'honeypot_report_{f.start:%Y%m%d}_{f.end:%Y%m%d}.md', mime='text/markdown',
                               help='규모·주요 위협·IOC·권장 조치를 한 장으로 정리합니다. 누를 때 만듭니다.')
with right:
    with C.card(f"새로 나타난 것 · {br['label']}", help='그 기간 전까지의 보유 데이터에 없던 항목만 셉니다.'):
        rows = [('새 다운로드 서버', len(br['new_servers']), C.ORANGE,
                 ', '.join(br['new_servers']['host'].head(3)) if len(br['new_servers']) else ''),
                ('새 파일 해시', len(br['new_hashes']), C.LIME, ', '.join(D.short_hash(h) for h in br['new_hashes'][:2])),
                ('새 위험 행동 IP', len(br['new_danger_ips']), C.RED,
                 ', '.join(br['new_danger_ips']['src_ip'].map(D.mask_ip).head(3)) if len(br['new_danger_ips']) else ''),
                ('처음 관측된 행동', len(br['new_rules']), C.VIOLET, ', '.join(n for _, n in br['new_rules'][:2]))]
        st.markdown('<div class="hp-new">' + ''.join(
            f'<div class="row"><div class="n" style="color:{c if n else C.MUTED}">{n:,}</div>'
            f'<div><div class="a">{escape(lab)}</div><div class="b">{escape(ex) if ex else "-"}</div></div></div>'
            for lab, n, c, ex in rows) + '</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------- ④ 규모
k, prev = D.kpis(sc), D.compare(ds, f)


def delta(key):
    if prev is None or k[key] is None:
        return None
    return D.change(k[key], prev[key])


cmp_note = f'직전 {f.days}일 대비' if prev else ''
with C.card('규모', help='세션은 시작 시각, 인증은 이벤트 시각 기준. 우선 확인 = 위험도 높음 행동이 관측된 고유 세션. '
                         '아래 막대: 허니팟별 비율과 IP 집중도(상위 IP가 차지하는 세션 비율).'):
    cols = st.columns(6)
    rate = f"성공률 {k['auth_success'] / k['auth'] * 100:.1f}%" if k['auth'] else ('미수집' if k['auth'] is None else '')
    tiles = [('접속 세션', f"{k['sessions']:,}", C.CYAN, cmp_note, delta('sessions')),
             ('공격 IP', f"{k['ips']:,}", C.VIOLET, cmp_note, delta('ips')),
             ('인증 시도', '미수집' if k['auth'] is None else f"{k['auth']:,}", C.PINK, rate, delta('auth')),
             ('명령 입력 세션', f"{k['command_sessions']:,}", C.LIME, f"명령 {k['commands']:,}줄", delta('command_sessions')),
             ('우선 확인 세션', f"{k['priority']:,}", C.RED, '위험도 높음', delta('priority')),
             ('파일 다운로드', f"{b['files']['downloads']:,}", C.ORANGE, f"실패 {b['files']['failed']:,}", None)]
    for col, (lab, val, color, sub, dl) in zip(cols, tiles):
        with col:
            C.kpi(lab, val, color, sub, dl)
    l2, r2 = st.columns(2)
    with l2:
        src = D.source_split(sc)
        C.share_bar('허니팟별 접속 비율',
                    [(r.name, r.percent, C.SOURCE_COLORS.get(r.name, C.MUTED), f'{r.name} {r.sessions:,} ({r.percent:.1f}%)')
                     for r in src.itertuples()])
    with r2:
        conc = b['conc']
        if conc['total']:
            pc = conc['parts']['percent'].tolist()
            C.share_bar('IP 집중도 (상위 IP가 차지하는 세션 비율)', [
                ('1위', pc[0], C.RED, f"1위 {D.mask_ip(conc['top1_ip'])} {pc[0]:.0f}%"),
                ('2~3위', pc[1], C.AMBER, f'2~3위 {pc[1]:.0f}%'),
                ('나머지', pc[2], C.MUTED, f"나머지 {max(conc['ips'] - 3, 0):,}개 IP {pc[2]:.0f}%")])

if k['sessions'] == 0:
    st.info('이 범위에 접속 세션이 없습니다.')
    st.stop()

partial = [s_['name'] for s_ in status if s_['last_event'] is not None and s_['last_event'].date() <= f.end]
if partial and not f.full_period:
    st.caption(f"⚠ {', '.join(partial)}의 마지막 수집일은 하루치가 다 들어오지 않아 변화율이 실제보다 낮게 보일 수 있습니다.")

# ---------------------------------------------------------------- ⑤ 추이 + 출발지
left, right = st.columns([1.15, 1])
with left:
    with C.card(f'{"시간별" if f.days == 1 else "일별"} 접속', help='막대는 세션 수(KST), 점선은 평균입니다.'):
        split_by = st.segmented_control('구분', ['프로토콜', '허니팟'], default='프로토콜', key='tl_split',
                                        label_visibility='collapsed') or '프로토콜'
        by = 'protocol' if split_by == '프로토콜' else 'source'
        tl, grain = D.timeline(sc, by)
        tl = tl.rename(columns={by: 'group'})
        unit = '시간' if grain == 'h' else '일'
        palette = C.PROTOCOL_COLORS if by == 'protocol' else C.SOURCE_COLORS
        groups_ = [p for p in palette if p in set(tl['group'])]
        avg = float(tl.groupby('bucket')['sessions'].sum().mean()) if len(tl) else 0.0
        bars = alt.Chart(tl).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
            x=alt.X('bucket:T', title=None, axis=alt.Axis(format='%H시' if grain == 'h' else '%m-%d', labelAngle=0, grid=False)),
            y=alt.Y('sessions:Q', title=None, stack=True, axis=alt.Axis(domain=False, ticks=False, format=',.0f')),
            color=alt.Color('group:N', title=None, scale=alt.Scale(domain=groups_, range=[palette[p] for p in groups_]),
                            legend=alt.Legend(orient='top', labelExpr='upper(datum.label)' if by == 'protocol' else 'datum.label')),
            tooltip=[alt.Tooltip('bucket:T', title='시각', format='%m-%d %H:00' if grain == 'h' else '%m-%d'),
                     alt.Tooltip('group:N', title=split_by), alt.Tooltip('sessions:Q', title='세션', format=',')])
        rule = alt.Chart(pd.DataFrame({'avg': [avg]})).mark_rule(color='#b4bfca', strokeDash=[4, 4]).encode(y='avg:Q')
        label = alt.Chart(pd.DataFrame({'avg': [avg], 'text': [f'평균 {avg:,.0f}/{unit}']})).mark_text(
            align='left', dx=4, dy=-7, color='#b4bfca', fontSize=11).encode(y='avg:Q', x=alt.value(0), text='text:N')
        C.chart((bars + rule + label).properties(height=230))
with right:
    ct = D.countries(sc)
    unknown = int(ct.loc[ct['country'] == '??', 'sessions'].sum())
    with C.card('공격 출발 국가', help='IP 기반 국가 추정(DB-IP Country Lite)이며 실제 위치가 아닙니다. 한 IP가 많이 반복하면 '
                                    '세션 수와 IP 수가 크게 다릅니다.'):
        metric = st.segmented_control('기준', ['세션 수', 'IP 수'], default='IP 수', key='map_metric',
                                      label_visibility='collapsed') or 'IP 수'
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
                    components.html(C.world_svg(cur, height=215), height=222)
                if play:
                    time.sleep(0.35)
        else:
            with holder:
                components.html(C.world_svg(dict(zip(ct['country'], ct[col])), height=215), height=222)
        top = ct[ct['country'] != '??'].sort_values(col, ascending=False).head(5)
        st.caption(' · '.join(f"{names.get(r.country, r.country)} IP {r.ips:,}·세션 {r.sessions:,}" for r in top.itertuples())
                   + (f' · 위치 미상 {unknown:,}' if unknown else '') + ' · [DB-IP](https://db-ip.com)')

# ---------------------------------------------------------------- ⑥ 위험 행동 · 인증 · 파일
c1, c2, c3 = st.columns([1.25, 1, 1])
with c1:
    dt = b['danger']
    dt = dt[(dt['sessions'] > 0) & (dt['rule_id'] != 'B19')].head(7).reset_index(drop=True)
    with C.card('위험 행동 Top (위험도 순)', help=X.DANGER_HELP + ' 셸 진입 요청(B19)은 거의 모든 봇에 나와 뺐습니다. '
                                                           '자세한 내용은 탐지 분석 페이지에 있습니다.'):
        if dt.empty:
            st.caption('이 범위에서 관측된 위험 행동이 없습니다.')
        else:
            C.bar_list([(r.plain, r.sessions, f'{r.sessions:,} · {r.percent:.0f}%', X.DANGER_COLORS[r.danger])
                        for r in dt.itertuples()],
                       note='세션 수 · 명령 입력 세션 대비 %. 빨강=높음 · 노랑=중간 · 회색=낮음')
with c2:
    au = b['auth']
    with C.card('인증', help='원본 로그의 로그인 성공·실패(세션·시간·IP가 맞는 것). 원본 로그가 없는 출처는 미수집입니다.'):
        if au is None:
            st.info('선택한 출처에 원본 인증 로그가 없어 미수집입니다.')
        else:
            pct = au['success'] / max(au['total'], 1) * 100
            C.share_bar(f"시도 {au['total']:,}건", [('성공', pct, C.PINK, f"성공 {au['success']:,} ({pct:.1f}%)"),
                                                   ('실패', 100 - pct, '#475260', f"실패 {au['failed']:,}")])
            st.markdown('<div class="hp-bars-note" style="margin-top:.4rem">많이 시도된 아이디 / 비밀번호</div>',
                        unsafe_allow_html=True)
            C.bar_list([(v, n, f'{n:,}', C.PINK) for v, n in zip(au['pairs']['value'].head(6), au['pairs']['count'].head(6))])
with c3:
    fs = b['files']
    with C.card('수집 파일', help='Cowrie가 기록한 다운로드·업로드. URL은 링크가 아닙니다. 악성 여부는 확인하지 않았습니다.'):
        tried = max(fs['downloads'] + fs['failed'], 1)
        C.share_bar(f"다운로드 시도 {fs['downloads'] + fs['failed']:,}건",
                    [('성공', fs['downloads'] / tried * 100, C.ORANGE, f"성공 {fs['downloads']:,}"),
                     ('실패', fs['failed'] / tried * 100, '#475260', f"실패 {fs['failed']:,}")])
        files = fs['files'].head(6)
        if files.empty:
            st.caption('이 범위에서 수집된 파일이 없습니다.')
        else:
            st.markdown('<div class="hp-bars-note" style="margin-top:.4rem">최근 받아진 파일 · 세션 수 · 최근 관측</div>',
                        unsafe_allow_html=True)
            C.bar_list([(r.name, r.sessions, f'{r.sessions:,} · {last}', C.ORANGE)
                        for r, last in zip(files.itertuples(), C.dtfmt(files['last'], '%m-%d'))])
        st.caption(f"고유 해시 {fs['unique_hashes']:,}개 · 업로드 {fs['uploads']:,}건 · 전체 목록은 세션 조사 > 수집 파일")

# ---------------------------------------------------------------- ⑦ 반복 IP · 최근 명령
c1, c2 = st.columns([1, 1.5])
with c1:
    ri = b['repeat']
    with C.card('반복 접속 IP', help='세션 수 순위. 활동일은 접속한 날짜 수. 누르면 세션 조사의 IP 상세로 이동합니다.'):
        view = pd.DataFrame({'IP': ri['ip_masked'],
                             '국가': ri['country'].map(lambda c: names.get(c, c) if isinstance(c, str) else '-'),
                             '세션': ri['sessions'], '활동일': ri['days'], '대표 행동': ri['behavior']})
        ev = st.dataframe(view, hide_index=True, width='stretch', height='content', on_select='rerun',
                          selection_mode='single-row', key='ip_pick',
                          column_config={'세션': st.column_config.ProgressColumn('세션', format='%d', min_value=0,
                                                                               max_value=C.max_or_one(ri['sessions']))})
        if ev.selection.rows:
            C.open_detail(ip=ri.iloc[ev.selection.rows[0]]['src_ip'])
with c2:
    rc = b['recent']
    with C.card('최근 입력 명령', help='근거가 "규칙 일치"일 때만 시그니처 탐지입니다. 누르면 세션 조사로 이동합니다.'):
        view = pd.DataFrame({'시각': C.dtfmt(rc['time'], '%m-%d %H:%M'), 'IP': rc['ip_masked'], '명령': rc['command_view'],
                             '행동 설명': rc['behavior'], '근거': rc['basis']})
        ev = st.dataframe(C.style_commands(view), hide_index=True, width='stretch', height='content', on_select='rerun',
                          selection_mode='single-row', key='cmd_pick',
                          column_config={'명령': st.column_config.TextColumn(width='large')})
        if ev.selection.rows:
            r = rc.iloc[ev.selection.rows[0]]
            C.open_detail(source=r['source'], session=r['session_id'])

# ---------------------------------------------------------------- ⑧ 허니팟 상태
hd = b['health']
with C.card('허니팟 상태', help='로그인 성공 후 명령 없이 끊은 비율이 꾸준히 오르면 공격자가 허니팟을 알아챘을 가능성이 있습니다(위장 점검 신호). '
                              '로그인이 30건 미만인 날은 비율이 크게 흔들려 흐리게 표시합니다.'):
    left, right = st.columns([1.6, 1])
    with left:
        if not hd.empty:
            st.caption('일별 · 로그인 성공 후 명령 없이 끊은 비율(%) · 점 크기 = 로그인 수')
            hd = hd.assign(신뢰=hd['reliable'].map({True: '로그인 30건 이상', False: '30건 미만(참고)'}))
            C.chart((alt.Chart(hd).mark_line(color=C.AMBER, strokeWidth=1.5).encode(
                x=alt.X('day:T', title=None, axis=alt.Axis(format='%m-%d', labelAngle=0, grid=False)),
                y=alt.Y('bail:Q', title=None, scale=alt.Scale(domain=[0, 100]), axis=alt.Axis(domain=False, ticks=False)))
                + alt.Chart(hd).mark_circle().encode(
                    x='day:T', y='bail:Q', size=alt.Size('logins:Q', legend=None, scale=alt.Scale(range=[20, 260])),
                    opacity=alt.condition('datum.reliable', alt.value(1), alt.value(0.25)), color=alt.value(C.AMBER),
                    tooltip=[alt.Tooltip('day:T', title='날짜', format='%m-%d'),
                             alt.Tooltip('bail:Q', title='명령 없이 끊음(%)', format='.1f'),
                             alt.Tooltip('logins:Q', title='로그인 성공', format=','), alt.Tooltip('신뢰:N', title='표본')]))
                .properties(height=150))
    with right:
        st.dataframe(pd.DataFrame([{'허니팟': s_['name'], '마지막 이벤트': C.fmt_dt(s_['last_event']),
                                    '가져온 시각': C.fmt_dt(s_['imported_at']),
                                    '수집 공백': f"{s_['empty_hours']}시간" if s_['has_raw_logs'] else '원본 로그 없음'}
                                   for s_ in status]), hide_index=True, width='stretch', height='content')
