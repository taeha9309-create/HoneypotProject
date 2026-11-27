"""허니팟 공격 분석 대시보드 (Streamlit, 읽기 전용). 기획: docs/dashboard-plan-v2.ko.md

준비 (한 번, 로그를 새로 가져올 때마다):
    python streamlit_app/build_db.py --seoul-logs <서울 로그 폴더> --syd-db <시드니 DB> --geo work/geo/dbip-country-ipv4.csv --ml
실행:
    streamlit run streamlit_app/app.py

화면 구성: 왼쪽 사이드바 = 메뉴·데이터 기준, 본문 맨 위 = 조회 범위(모든 페이지 공통), 그 아래 = 각 페이지.
"""
from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402
import data as D  # noqa: E402

st.set_page_config(page_title='허니팟 대시보드', layout='wide', page_icon=':material/shield:')
C.inject_css()

try:
    ds = C.dataset()
except FileNotFoundError as e:
    st.error(str(e))
    st.code('python streamlit_app/build_db.py --seoul-logs <서울 로그 폴더> --syd-db <시드니 DB> '
            '--geo work/geo/dbip-country-ipv4.csv --ml', language='bash')
    st.stop()

first, last = D.data_range(ds)

# ---------------------------------------------------------------- 사이드바: 브랜드 + 데이터 기준 (메뉴는 st.navigation이 위에 그린다)
with st.sidebar:
    st.markdown('<div class="hp-brand"><b><i></i>HONEYPOT</b><span>SSH·Telnet 공격 분석 대시보드</span></div>',
                unsafe_allow_html=True)
    for w in ds.warnings:
        st.warning(w)
    lines = [f"{D.SOURCE_NAMES.get(r.source, r.source)} {r.first_event:%m-%d} ~ {r.last_event:%m-%d %H:%M}"
             + ('' if r.has_raw_logs else ' (DB 사본)') for r in ds.sources.itertuples()]
    built = ds.sources['imported_at'].max()
    st.markdown('<div class="hp-side-info"><div class="h">데이터 기준 (KST)</div>'
                + ''.join(f'<div>{x}</div>' for x in lines)
                + f"<div>빌드 {built:%m-%d %H:%M} · 규칙 {ds.meta.get('rules_commit', '?').split(' ')[0]}</div>"
                + '<div>국가: <a href="https://db-ip.com" target="_blank">DB-IP</a> Country Lite</div>'
                + '<div class="note">테스트 접속은 제외됩니다.</div></div>', unsafe_allow_html=True)

# ---------------------------------------------------------------- 본문 맨 위: 조회 범위 (모든 페이지 공통)
all_sources = list(ds.sources['source'])
all_protocols = sorted(ds.sessions['protocol'].dropna().unique())
with st.container(border=True, key='filter_bar'):
    c1, c2, c3, c4 = st.columns([1.15, 1.25, 1, 0.9], vertical_alignment='center')
    with c1:
        mode = st.segmented_control('기간', ['전체 기간', '하루', '기간 지정'], default='전체 기간',
                                    key='period_mode') or '전체 기간'
    with c2:
        if mode == '하루':
            day = st.date_input('날짜 (KST)', value=last, min_value=first, max_value=last, key='day')
            start, end = day, day
        elif mode == '기간 지정':
            picked = st.date_input('시작일 ~ 종료일 (KST)', value=(first, last), min_value=first, max_value=last,
                                   key='range')
            start, end = (picked if isinstance(picked, (tuple, list)) and len(picked) == 2 else (first, last))
        else:
            start, end = first, last
            st.markdown(f'<div class="hp-range"><span>조회 기간 (KST)</span><b>{first:%Y-%m-%d} ~ {last:%Y-%m-%d}</b></div>',
                        unsafe_allow_html=True)
    with c3:
        sources = st.pills('허니팟', all_sources, selection_mode='multi', default=all_sources, key='sources',
                           format_func=lambda s: D.SOURCE_NAMES.get(s, s)) or []
    with c4:
        protocols = st.pills('프로토콜', all_protocols, selection_mode='multi', default=all_protocols, key='protocols',
                             format_func=str.upper) or []

st.session_state['filters'] = D.Filters(tuple(sources), tuple(protocols), start, end, mode == '전체 기간')

here = Path(__file__).resolve().parent / 'views'
pages = {'home': st.Page(str(here / 'home.py'), title='홈', icon=':material/home:', default=True),
         'overview': st.Page(str(here / 'overview.py'), title='상세 현황', icon=':material/monitoring:'),
         'detail': st.Page(str(here / 'investigate.py'), title='세션 조사', icon=':material/manage_search:'),
         'detection': st.Page(str(here / 'detection.py'), title='탐지 분석', icon=':material/policy:'),
         'patterns': st.Page(str(here / 'patterns.py'), title='패턴 분석 (ML)', icon=':material/hub:'),
         'intel': st.Page(str(here / 'intel.py'), title='위협 정보 (IOC)', icon=':material/block:')}
st.session_state['pages'] = pages
st.navigation(list(pages.values())).run()
