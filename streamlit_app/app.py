"""허니팟 공격 분석 대시보드 (Streamlit, 읽기 전용). 기획: docs/dashboard-plan-v2.ko.md

준비 (한 번, 로그를 새로 가져올 때마다):
    python streamlit_app/build_db.py --seoul-logs <서울 로그 폴더> --syd-db <시드니 DB> --geo work/geo/dbip-country-ipv4.csv
실행:
    streamlit run streamlit_app/app.py
"""
from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402
import data as D  # noqa: E402

st.set_page_config(page_title='허니팟 대시보드', layout='wide', page_icon='🛡️')

try:
    ds = C.dataset()
except FileNotFoundError as e:
    st.error(str(e))
    st.code('python streamlit_app/build_db.py --seoul-logs <서울 로그 폴더> --syd-db <시드니 DB> '
            '--geo work/geo/dbip-country-ipv4.csv', language='bash')
    st.stop()

first, last = D.data_range(ds)
with st.sidebar:
    st.markdown('<div style="font-weight:900;font-size:1.05rem;letter-spacing:.06em">🛡️ HONEYPOT</div>'
                '<div style="color:#7d8590;font-size:.75rem;margin-bottom:.6rem">SSH·Telnet 공격 분석 대시보드</div>',
                unsafe_allow_html=True)
    st.subheader('조회 범위')
    mode = st.radio('기간', ['전체 기간', '하루', '기간 지정'], horizontal=True, label_visibility='collapsed',
                    key='period_mode')
    if mode == '하루':
        day = st.date_input('날짜 (KST)', value=last, min_value=first, max_value=last, key='day')
        start, end = day, day
    elif mode == '기간 지정':
        picked = st.date_input('시작일 ~ 종료일 (KST)', value=(first, last), min_value=first, max_value=last,
                               key='range')
        start, end = (picked if isinstance(picked, (tuple, list)) and len(picked) == 2 else (first, last))
    else:
        start, end = first, last
    all_sources = list(ds.sources['source'])
    sources = st.multiselect('허니팟', all_sources, default=all_sources, key='sources',
                             format_func=lambda s: D.SOURCE_NAMES.get(s, s))
    all_protocols = sorted(ds.sessions['protocol'].dropna().unique())
    protocols = st.multiselect('프로토콜', all_protocols, default=all_protocols, key='protocols')
    st.caption('모든 카드·그래프·목록에 같은 범위가 적용됩니다. 시각은 KST, 테스트 접속은 제외됩니다.')
    for w in ds.warnings:
        st.warning(w)
    st.divider()
    st.caption('**데이터 기준**')
    for r in ds.sources.itertuples():
        st.caption(f"· {D.SOURCE_NAMES.get(r.source, r.source)}: {r.first_event:%m-%d} ~ {r.last_event:%m-%d %H:%M} KST"
                   + ('' if r.has_raw_logs else ' (DB 사본)'))
    built = ds.sources['imported_at'].max()
    st.caption(f"· 빌드 {built:%m-%d %H:%M} · 탐지 규칙 {ds.meta.get('rules_commit', '?')}")
    st.caption('· 국가: [DB-IP](https://db-ip.com) Country Lite')

st.session_state['filters'] = D.Filters(tuple(sources), tuple(protocols), start, end, mode == '전체 기간')

here = Path(__file__).resolve().parent / 'views'
pages = {'overview': st.Page(str(here / 'overview.py'), title='Overview', icon='📊', default=True),
         'detail': st.Page(str(here / 'investigate.py'), title='세션 조사', icon='🔎'),
         'detection': st.Page(str(here / 'detection.py'), title='탐지 분석', icon='🛡️'),
         'patterns': st.Page(str(here / 'patterns.py'), title='패턴 분석 (ML)', icon='🧩'),
         'intel': st.Page(str(here / 'intel.py'), title='위협 정보 (IOC)', icon='🚫')}
st.session_state['pages'] = pages
st.navigation(list(pages.values())).run()
