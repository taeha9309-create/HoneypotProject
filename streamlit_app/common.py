"""두 페이지가 같이 쓰는 설정, 데이터 적재, 표시 도우미."""
import argparse
from html import escape
import json
import math
import os
from pathlib import Path
import sys

import altair as alt
import pandas as pd
import streamlit as st

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import data as D  # noqa: E402
from match_signatures import load_rules  # noqa: E402

WORLD = ROOT / 'dashboard/assets/world.json'  # handoff 브랜치의 Natural Earth 국가 경계 (Korean names 포함)

# 어두운 관제 화면 팔레트 (템플릿: 검정 배경 + 시안/파랑 막대 + 핑크 강조).
# 같은 대상은 모든 차트에서 같은 색을 쓴다.
CYAN = '#22d3ee'
BLUE = '#2f8fe0'
PINK = '#f472b6'
VIOLET = '#c084fc'
LIME = '#bef264'
AMBER = '#fbbf24'
RED = '#fb7185'
GRID = '#20252c'
AXIS = '#7d8590'
INK = '#e6e8eb'
SURFACE = '#0f1317'
ORANGE = '#fb923c'
PROTOCOL_COLORS = {'ssh': CYAN, 'telnet': ORANGE}
GREEN = '#34d399'
SOURCE_COLORS = {'서울': GREEN, '시드니': VIOLET}
BAR = CYAN
ALERT = RED
MUTED = '#4b5563'


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--data', default=os.environ.get('HONEYPOT_DASHBOARD_DATA', str(D.DEFAULT_DIR)))
    p.add_argument('--rules', default=str(ROOT / 'signatures/rules.yaml'))
    a, _ = p.parse_known_args(sys.argv[1:])
    return Path(a.data).resolve(), Path(a.rules).resolve()


DATA_DIR, RULES_PATH = parse_args()


def _version():
    files = [DATA_DIR / 'dashboard.db', DATA_DIR / 'seoul.db', DATA_DIR / 'syd.db', RULES_PATH]
    return tuple(f.stat().st_mtime_ns if f.exists() else 0 for f in files)


@st.cache_resource(show_spinner='데이터 불러오는 중…')
def _dataset(data_dir, rules_path, version):
    return D.load(data_dir, load_rules(rules_path))


def dataset():
    return _dataset(str(DATA_DIR), str(RULES_PATH), _version())


@st.cache_resource
def world():
    """[{code, name, lon, lat, path}] path는 x=(lon+180)*2, y=(90-lat)*2 좌표계(720x360)의 SVG 경로."""
    if not WORLD.exists():
        return []
    return json.loads(WORLD.read_text(encoding='utf-8'))


def country_names():
    names = {c['code']: c['name'] for c in world() if c['code'] and c['code'] != '-99'}
    names['??'] = '위치 미상'
    return names


def filters():
    return st.session_state['filters']


def open_detail(**kw):
    """세션·IP 상세 화면으로 이동. kw: ip=... 또는 source=..., session=..."""
    st.session_state['detail'] = kw
    st.session_state['_goto_tab'] = 'IP' if 'ip' in kw else '세션'
    st.switch_page(st.session_state['pages']['detail'])


# ---------------------------------------------------------------- 표시 도우미

CSS = """
<style>
.block-container {padding-top: 1.2rem; max-width: 1500px;}
/* Streamlit 기본 개발자 메뉴(Deploy, ⋮)와 상단 장식 줄을 숨긴다. 사이드바 펼치기 버튼은 남긴다. */
[data-testid="stAppDeployButton"], [data-testid="stMainMenu"], [data-testid="stToolbarActions"],
[data-testid="stDecoration"], [data-testid="stStatusWidget"] {display: none !important;}
header[data-testid="stHeader"] {background: transparent; height: 2.2rem;}
/* 사이드바 브랜드·데이터 기준 */
.hp-brand {display: flex; flex-direction: column; margin: .2rem 0 .8rem 0;}
.hp-brand b {font-weight: 900; font-size: 1.05rem; letter-spacing: .06em; color: #f3f4f6;}
.hp-brand span {color: #7d8590; font-size: .75rem;}
.hp-side-info {color: #9aa3ad; font-size: .74rem; line-height: 1.7; border-top: 1px solid #1c2128; padding-top: .6rem;}
.hp-side-info .h {color: #cbd2d9; font-weight: 700; margin-bottom: .1rem;}
.hp-side-info .note {color: #6b7280; margin-top: .3rem;}
.hp-side-info a {color: #7dd3fc;}
/* 본문 맨 위 조회 범위 바 */
.st-key-filter_bar {background: #0f1317; padding: .35rem .9rem .5rem .9rem !important; margin-bottom: .2rem;}
.st-key-filter_bar label p {font-size: .72rem !important; color: #9aa3ad !important; font-weight: 700; letter-spacing: .04em;}
.hp-range {display: flex; flex-direction: column;}
.hp-range span {font-size: .72rem; color: #9aa3ad; font-weight: 700; letter-spacing: .04em; margin-bottom: .25rem;}
.hp-range b {color: #e6e8eb; font-size: .95rem; font-variant-numeric: tabular-nums; padding: .35rem 0;}
/* 같은 줄 카드 높이 맞추기: 열을 줄 높이만큼 늘리고, 열의 마지막 카드가 남은 높이를 채운다(안쪽 스크롤 없음) */
[data-testid="stHorizontalBlock"] {align-items: stretch;}
[data-testid="stColumn"] {display: flex; flex-direction: column;}
[data-testid="stColumn"] > [data-testid="stVerticalBlock"] {flex: 1 1 auto;}
[data-testid="stColumn"] > [data-testid="stVerticalBlock"] > [data-testid="stLayoutWrapper"]:last-child {
    flex: 1 1 auto; display: flex; flex-direction: column;}
[data-testid="stColumn"] > [data-testid="stVerticalBlock"] > [data-testid="stLayoutWrapper"]:last-child > [data-testid="stVerticalBlock"] {
    flex: 1 1 auto;}
h1, h2, h3 {letter-spacing: .02em;}
.hp-head {font-size: 1.55rem; font-weight: 800; letter-spacing: .04em; color: #f3f4f6; text-transform: uppercase;}
.hp-head span {color: #7d8590; font-weight: 700;}
.hp-sub {color: #7d8590; font-size: .82rem; margin-top: .15rem;}
.hp-title {color: #9aa3ad; font-size: .74rem; font-weight: 700; letter-spacing: .06em;
           margin: -.2rem 0 .3rem 0;}
div[data-testid="stVerticalBlockBorderWrapper"] {background: #0f1317; border-color: #1c2128 !important;}
.hp-kpi {padding: .1rem .2rem .2rem .2rem;}
.hp-kpi .lab {font-size: .8rem; font-weight: 600; padding-bottom: .35rem; border-bottom: 1px solid #2a3038;}
.hp-kpi .lab {white-space: nowrap; overflow: hidden; text-overflow: ellipsis;}
.hp-kpi .val {font-size: clamp(1.25rem, 2.1vw, 2.05rem); font-weight: 800; line-height: 1.15; margin-top: .45rem;
              font-variant-numeric: tabular-nums; white-space: nowrap;}
.hp-share {margin-top: .5rem; padding-top: .6rem; border-top: 1px dashed #2a3038;}
.hp-share .ttl {color: #9aa3ad; font-size: .72rem; font-weight: 700; letter-spacing: .06em; margin-bottom: .35rem;}
.hp-share .bar {display: flex; height: 22px; border-radius: 4px; overflow: hidden; background: #1a1f26;}
.hp-share .seg {display: flex; align-items: center; justify-content: center; color: #0b0d10; font-size: .72rem;
                font-weight: 800; white-space: nowrap; overflow: hidden; border-right: 2px solid #0f1317;}
.hp-share .seg:last-child {border-right: none;}
.hp-share .lg {display: flex; flex-wrap: wrap; gap: .15rem .9rem; font-size: .74rem; color: #cbd2d9; margin-top: .4rem;}
.hp-share .nt {color: #7d8590; font-size: .7rem; margin-top: .2rem;}
.hp-kpi .sub {color: #7d8590; font-size: .74rem; margin-top: .15rem; min-height: 1.1rem;}
.hp-kpi .up {color: #fb7185;} .hp-kpi .down {color: #34d399;}
.hp-status {display: flex; gap: 1.6rem; flex-wrap: wrap; color: #7d8590; font-size: .76rem; margin: .4rem 0 .6rem 0;}
.hp-status b {color: #cbd2d9;} .hp-dot {display:inline-block;width:.5rem;height:.5rem;border-radius:50%;margin-right:.35rem;}
.hp-story {font-size: 1.02rem; line-height: 1.7; color: #e6e8eb; margin: .2rem 0 .6rem 0;}
.hp-story code {background: #1a1f26; color: #f472b6; padding: .05rem .35rem; border-radius: 4px;}
.hp-chips {display: flex; flex-wrap: wrap; align-items: center; gap: .35rem; margin: .3rem 0 .2rem 0;}
.hp-chips .arrow {color: #3b434d; font-weight: 800;}
.hp-chip {border: 1px solid; border-radius: 999px; padding: .12rem .6rem; font-size: .76rem; color: #4b5563;}
.hp-chip.on {font-weight: 700; background: rgba(255,255,255,.03);}
.hp-danger {margin-top: .5rem; color: #fb7185; font-weight: 700; font-size: .85rem;}
.hp-flow {padding-right: .4rem;}
.hp-flow-row {display: grid; grid-template-columns: 4.6rem 1.2rem 1fr; gap: .2rem; padding: .15rem 0;}
.hp-flow-row .t {color: #7d8590; font-size: .74rem; padding-top: .25rem; font-variant-numeric: tabular-nums;}
.hp-flow-row .rail {position: relative; display: flex; justify-content: center;}
.hp-flow-row .rail::before {content: ''; position: absolute; top: 0; bottom: -0.3rem; width: 2px; background: #1f252c;}
.hp-flow-row .dot {position: relative; width: .7rem; height: .7rem; border-radius: 50%; margin-top: .35rem;
                   box-shadow: 0 0 0 3px #0f1317;}
.hp-flow-row .body {padding-bottom: .55rem; border-bottom: 1px solid #161b21;}
.hp-flow-row .head {display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap;}
.hp-flow-row .step {font-size: .76rem; font-weight: 800; white-space: nowrap;}
.hp-flow-row .what {font-size: .92rem; color: #f3f4f6; font-weight: 600;}
.hp-flow-row .meta {font-size: .72rem; color: #7d8590; margin-top: .1rem;}
.hp-flow-row .b {padding: 0 .35rem; border-radius: 4px; font-weight: 700;}
.hp-flow-row .b.rule {color: #fb7185; background: rgba(251,113,133,.12);}
.hp-flow-row .b.guess {color: #fbbf24; background: rgba(251,191,36,.12);}
.hp-flow-row .b.none {color: #9aa3ad; background: rgba(154,163,173,.12);}
.hp-flow-row .b.obs {color: #22d3ee; background: rgba(34,211,238,.12);}
.hp-flow-row .b.fail {color: #f87171; background: rgba(248,113,113,.15);}
.hp-flow-row .raw {font-family: ui-monospace, SFMono-Regular, Consolas, monospace; margin: .25rem 0 0 0; padding: .3rem .5rem; background: #0b0e12; border: 1px solid #1a1f26;
                      border-radius: 4px; color: #8b949e; font-size: .72rem; white-space: pre-wrap; word-break: break-all;
                      max-height: 6.5rem; overflow: hidden;}
.hp-flow-more {color: #7d8590; font-size: .78rem; padding: .4rem 0;}
.hp-banner {display: flex; gap: 1rem; align-items: center; border: 1px solid; border-left-width: 6px; border-radius: 8px;
            padding: .7rem 1rem; background: #0f1317; margin: .3rem 0 .4rem 0;}
.hp-banner .lvl {color: #0b0d10; font-weight: 900; font-size: 1.05rem; padding: .35rem .9rem; border-radius: 6px;
                 white-space: nowrap;}
.hp-banner .t1 {color: #f3f4f6; font-weight: 700; font-size: 1rem;}
.hp-banner .t2 {color: #9aa3ad; font-size: .82rem; margin-top: .1rem;}
.hp-todo .row, .hp-new .row {display: flex; gap: .7rem; align-items: flex-start; padding: .38rem 0;
                             border-bottom: 1px solid #161b21;}
.hp-todo .row:last-child, .hp-new .row:last-child {border-bottom: none;}
.hp-todo .bar {width: 4px; align-self: stretch; border-radius: 2px; flex: none;}
.hp-todo .a, .hp-new .a {color: #f3f4f6; font-weight: 700; font-size: .9rem;}
.hp-todo .b, .hp-new .b {color: #7d8590; font-size: .76rem;}
.hp-new .n {font-size: 1.5rem; font-weight: 800; min-width: 2.6rem; text-align: right; line-height: 1.2;
            font-variant-numeric: tabular-nums;}
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)  # 고정 문자열만. 공격자 데이터는 넣지 않는다.


def _dark_theme():
    return {'config': {
        'background': 'transparent',
        'view': {'stroke': None},
        'font': 'sans-serif',
        'axis': {'domainColor': GRID, 'gridColor': GRID, 'tickColor': GRID, 'labelColor': AXIS,
                 'titleColor': AXIS, 'labelFontSize': 11, 'titleFontSize': 11, 'titleFontWeight': 'normal'},
        'legend': {'labelColor': '#cbd2d9', 'titleColor': AXIS, 'labelFontSize': 11, 'symbolType': 'circle'},
        'text': {'color': '#cbd2d9'},
        'title': {'color': INK},
    }}


try:
    alt.theme.register('honeypot_dark', enable=True)(_dark_theme)
except AttributeError:  # altair < 5.5
    alt.themes.register('honeypot_dark', _dark_theme)
    alt.themes.enable('honeypot_dark')


def chart(c, **kw):
    """Streamlit 기본 테마 대신 위 어두운 테마로 그린다."""
    st.altair_chart(c, width='stretch', theme=None, **kw)


BASIS_COLORS = {'규칙 일치': RED, '입력 기반 추정': AMBER, '근거 부족': '#7d8590'}


def style_commands(df):
    """최근 명령 표 색: 시각·프로토콜·근거별로 구분해 흰 글자만 있는 표보다 읽기 쉽게 한다."""
    def basis_color(v):
        return f"color: {BASIS_COLORS.get(v, INK)}; font-weight: 600"

    def row_behavior(row):
        color = BASIS_COLORS.get(row['근거'], INK)
        return [f'color: {color}' if c == '행동 설명' else '' for c in row.index]

    styler = df.style.apply(row_behavior, axis=1) if {'근거', '행동 설명'} <= set(df.columns) else df.style
    rules = [('시각', lambda v: f'color: {AXIS}'), ('IP', lambda v: f'color: {VIOLET}'),
             ('프로토콜', lambda v: f"color: {PROTOCOL_COLORS.get(v, INK)}; font-weight: 600"),
             ('명령', lambda v: 'color: #f3f4f6'), ('근거', basis_color),
             ('탐지 규칙', lambda v: f'color: {CYAN}; font-weight: 600')]
    for col, fn in rules:
        if col in df.columns:
            styler = styler.map(fn, subset=[col])
    return styler


def share_bar(title, segments, note=None):
    """제목이 붙은 한 줄짜리 100% 막대 (HTML). segments: [(짧은 이름, 퍼센트, 색, 자세한 설명)].
    막대 칸 안에 '이름 퍼센트'를 쓰고(칸이 좁으면 생략), 아래에 색 범례와 자세한 값을 쓴다.
    문자열은 대시보드가 만든 값(출처 이름, 가린 IP, 숫자)이며 모두 escape한다."""
    cells, legend = [], []
    for name, pct, color, detail in segments:
        if pct <= 0:
            continue
        inside = f'{escape(name)} {pct:.0f}%' if pct >= 14 else (f'{pct:.0f}%' if pct >= 6 else '')
        cells.append(f'<div class="seg" style="width:{pct:.2f}%;background:{color}" title="{escape(detail)}">{inside}</div>')
        legend.append(f'<span><span class="hp-dot" style="background:{color}"></span>{escape(detail)}</span>')
    html = (f'<div class="hp-share"><div class="ttl">{escape(title)}</div><div class="bar">{"".join(cells)}</div>'
            f'<div class="lg">{"".join(legend)}</div>'
            + (f'<div class="nt">{escape(note)}</div>' if note else '') + '</div>')
    st.markdown(html, unsafe_allow_html=True)


def page_header(title, scope_text, sub=None):
    st.markdown(f'<div class="hp-head">{escape(title)}: <span>{escape(scope_text)}</span></div>',
                unsafe_allow_html=True)
    if sub:
        st.markdown(f'<div class="hp-sub">{escape(sub)}</div>', unsafe_allow_html=True)


def card(title, help=None, height=None):
    """테두리 카드. 같은 줄의 카드는 같은 height를 줘서 높이를 맞춘다(넘치면 카드 안에서 스크롤)."""
    box = st.container(border=True, height=height or 'content')
    box.markdown(f'<div class="hp-title">{escape(title)}</div>', unsafe_allow_html=True, help=help)
    return box


def kpi(label, value, color, sub='', delta=None, bad_up=True):
    """템플릿식 KPI: 색 있는 라벨 + 밑줄 + 큰 숫자. 값은 모두 대시보드가 계산한 숫자·고정 문구다."""
    d = ''
    if delta is not None:
        cls = ('up' if delta > 0 else 'down') if bad_up else ('down' if delta > 0 else 'up')
        d = f'<span class="{cls}">{"▲" if delta > 0 else "▼"} {abs(delta):.0f}%</span> '
    st.markdown(f'<div class="hp-kpi"><div class="lab" style="color:{color}">{escape(label)}</div>'
                f'<div class="val" style="color:{color}">{escape(value)}</div>'
                f'<div class="sub">{d}{escape(sub)}</div></div>', unsafe_allow_html=True)


def fmt_dt(ts, fmt='%m-%d %H:%M'):
    return '-' if ts is None or (hasattr(ts, 'isna') and ts.isna()) or str(ts) == 'NaT' else ts.strftime(fmt)


def hbar(df, y, x, tooltip, text=None, color=BAR, sort='-x', x_title=None, row=26, min_h=120):
    top = float(df[x].max()) if len(df) else 1.0
    base = alt.Chart(df).encode(
        y=alt.Y(f'{y}:N', sort=sort, title=None, axis=alt.Axis(labelLimit=200, labelOverlap=False, domain=False, ticks=False)),
        x=alt.X(f'{x}:Q', title=x_title, scale=alt.Scale(domain=[0, max(top, 1) * (1.4 if text else 1.05)], nice=False),
                axis=alt.Axis(grid=True, domain=False, ticks=False)),
        tooltip=tooltip)
    c = base.mark_bar(color=color, cornerRadiusTopRight=3, cornerRadiusBottomRight=3, height={'band': 0.62})
    if text:
        c = c + base.mark_text(align='left', dx=5, fontSize=11, color='#cbd2d9').encode(text=text)
    return c.properties(height=max(min_h, row * len(df)))


def world_svg(counts, height=300):
    """국가별 원 지도 (SVG). counts: {국가코드: 세션 수}. 국가 이름은 자체 자산에서 오고,
    공격자 문자열은 넣지 않는다(숫자와 국가 이름만)."""
    shapes = world()
    if not shapes:
        return '<p style="color:#7d8590">지도 자료(dashboard/assets/world.json)가 없습니다.</p>'
    hot = {c: n for c, n in counts.items() if c != '??' and n > 0}
    peak = max(hot.values(), default=1)
    centers = {c['code']: (c['lon'], c['lat'], c['name']) for c in shapes if c['code'] != '-99'}
    parts = [f'<body style="margin:0;background:{SURFACE}"><svg viewBox="0 12 720 300" '
             f'style="width:100%;height:{height}px" role="img" aria-label="국가별 접속 세션 지도">']
    for c in shapes:
        fill = '#1d3446' if hot.get(c['code']) else '#1a1f26'
        parts.append(f'<path d="{c["path"]}" fill="{fill}" stroke="{SURFACE}" stroke-width="0.5"/>')
    for code, n in sorted(hot.items(), key=lambda kv: -kv[1]):
        if code not in centers:
            continue
        lon, lat, name = centers[code]
        x, y = (lon + 180) * 2, (90 - lat) * 2
        r = 2.2 + 15 * math.sqrt(n / peak)
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{PINK}" fill-opacity="0.35" '
                     f'stroke="{PINK}" stroke-width="0.9"><title>{escape(name)}: {n:,}세션</title></circle>'
                     f'<circle cx="{x:.1f}" cy="{y:.1f}" r="1.3" fill="#fde7f3"/>')
    parts.append('</svg></body>')
    return ''.join(parts)


def dtfmt(series, fmt='%m-%d %H:%M'):
    """날짜 열을 문자열로. 빈 열·날짜가 아닌 열·NaT도 안전하게 '-'로."""
    if not len(series):
        return series.astype(str)
    s_ = series if pd.api.types.is_datetime64_any_dtype(series) else pd.to_datetime(series, errors='coerce', utc=True)
    return s_.dt.strftime(fmt).fillna('-')


def max_or_one(series):
    """진행 막대 최댓값. 빈 표·NaN이면 1."""
    v = series.max() if len(series) else None
    return int(v) if v is not None and v == v and v > 0 else 1


def compact(df, key, step=10, on_select=None, **kw):
    """표: 처음 step줄만 보여 주고 높이는 내용에 맞춘다(안쪽 스크롤 없음). 남으면 '더 보기'.
    on_select='rerun'이면 선택 이벤트를 돌려준다 (선택 행 번호는 df 기준)."""
    n = st.session_state.get(key, step)
    extra = {'on_select': on_select, 'selection_mode': 'single-row'} if on_select else {}
    ev = st.dataframe(df.head(n), hide_index=True, width='stretch', height='content', key=f'{key}_tbl', **extra, **kw)
    if len(df) > n and st.button(f'더 보기 · {len(df) - n:,}개', key=f'{key}_more', type='tertiary'):
        st.session_state[key] = n + step * 2
        st.rerun()
    return ev
