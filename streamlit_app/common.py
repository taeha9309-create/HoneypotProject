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

# 관제 콘솔 팔레트. CSS의 :root 토큰과 같은 값이다(차트·HTML이 같은 색을 쓰도록 여기서도 정의).
# 강조색은 시안 하나. 빨강·호박·초록은 위험도(의미) 전용, 나머지는 데이터 범주(프로토콜·허니팟·군집)용.
CYAN = '#38d6e8'      # --accent
BLUE = '#5b8def'
ORANGE = '#f0995a'
PINK = '#e77fb3'
VIOLET = '#a48bf5'
LIME = '#a9dc6c'
AMBER = '#f2b84b'     # --warn
RED = '#f0647a'       # --crit
GREEN = '#43cc95'     # --ok
GRID = '#1c242d'      # --line
AXIS = '#7c8896'      # --ink-3
INK = '#e6ebf0'       # --ink
INK_2 = '#b4bfca'     # --ink-2
SURFACE = '#10151b'   # --surface
MUTED = '#475260'
PROTOCOL_COLORS = {'ssh': CYAN, 'telnet': ORANGE}
SOURCE_COLORS = {'서울': GREEN, '시드니': VIOLET}
BAR = CYAN
ALERT = RED


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
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
/* 관제 콘솔: 위에서 아래로 상태 → 할 일 → 규모 → 근거. 카드는 표면색 한 단계로만 구분하고 그림자는 쓰지 않는다. */
:root {
  --bg: #0b0e12; --surface: #10151b; --surface-2: #151c24; --line: #1c242d; --line-2: #27313c;
  --ink: #e6ebf0; --ink-2: #b4bfca; --ink-3: #7c8896; --ink-4: #4e5966;
  --accent: #38d6e8; --crit: #f0647a; --warn: #f2b84b; --ok: #43cc95;
  --font-display: 'Space Grotesk', 'IBM Plex Sans KR', system-ui, sans-serif;
  --font-mono: 'IBM Plex Mono', ui-monospace, Consolas, monospace;
  --fs-xs: .72rem; --fs-sm: .8rem; --fs-md: .9rem; --fs-lg: 1.05rem; --fs-xl: 1.55rem;
  --fs-num: clamp(1.3rem, 2vw, 1.95rem);
  color-scheme: dark;
}
.block-container {padding-top: 1.1rem; max-width: 1480px;}
:focus-visible {outline: 2px solid var(--accent) !important; outline-offset: 2px;}
@media (prefers-reduced-motion: reduce) {* {animation: none !important; transition: none !important;}}
/* Streamlit 개발자 메뉴(Deploy, ⋮)와 장식 줄 숨김. 사이드바 펼치기 버튼은 남긴다. */
[data-testid="stAppDeployButton"], [data-testid="stMainMenu"], [data-testid="stToolbarActions"],
[data-testid="stDecoration"], [data-testid="stStatusWidget"] {display: none !important;}
header[data-testid="stHeader"] {background: transparent; height: 2.2rem;}

/* 카드 제목: 작은 대문자 라벨 */
.hp-title {color: var(--ink-3); font-size: var(--fs-xs); font-weight: 600; letter-spacing: .08em; text-transform: uppercase;}

/* 사이드바 */
.hp-brand {display: flex; flex-direction: column; gap: .15rem; margin: .1rem 0 .9rem 0;}
.hp-brand b {font-family: var(--font-display); font-weight: 700; font-size: 1.05rem; letter-spacing: .16em; color: var(--ink);}
.hp-brand b i {display: inline-block; width: .5rem; height: .5rem; border-radius: 1px; background: var(--accent);
               margin-right: .55rem; transform: rotate(45deg) translateY(-.12rem);}
.hp-brand span {color: var(--ink-3); font-size: var(--fs-xs);}
.hp-side-info {color: var(--ink-3); font-size: var(--fs-xs); line-height: 1.75; border-top: 1px solid var(--line); padding-top: .7rem;}
.hp-side-info .h {color: var(--ink-2); font-weight: 600; letter-spacing: .06em; margin-bottom: .15rem;}
.hp-side-info .note {color: var(--ink-4); margin-top: .3rem;}
.hp-side-info a {color: var(--accent);}

/* 조회 범위 바 */
.st-key-filter_bar {background: var(--surface); padding: .3rem .9rem .5rem .9rem !important; margin-bottom: .15rem;}
.st-key-filter_bar label p {font-size: var(--fs-xs) !important; color: var(--ink-3) !important; font-weight: 600;
                            letter-spacing: .06em;}
.hp-range {display: flex; flex-direction: column;}
.hp-range span {font-size: var(--fs-xs); color: var(--ink-3); font-weight: 600; letter-spacing: .06em; margin-bottom: .25rem;}
.hp-range b {color: var(--ink); font-family: var(--font-mono); font-weight: 500; font-size: var(--fs-md); padding: .35rem 0;}

/* 페이지 머리 */
.hp-head {font-family: var(--font-display); font-size: var(--fs-xl); font-weight: 700; color: var(--ink);
          text-wrap: balance; line-height: 1.25;}
.hp-head span {color: var(--ink-3); font-weight: 500;}
.hp-sub {color: var(--ink-3); font-size: var(--fs-sm); margin-top: .2rem; max-width: 75ch;}

/* 같은 줄 카드 높이 맞추기 (안쪽 스크롤 없이) */
[data-testid="stHorizontalBlock"] {align-items: stretch;}
[data-testid="stColumn"] {display: flex; flex-direction: column;}
[data-testid="stColumn"] > [data-testid="stVerticalBlock"] {flex: 1 1 auto;}
[data-testid="stColumn"] > [data-testid="stVerticalBlock"] > [data-testid="stLayoutWrapper"]:last-child {
    flex: 1 1 auto; display: flex; flex-direction: column;}
[data-testid="stColumn"] > [data-testid="stVerticalBlock"] > [data-testid="stLayoutWrapper"]:last-child > [data-testid="stVerticalBlock"] {
    flex: 1 1 auto;}

/* KPI: 색 라벨 + 가는 선 + 큰 숫자(디스플레이 글꼴, 고정폭 숫자) */
.hp-kpi {padding: .05rem .15rem .15rem .15rem;}
.hp-kpi .lab {font-size: var(--fs-xs); font-weight: 600; letter-spacing: .04em; padding-bottom: .35rem;
              border-bottom: 1px solid var(--line-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;}
.hp-kpi .val {font-family: var(--font-display); font-size: var(--fs-num); font-weight: 600; line-height: 1.15; margin-top: .4rem;
              font-variant-numeric: tabular-nums; white-space: nowrap;}
.hp-kpi .sub {color: var(--ink-3); font-size: var(--fs-xs); margin-top: .15rem; min-height: 1.1rem;}
.hp-kpi .up {color: var(--crit);} .hp-kpi .down {color: var(--ok);}

/* 비율 막대 */
.hp-share {margin-top: .55rem; padding-top: .6rem; border-top: 1px dashed var(--line-2);}
.hp-share .ttl {color: var(--ink-3); font-size: var(--fs-xs); font-weight: 600; letter-spacing: .06em; margin-bottom: .35rem;}
.hp-share .bar {display: flex; height: 20px; border-radius: 4px; overflow: hidden; background: var(--surface-2);}
.hp-share .seg {display: flex; align-items: center; justify-content: center; color: var(--bg); font-size: var(--fs-xs);
                font-weight: 700; white-space: nowrap; overflow: hidden; border-right: 2px solid var(--surface);}
.hp-share .seg:last-child {border-right: none;}
.hp-share .lg {display: flex; flex-wrap: wrap; gap: .15rem .9rem; font-size: var(--fs-xs); color: var(--ink-2); margin-top: .4rem;}
.hp-share .nt {color: var(--ink-3); font-size: var(--fs-xs); margin-top: .2rem;}
.hp-dot {display: inline-block; width: .5rem; height: .5rem; border-radius: 50%; margin-right: .35rem;}

/* 순위 막대 목록: 라벨 | 막대 | 값 (좁으면 라벨이 위로) */
.hp-bars {display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr) auto; gap: .32rem .6rem;
          align-items: center; font-size: var(--fs-sm); margin: .2rem 0 .3rem 0;}
.hp-bars .r {display: contents;}
.hp-bars .l {color: var(--ink-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; text-align: right;}
.hp-bars .t {height: 10px; background: var(--surface-2); border-radius: 2px; overflow: hidden;}
.hp-bars .f {height: 100%; border-radius: 2px;}
.hp-bars .v {color: var(--ink); font-family: var(--font-mono); font-size: var(--fs-xs); white-space: nowrap; text-align: right;}
.hp-bars-note {color: var(--ink-3); font-size: var(--fs-xs); margin-top: .2rem;}
@media (max-width: 1100px) {
  .hp-bars {grid-template-columns: minmax(0, 1fr) auto;}
  .hp-bars .l {grid-column: 1 / -1; text-align: left; margin-bottom: -.15rem;}
}

/* 데이터 상태 줄 */
.hp-status {display: flex; gap: 1.6rem; flex-wrap: wrap; color: var(--ink-3); font-size: var(--fs-xs); margin: .35rem 0 .55rem 0;}
.hp-status b {color: var(--ink-2); font-weight: 600;}

/* 상황 배너: 위험도 색으로 옅게 칠한 띠 + 등급 칩 (테두리 레일 없음). --sev는 화면에서 넣는다 */
.hp-banner {--sev: var(--crit); display: flex; gap: 1rem; align-items: center; border-radius: 8px; padding: .75rem 1rem;
            border: 1px solid color-mix(in srgb, var(--sev) 45%, transparent);
            background: color-mix(in srgb, var(--sev) 9%, var(--bg)); margin: .3rem 0 .35rem 0;}
.hp-banner .lvl {color: var(--bg); background: var(--sev); font-family: var(--font-display); font-weight: 700;
                 font-size: var(--fs-md); letter-spacing: .08em; padding: .3rem .85rem; border-radius: 4px; white-space: nowrap;}
.hp-banner .t1 {color: var(--ink); font-weight: 600; font-size: var(--fs-md); text-wrap: balance;}
.hp-banner .t2 {color: var(--ink-2); font-size: var(--fs-sm); margin-top: .15rem;}

/* 지금 할 일: 조치 종류 칩 + 내용 / 새로 나타난 것: 큰 숫자 + 내용 */
.hp-todo .row, .hp-new .row {display: flex; gap: .75rem; align-items: flex-start; padding: .45rem 0; border-bottom: 1px solid var(--line);}
.hp-todo .row:last-child, .hp-new .row:last-child {border-bottom: none;}
.hp-todo .act {--c: var(--accent); flex: none; width: 3.1rem; text-align: center; font-size: var(--fs-xs); font-weight: 700;
               color: var(--c); border: 1px solid color-mix(in srgb, var(--c) 55%, transparent);
               background: color-mix(in srgb, var(--c) 10%, transparent); border-radius: 4px; padding: .1rem 0; margin-top: .1rem;}
.hp-todo .a, .hp-new .a {color: var(--ink); font-weight: 600; font-size: var(--fs-md);}
.hp-todo .b, .hp-new .b {color: var(--ink-3); font-size: var(--fs-xs); margin-top: .1rem;}
.hp-new .n {font-family: var(--font-display); font-size: 1.45rem; font-weight: 600; min-width: 2.4rem; text-align: right;
            line-height: 1.15; font-variant-numeric: tabular-nums;}

/* 세션 이야기 */
.hp-story {font-size: var(--fs-lg); line-height: 1.75; color: var(--ink); margin: .2rem 0 .6rem 0; max-width: 80ch;}
.hp-story code {background: var(--surface-2); color: var(--accent); font-family: var(--font-mono); padding: .05rem .35rem; border-radius: 3px;}
.hp-chips {display: flex; flex-wrap: wrap; align-items: center; gap: .35rem; margin: .3rem 0 .2rem 0;}
.hp-chips .arrow {color: var(--ink-4); font-weight: 700;}
.hp-chip {border: 1px solid; border-radius: 4px; padding: .1rem .55rem; font-size: var(--fs-xs); color: var(--ink-4);}
.hp-chip.on {font-weight: 600;}
.hp-danger {margin-top: .5rem; color: var(--crit); font-weight: 600; font-size: var(--fs-sm);}

/* 시간순 흐름 */
.hp-flow {padding-right: .4rem;}
.hp-flow-row {display: grid; grid-template-columns: 4.6rem 1.2rem 1fr; gap: .2rem; padding: .15rem 0;}
.hp-flow-row .t {color: var(--ink-3); font-family: var(--font-mono); font-size: var(--fs-xs); padding-top: .25rem;}
.hp-flow-row .rail {position: relative; display: flex; justify-content: center;}
.hp-flow-row .rail::before {content: ''; position: absolute; top: 0; bottom: -0.3rem; width: 1px; background: var(--line-2);}
.hp-flow-row .dot {position: relative; width: .6rem; height: .6rem; border-radius: 50%; margin-top: .4rem; box-shadow: 0 0 0 3px var(--bg);}
.hp-flow-row .body {padding-bottom: .55rem; border-bottom: 1px solid var(--line); min-width: 0;}
.hp-flow-row .head {display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap;}
.hp-flow-row .step {font-size: var(--fs-xs); font-weight: 700; letter-spacing: .04em; white-space: nowrap;}
.hp-flow-row .what {font-size: var(--fs-md); color: var(--ink); font-weight: 600;}
.hp-flow-row .meta {font-size: var(--fs-xs); color: var(--ink-3); margin-top: .1rem;}
.hp-flow-row .b {padding: 0 .35rem; border-radius: 3px; font-weight: 600;}
.hp-flow-row .b.rule {color: var(--crit); background: color-mix(in srgb, var(--crit) 13%, transparent);}
.hp-flow-row .b.guess {color: var(--warn); background: color-mix(in srgb, var(--warn) 13%, transparent);}
.hp-flow-row .b.none {color: var(--ink-3); background: color-mix(in srgb, var(--ink-3) 13%, transparent);}
.hp-flow-row .b.obs {color: var(--accent); background: color-mix(in srgb, var(--accent) 13%, transparent);}
.hp-flow-row .b.fail {color: var(--crit); background: color-mix(in srgb, var(--crit) 16%, transparent);}
.hp-flow-row .raw {font-family: var(--font-mono); margin: .3rem 0 0 0; padding: .35rem .55rem; background: var(--bg);
                   border: 1px solid var(--line); border-radius: 4px; color: var(--ink-3); font-size: var(--fs-xs);
                   white-space: pre-wrap; word-break: break-all; max-height: 6.5rem; overflow: hidden;}
.hp-flow-more {color: var(--ink-3); font-size: var(--fs-sm); padding: .4rem 0;}
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)  # 고정 문자열만. 공격자 데이터는 넣지 않는다.


def _dark_theme():
    return {'config': {
        'background': 'transparent',
        'view': {'stroke': None},
        'font': "'IBM Plex Sans KR', sans-serif",
        'axis': {'domainColor': GRID, 'gridColor': GRID, 'tickColor': GRID, 'labelColor': AXIS,
                 'titleColor': AXIS, 'labelFontSize': 11, 'titleFontSize': 11, 'titleFontWeight': 'normal'},
        'legend': {'labelColor': INK_2, 'titleColor': AXIS, 'labelFontSize': 11, 'symbolType': 'circle'},
        'text': {'color': INK_2},
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


BASIS_COLORS = {'규칙 일치': RED, '입력 기반 추정': AMBER, '근거 부족': AXIS}


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
             ('명령', lambda v: f'color: {INK}'), ('근거', basis_color),
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


def bar_list(rows, note=None):
    """폭에 맞춰 줄어드는 순위 막대 (HTML). rows: [(라벨, 값, 표시 문자열, 색)].
    라벨은 넘치면 말줄임하고 마우스를 올리면 전체를 보여 준다. 숫자는 항상 오른쪽 끝에 고정.
    라벨에 공격자 문자열(계정 등)이 올 수 있으므로 모두 escape한다."""
    if not rows:
        return
    top = max((v for _, v, _, _ in rows), default=0) or 1
    html = ['<div class="hp-bars">']
    for label, v, text, color in rows:
        w = max(1.5, v / top * 100) if v else 0
        html.append(f'<div class="r"><div class="l" title="{escape(str(label))}">{escape(str(label))}</div>'
                    f'<div class="t"><div class="f" style="width:{w:.1f}%;background:{color}"></div></div>'
                    f'<div class="v">{escape(str(text))}</div></div>')
    html.append('</div>')
    if note:
        html.append(f'<div class="hp-bars-note">{escape(note)}</div>')
    st.markdown(''.join(html), unsafe_allow_html=True)


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
