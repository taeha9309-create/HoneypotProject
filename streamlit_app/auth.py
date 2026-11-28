"""대시보드 비밀번호 보호 (선택).

환경변수 HONEYPOT_DASH_PASSWORD가 설정돼 있을 때만 켜진다. 없으면 인증 없이 열린다(로컬 개발용).
비밀번호는 코드나 git에 두지 않는다. 일반 비밀번호 또는 `sha256:<hex>` 형태의 해시를 쓸 수 있다.
틀린 횟수가 MAX_FAILS번이면 모든 접속에 LOCK_SECONDS초 동안 입력을 막는다(접속자 구분 없이 서버 전체 기준).
"""
import hashlib
import hmac
import os
import time

ENV = 'HONEYPOT_DASH_PASSWORD'
MAX_FAILS = 5
LOCK_SECONDS = 60


def configured(env=None):
    return bool((env if env is not None else os.environ).get(ENV, ''))


def check_password(given, env=None):
    """입력값이 설정된 비밀번호와 같은지(상수 시간 비교). 설정이 없으면 False."""
    expected = (env if env is not None else os.environ).get(ENV, '')
    if not expected or not given:
        return False
    if expected.startswith('sha256:'):
        digest = hashlib.sha256(given.encode('utf-8')).hexdigest()
        return hmac.compare_digest(digest, expected[7:].strip().lower())
    return hmac.compare_digest(given.encode('utf-8'), expected.encode('utf-8'))


class Throttle:
    """틀린 횟수 제한. now는 시간 함수(테스트용으로 바꿀 수 있다)."""

    def __init__(self, max_fails=MAX_FAILS, lock_seconds=LOCK_SECONDS, now=time.monotonic):
        self.max_fails, self.lock_seconds, self.now = max_fails, lock_seconds, now
        self.fails = 0
        self.locked_until = 0.0

    def remaining(self):
        """잠겨 있으면 남은 초, 아니면 0."""
        left = self.locked_until - self.now()
        return max(0, int(left) + (1 if left > 0 else 0))

    def fail(self):
        self.fails += 1
        if self.fails >= self.max_fails:
            self.locked_until = self.now() + self.lock_seconds
            self.fails = 0

    def ok(self):
        self.fails = 0


def gate():
    """app.py 맨 위에서 호출한다. 인증되지 않았으면 입력창만 그리고 st.stop()."""
    import streamlit as st

    if not configured():
        return
    if st.session_state.get('hp_authed'):
        with st.sidebar:
            if st.button('로그아웃', key='hp_logout', icon=':material/logout:'):
                st.session_state['hp_authed'] = False
                st.rerun()
        return

    @st.cache_resource
    def _throttle():
        return Throttle()

    th = _throttle()
    st.markdown('<div style="max-width:380px;margin:12vh auto 0 auto"><h3>HONEYPOT 대시보드</h3>'
                '<p style="opacity:.7">관리자 비밀번호를 입력하세요.</p></div>', unsafe_allow_html=True)
    _, mid, _ = st.columns([1, 1, 1])
    with mid:
        wait = th.remaining()
        if wait:
            st.error(f'시도 횟수를 초과했습니다. {wait}초 후 다시 시도하세요.')
        with st.form('hp_login', border=False):
            pw = st.text_input('비밀번호', type='password', label_visibility='collapsed', placeholder='비밀번호')
            go = st.form_submit_button('들어가기', use_container_width=True, disabled=bool(wait))
        if go:
            if th.remaining():
                st.rerun()
            elif check_password(pw):
                th.ok()
                st.session_state['hp_authed'] = True
                st.rerun()
            else:
                th.fail()
                st.error('비밀번호가 맞지 않습니다.')
    st.stop()
