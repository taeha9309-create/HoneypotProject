"""Record an explicit human review decision for a saved candidate."""
from contextlib import closing
import sqlite3

import streamlit as st
from ml.analysis import candidate_registry


def render(candidate, registry):
    if candidate["status"] != "proposed":
        return
    cid = candidate["id"]
    st.caption('승인은 이 초안을 검토했다는 기록입니다. 운영 규칙 등록에는 정규식과 적용 범위 검증이 필요합니다.')
    with st.form(f"review_decision_{cid}"):
        reviewer = st.text_input('검토자', key=f"reviewer_{cid}")
        reason = st.text_area('판정 사유', key=f"reason_{cid}")
        decision = st.radio('검토 결과', ('승인', '거부'), index=None, key=f"decision_{cid}")
        submitted = st.form_submit_button('검토 결과 저장')
    if submitted:
        if not reviewer.strip() or not reason.strip() or decision is None:
            st.warning('검토자, 판정 사유, 검토 결과를 모두 입력하세요.')
            return
        status = "approved" if decision == "승인" else "rejected"
        try:
            with closing(candidate_registry.open_registry(registry)) as conn:
                candidate_registry.decide(conn, cid, status, reviewer, reason)
        except ValueError:
            st.warning('후보가 이미 검토됐거나 존재하지 않습니다. 새로고침해 상태를 확인하세요.')
        except (OSError, sqlite3.Error):
            st.error('검토 기록을 저장할 수 없습니다.')
        else:
            st.rerun()
