"""Read-only detection candidate review using the local T7a artifacts."""
import json
import re
import sqlite3
from contextlib import closing

import pandas as pd
import streamlit as st

import common as C
import review_decision
from ml.analysis import signature_validation, proposal_registry

REVIEW_DIR = C.ROOT / 'work' / 'advancement' / 'T7a'
STATUS = {'proposed': '검토 대기', 'approved': '승인됨', 'rejected': '거부됨'}


def candidates(root):
    uri = (root / 'candidates.db').resolve().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as con:
        return con.execute('SELECT id, payload, status, reviewer, decided_utc, reason '
                           'FROM candidates ORDER BY id').fetchall()


def percentage(value):
    return '—' if value is None else f'{value:.2%}'


C.page_header('후보 검토', '개발 검증 · 관리자 검토',
              '후보 상태, 일치 세션, 규칙 추가 전후 지표를 확인합니다.')
def show_review_groups():
    path = C.DATA_DIR / 'signature_review_groups.json'
    with st.expander('자동으로 찾은 검토 대상', expanded=True):
        if not path.is_file():
            st.info('새 갱신본을 만들면 여기에서 반복된 미분류 흐름을 확인할 수 있습니다.')
            return
        try:
            report = json.loads(path.read_text(encoding='utf-8'))
            dashboard = C.dataset().meta
            ml_uri = (C.DATA_DIR / 'ml.db').resolve().as_uri() + '?mode=ro'
            with closing(sqlite3.connect(ml_uri, uri=True)) as con:
                model = con.execute("SELECT value FROM ml_meta WHERE key='trained_at'").fetchone()
            if (report['rules_sha256'] != dashboard.get('rules_sha256')
                    or report['built_at_utc'] != dashboard.get('built_at')
                    or report['trained_at_utc'] != (model[0] if model else None)):
                st.warning('현재 데이터에 맞는 검토 대상을 보려면 갱신본을 다시 만드세요.')
                return
            groups = report['groups']
            if not isinstance(groups, list):
                raise ValueError('unexpected review groups')
            table = [{
                '프로토콜': row['protocol'].upper(),
                '군집': row['cluster_id'],
                '규칙 설명 부족': row['gap_sessions'],
                '군집 전체 세션': row['cluster_sessions'],
                '반복 흐름 세션': row['recurrent_gap_sessions'],
                '반복 흐름 IP 수': row['recurrent_ips'],
            } for row in groups]
        except (OSError, TypeError, ValueError, KeyError, sqlite3.Error):
            st.warning('검토 대상 파일을 읽을 수 없습니다.')
            return
        if not groups:
            st.info('이 갱신본에서 선별 조건을 충족한 군집이 없습니다.')
            return
        st.caption('일치 규칙이 없거나 셸 진입 규칙만 있는 세션에서 반복된 명령 흐름을 찾았습니다.')
        st.dataframe(pd.DataFrame(table), hide_index=True, width='stretch')
        selected = st.selectbox('대표 입력 흐름 보기', range(len(groups)),
                                format_func=lambda index: f"{table[index]['프로토콜']} · 군집 {table[index]['군집']}")
        for flow in groups[selected]['representative_flows']:
            st.caption(f"반복 {flow['sessions']:,}세션 · IP {flow['ips']:,}개"
                       + (f" · 이후 {flow['steps_omitted']}단계 생략" if flow['steps_omitted'] else ''))
            st.text(flow['observed_flow'])
        st.caption('로컬 시험 · 이 갱신본에서 후보가 얼마나 넓게 걸릴지 확인합니다.')
        group = groups[selected]
        fingerprint = tuple(report[key] for key in signature_validation.SNAPSHOT_KEYS) + (
            group['protocol'], group['cluster_id'])
        if st.button('후보 제안 및 로컬 검사', key='signature_proposal_demo_button'):
            try:
                validation_path = C.DATA_DIR / signature_validation.REPORT_NAME
                if validation_path.is_file():
                    checked = json.loads(validation_path.read_text(encoding='utf-8'))
                    if any(checked[key] != report[key] for key in signature_validation.SNAPSHOT_KEYS):
                        raise ValueError('proposal check belongs to another snapshot')
                else:
                    checked = signature_validation.build(C.DATA_DIR, C.RULES_PATH, report)
                result = next(item for item in checked['groups']
                              if (item['protocol'], item['cluster_id']) ==
                              (group['protocol'], group['cluster_id']))
            except (OSError, TypeError, KeyError, ValueError, StopIteration, sqlite3.Error):
                st.session_state.pop('signature_proposal_demo_result', None)
                st.warning('이 군집의 후보 검사 결과를 만들 수 없습니다. 현재 갱신본을 확인하세요.')
            else:
                st.session_state['signature_proposal_demo_result'] = (fingerprint, result)
        saved = st.session_state.get('signature_proposal_demo_result')
        if saved is not None and saved[0] == fingerprint:
            result = saved[1]
            proposal = result['proposal']
            if proposal['decision'] == 'propose':
                st.markdown('**검토용 초안**')
                st.text(proposal['behavior'])
                st.text(' → '.join(proposal['draft_steps']))
            else:
                st.markdown('**판단 보류**')
            st.text(proposal['reason'])
            for evidence in proposal['evidence']:
                st.caption(f"근거 흐름 {evidence['flow_number']} · {evidence['sessions']:,}세션"
                           f" · IP {evidence['distinct_ip_count']:,}개")
            validation = result['validation']
            if validation is not None:
                st.caption('같은 갱신본에서 검사한 결과입니다. 다른 시기의 기록으로도 확인해야 합니다.')
                scopes = (('해당 프로토콜 전체', 'all'), ('원래 군집', 'origin_cluster'),
                          ('군집 밖', 'outside_cluster'))
                table_rows = []
                for label, key in scopes:
                    metrics = validation[key]
                    table_rows.append({'범위': label, '세션 수': metrics['population'],
                                       '일치 세션': metrics['matches'], '일치율': percentage(metrics['match_rate']),
                                       'B19만 적중한 세션 중 세분화': metrics['b19_only_refined'],
                                       '기존 구체 규칙과 중복': metrics['already_specific'],
                                       '기존 규칙 미적중 중 일치': metrics['new_coverage']})
                st.dataframe(pd.DataFrame(table_rows), hide_index=True, width='stretch')
                if validation['all']['overlap_by_rule']:
                    overlaps = sorted(validation['all']['overlap_by_rule'].items(),
                                      key=lambda item: (-item[1], item[0]))
                    st.text('중복 규칙 · ' + ', '.join(f'{rule} {n:,}건' for rule, n in overlaps))
                share = percentage(validation['top_known_ip_share'])
                st.caption(f"일치한 세션의 IP {validation['distinct_matched_ips']:,}개 · 최대 IP 비중 {share}")
                if result['same_draft_other_clusters']:
                    st.info('같은 초안을 제안한 다른 군집 ' + ', '.join(map(str, result['same_draft_other_clusters'])))
                st.download_button('검사 결과 JSON', json.dumps(result, ensure_ascii=False, indent=2),
                                   file_name=f"signature-review-{group['protocol']}-{group['cluster_id']}.json",
                                   mime='application/json')



show_review_groups()

def show_saved_candidates():
    st.subheader('저장된 검토 후보')
    try:
        saved = proposal_registry.load(proposal_registry.DEFAULT_REGISTRY)
    except (OSError, sqlite3.Error, ValueError):
        st.warning('저장된 후보 이력을 읽을 수 없습니다.')
        return
    if not saved:
        st.info('검사한 초안을 저장하면 여기에 검토 대기 후보가 표시됩니다.')
        return
    index = st.selectbox('저장된 후보', range(len(saved)),
                         format_func=lambda i: f"{saved[i]['protocol'].upper()} · {saved[i]['name']}")
    item = saved[index]
    st.text(f"상태 · {STATUS.get(item['status'], item['status'])}")
    if item['reviewer']:
        st.text(f"{item['reviewer']} · {item['decided_utc']} · {item['reason']}")
    st.code(item['id'], language=None)
    st.caption('검토 명령에서 사용하는 후보 ID입니다.')
    history = item['discoveries']
    st.dataframe(pd.DataFrame([{
        '갱신 시각 (UTC)': h['identity']['built_at_utc'],
        '군집': h['evidence']['cluster_id'],
        '전체 일치': h['evidence']['validation']['all']['matches'],
        '군집 밖 일치': h['evidence']['validation']['outside_cluster']['matches'],
        'B19 단독 적중 세분화': h['evidence']['validation']['all']['b19_only_refined'],
    } for h in history]), hide_index=True, width='stretch')
    review_decision.render(item, proposal_registry.DEFAULT_REGISTRY)
    st.download_button('후보와 발견 이력 JSON', json.dumps(item,ensure_ascii=False,indent=2),
                       file_name=f"{item['id']}.json",mime='application/json')


show_saved_candidates()

try:
    entries = {row[0]: row for row in candidates(REVIEW_DIR)
               if re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,39}', row[0])}
except sqlite3.Error:
    st.info('로컬 후보 저장소가 없거나 열 수 없습니다.')
    st.stop()
if not entries:
    st.info('등록된 후보가 없습니다.')
    st.stop()

candidate_id = st.selectbox('후보', list(entries))
_, payload, status, reviewer, decided_utc, reason = entries[candidate_id]
try:
    candidate = json.loads(payload)
    name = candidate['name']
    days = candidate['activity_days_utc']
    support = len(candidate['evidence_session_keys'])
except (TypeError, KeyError, ValueError):
    st.error('후보 기록을 읽을 수 없습니다.')
    st.stop()

left, right = st.columns([3, 2])
with left:
    st.text(f'{candidate_id} · {name}')
    st.caption(f'근거 세션 {support:,}개 · 활동일 {len(days):,}일')
with right:
    st.metric('후보 상태', STATUS.get(status, '확인 필요'))
    if reviewer and decided_utc:
        st.text(f'{reviewer} · {decided_utc}')
    if reason:
        st.text(reason)

try:
    report = json.loads((REVIEW_DIR / f'{candidate_id}_review.json').read_text(encoding='utf-8'))
    if (report['candidate_id'] != candidate_id
            or report['baseline_rules_sha256'] != candidate['baseline_rules_sha256']
            or report['input_ml_db_sha256'] != candidate['development_input_sha256']['ml.db']):
        raise ValueError('Report does not match candidate metadata')
    metrics = report['metrics']
    counts = metrics['candidate']
    matches, refined, lost = counts['matches'], counts['b19_only_refined'], metrics['lost_rule_hits']
    values = {label: (percentage(metrics[f'{key}_before']), percentage(metrics[f'{key}_after']))
              for label, key in (('커버리지', 'coverage'), ('구체화율', 'specificity'))}
    related = [{
        '허니팟': {'seoul': '서울', 'syd': '시드니'}.get(item['source_session'][0], '기타'),
        '가린 IP': item.get('masked_ip'),
        '첫 입력 시각 (UTC)': item['first_command_utc'],
        '관측 입력 요약': item['observed_input'].replace('\n', ' → '),
    } for item in report['related_sessions']]
    period = f"{report['start_utc'][:10]} ~ {report['end_exclusive_utc'][:10]} (종료일 제외, UTC)"
except FileNotFoundError:
    st.info('이 후보의 개발 검증 보고서가 아직 없습니다.')
    st.stop()
except (OSError, TypeError, ValueError, KeyError, IndexError):
    st.warning('후보와 연결된 개발 검증 보고서를 확인할 수 없습니다.')
    st.stop()

st.subheader('개발 검증 결과')
st.caption(f'텔넷 {metrics["population"]:,}세션 · {period}')
for column, title, value in zip(st.columns(3),
                                ('후보 일치', 'B19 단독 적중 세분화', '기존 적중 손실'),
                                (matches, refined, lost)):
    column.metric(title, f'{value:,}건')
st.dataframe(pd.DataFrame([{'지표': key, '추가 전': before, '추가 후': after}
                           for key, (before, after) in values.items()]), hide_index=True, width='stretch')

st.subheader('관련 세션')
if related:
    st.dataframe(pd.DataFrame(related), hide_index=True, width='stretch')
else:
    st.info('이 구간에서 후보에 일치한 세션이 없습니다.')
