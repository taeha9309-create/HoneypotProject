"""위협 정보(IOC): 허니팟에서 얻은 정보를 실제 방어에 옮겨 쓰기.

차단 후보 IP · 명령 흐름 묶음 · 다운로드 서버 · 파일 해시 · 공격 계정 · 서울/시드니 공통 IP를 모으고 CSV로 내려받는다.
이 페이지는 차단 목록으로 쓰도록 IP를 가리지 않는다(다른 페이지 목록은 가림). URL은 링크가 되지 않게 표시한다.
"""
import pandas as pd
import streamlit as st

import common as C
import data as D
import intel as I
import detect as X

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
C.page_header('Threat intel', f'{scope_kind} {period} KST',
              '허니팟에서 얻은 차단·점검용 정보입니다. 차단 목록으로 쓰도록 이 페이지는 IP를 가리지 않습니다. '
              '모든 항목은 입력 관측 기반이라 반영 전에 검토가 필요합니다.')


@st.cache_data(show_spinner='위협 정보 정리 중…')
def intel_cached(version, filters):
    d = C.dataset()
    s = D.scope(d, filters)
    ipi = I.ip_intel(d, s, d.rules)
    return ipi, I.download_servers(d, s), I.credentials(s), I.shared_ips(s), I.exposure_checks(d, s, d.rules)


version = C._version()
ipi, servers, creds, shared, checks = intel_cached(version, f)
bl = I.blocklist(ipi)
pub_servers = servers[servers['kind'] != '루프백(무시)'].reset_index(drop=True)
files = D.file_catalog(sc)
country = lambda c: names.get(c, c) if isinstance(c, str) else '위치 미상'  # noqa: E731

# ---------------------------------------------------------------- 요약
with C.card('THREAT INTEL SUMMARY', help='차단 후보 IP: 내려받아 실행·위험 행동·다운로드 시도·무차별 대입(인증 '
                                         f'{I.BRUTE_ATTEMPTS}회 이상)·반복 접속(3일 이상, 20세션 이상) 중 하나 이상인 공인 IP.'):
    cols = st.columns(5)
    kp = [('1순위 차단 IP', f"{int((bl['tier'] == 1).sum()):,}", C.RED,
           f"2순위 {int((bl['tier'] == 2).sum()):,} · 3순위 {int((bl['tier'] == 3).sum()):,} · 전체 IP {len(ipi):,}"),
          ('다운로드 서버', f'{len(pub_servers):,}', C.ORANGE, f"성공한 다운로드 {int(pub_servers['ok'].sum()):,}건"),
          ('파일 해시', f'{len(files):,}', C.LIME, '받아진·올라온 파일'),
          ('공격 계정 조합', f'{len(creds):,}' if sc.raw_selected else '미수집', C.PINK,
           f"성공 {int((creds['success'] > 0).sum()):,}개" if len(creds) else ''),
          ('서울·시드니 공통 IP', f'{len(shared):,}', C.VIOLET, '두 허니팟 모두 접속')]
    for col, (lab, val, color, sub) in zip(cols, kp):
        with col:
            C.kpi(lab, val, color, sub)

with C.card('우리 환경 점검 포인트', help='허니팟에서 관측된 공격을 근거로, 실제 회사 환경에서 확인할 항목입니다.'):
    st.dataframe(checks, hide_index=True, width='stretch', height='content',
                 column_config={'근거': st.column_config.TextColumn(width='large'),
                                '권장 조치': st.column_config.TextColumn(width='large')})

# ---------------------------------------------------------------- 탭
tab = st.segmented_control('IOC', ['차단 후보 IP', '명령 흐름 묶음', '다운로드 서버', '파일 해시', '공격 계정', '서울·시드니 공통'],
                           default='차단 후보 IP', key='i_tab', label_visibility='collapsed') or '차단 후보 IP'

if tab == '차단 후보 IP':
    with C.card(f'차단 후보 IP · {len(bl):,}개', help='우선순위 → 점수 순(이유 개수·위험도·세션·인증 시도). 행을 누르면 세션 조사의 '
                                                    'IP 상세로 이동합니다. "신규"는 조회 시작 전에 본 적 없는 IP입니다. CSV는 지금 거른 목록입니다.'):
        st.caption(I.TIER_HELP)
        tiers = st.segmented_control('우선순위', [1, 2, 3], default=[1], selection_mode='multi', key='i_tiers',
                                     format_func=lambda t: I.TIER_NAMES[t]) or [1, 2, 3]
        reasons = sorted({r for rs in bl['reasons'] for r in rs})
        pick = st.multiselect('이유로 거르기', reasons, key='i_reason', placeholder='전체')
        view_src = bl[bl['tier'].isin(tiers)]
        view_src = view_src[view_src['reasons'].map(lambda rs: bool(set(pick) & set(rs)))] if pick else view_src
        view_src = view_src.reset_index(drop=True)
        view = pd.DataFrame({'우선순위': view_src['tier'].map(lambda t: f'{t}순위'),
                             'IP': view_src['src_ip'], '국가': view_src['country'].map(country),
                             '이유': view_src['reasons'].map(lambda r: ', '.join(r)),
                             '위험': view_src['danger'].map(lambda d: X.DANGER_NAMES.get(d, '-')),
                             '세션': view_src['sessions'], '인증 시도': view_src['attempts'],
                             '비밀번호 종류': view_src['passwords'], '활동일': view_src['days'],
                             '허니팟': view_src['sources'], '신규': view_src['new'].map({True: '신규', False: ''}),
                             '마지막': C.dtfmt(view_src['last'], '%m-%d %H:%M')})
        ev = C.compact(view, 'i_bl', 15, on_select='rerun',
                       column_config={'이유': st.column_config.TextColumn(width='medium')})
        st.download_button('차단 후보 IP CSV 내려받기', I.to_csv(view_src.assign(reasons=view_src['reasons'].map('|'.join))[
            ['tier', 'src_ip', 'country', 'reasons', 'danger', 'sessions', 'attempts', 'passwords', 'days', 'sources',
             'first', 'last']]),
            file_name=f'blocklist_{f.start:%Y%m%d}_{f.end:%Y%m%d}.csv', mime='text/csv')
        if ev.selection.rows:
            C.open_detail(ip=view_src.iloc[ev.selection.rows[0]]['src_ip'])

elif tab == '명령 흐름 묶음':
    @st.cache_data(show_spinner='명령 흐름 묶는 중…')
    def flow_cached(version, filters):
        d = C.dataset()
        return I.flow_groups(D.scope(d, filters))

    try:
        fg, fg_sum = flow_cached(version, f)
    except ImportError:
        st.warning('이 기능은 ML 패키지(hdbscan, scikit-learn)가 필요합니다. ml/requirements.txt를 설치하세요.')
        st.stop()
    with C.card(f'명령 흐름 묶음 · {len(fg):,}개',
                help='정규화한 명령 순서가 같은 세션을 한 묶음으로 보고, 그 묶음이 몇 개 IP에서 왔는지 봅니다. '
                     f'명령 {fg_sum["min_steps"]}단계 이상, 묶음당 {fg_sum["min_sessions"]}세션 이상만 대상입니다. '
                     '같은 흔적을 공유한다는 뜻이지 같은 행위자라는 뜻이 아닙니다(공개 봇 스크립트는 여러 곳에서 쓰입니다).'):
        if fg.empty:
            st.caption('이 범위에 묶음이 없습니다.')
            st.stop()
        st.caption('소수 IP 반복 = IP 5개 이하이거나 한 IP가 절반 이상 · 분산 = IP 20개 이상이고 한 IP가 20% 미만 · 그 외 중간. '
                   '임계값은 힌트이며 검증된 기준이 아닙니다. 소수 IP 반복은 IP 차단, 분산은 입력 흐름 기준 탐지가 맞는지 검토하세요.')
        kinds = st.segmented_control('집중도', list(I.FLOW_LABELS), default=list(I.FLOW_LABELS), selection_mode='multi',
                                     key='i_fg_kind', format_func=I.FLOW_LABELS.get) or list(I.FLOW_LABELS)
        fv = fg[fg['concentration'].isin(kinds)].reset_index(drop=True)
        view = pd.DataFrame({'집중도': fv['concentration'].map(I.FLOW_LABELS), '세션': fv['sessions'], 'IP': fv['ips'],
                             '최다 IP 점유': fv['top_ip_share'].map(lambda v: f'{v:.0%}'), '활동일': fv['days'],
                             '허니팟': fv['sources'], '규칙': fv['rules'], '해시': fv['hashes'], '서버': fv['servers'],
                             '입력 흐름': fv['flow'].map(lambda t: D.defang(t, 200, False))})
        ev = C.compact(view, 'i_fg', 15, on_select='rerun',
                       column_config={'입력 흐름': st.column_config.TextColumn(width='large')})
        st.download_button('명령 흐름 묶음 CSV 내려받기', I.to_csv(fv.drop(columns=['top_ip_raw', 'ips_raw', 'top_ip', 'clusters'])),
                           file_name=f'flow_groups_{f.start:%Y%m%d}_{f.end:%Y%m%d}.csv', mime='text/csv')
        if ev.selection.rows:
            row = fv.iloc[ev.selection.rows[0]]
            st.markdown(f'**선택한 묶음의 IP {len(row["ips_raw"]):,}개** (차단 검토용, 자동 차단 목록이 아닙니다)')
            st.code('\n'.join(row['ips_raw']), language=None)
            st.download_button('이 묶음의 IP TXT', '\n'.join(row['ips_raw']).encode('utf-8'),
                               file_name=f'flow_group_{row["group_id"]}_ips.txt', mime='text/plain')

elif tab == '다운로드 서버':
    with C.card(f'다운로드 서버 · {len(pub_servers):,}개',
                help='명령 안의 URL과 tftp/ftpget 대상, Cowrie 파일 이벤트에서 뽑은 서버입니다. 우리 서버에서 이 주소로 나가는 '
                     '연결이 있는지 확인하고 차단을 검토하세요. "공격자 자신"은 접속한 IP가 직접 파일을 내려준 경우(감염 장비의 전파)입니다. '
                     '행을 누르면 관련 세션이 나옵니다.'):
        view = pd.DataFrame({'서버': pub_servers['host'], '종류': pub_servers['kind'],
                             '공격자 자신': pub_servers['self_hosted'].map({True: '예', False: ''}),
                             '세션': pub_servers['sessions'], '공격 IP': pub_servers['ips'], '도구': pub_servers['tools'],
                             '다운로드 성공': pub_servers['ok'], '실패': pub_servers['failed'],
                             '예시 URL': pub_servers['urls'].map(lambda u: D.defang(u[0], 120, False)),
                             '마지막': C.dtfmt(pub_servers['last'], '%m-%d %H:%M')})
        ev = C.compact(view, 'i_sv', 15, on_select='rerun',
                       column_config={'예시 URL': st.column_config.TextColumn(width='large')})
        st.download_button('다운로드 서버 CSV 내려받기', I.to_csv(pub_servers.assign(
            urls=pub_servers['urls'].map(lambda u: ' | '.join(D.defang(x, mask_ips=False) for x in u)))[
            ['host', 'kind', 'self_hosted', 'sessions', 'ips', 'tools', 'ok', 'failed', 'urls', 'first', 'last']]),
            file_name=f'download_servers_{f.start:%Y%m%d}_{f.end:%Y%m%d}.csv', mime='text/csv')
        if ev.selection.rows:
            host = pub_servers.iloc[ev.selection.rows[0]]['host']
            st.markdown(f'**{host}** 관련 URL')
            st.code('\n'.join(D.defang(u, mask_ips=False) for u in pub_servers.iloc[ev.selection.rows[0]]['urls']),
                    language=None, wrap_lines=True)
            mask = sc.commands['command'].str.contains(host, regex=False)
            rel = (sc.commands[mask][['source', 'session_id', 'time']].drop_duplicates(['source', 'session_id'])
                   .merge(sc.sessions[['source', 'session_id', 'src_ip']], on=['source', 'session_id'])
                   .sort_values('time', ascending=False).reset_index(drop=True))
            ev2 = C.compact(pd.DataFrame({'시각': C.dtfmt(rel['time'], '%m-%d %H:%M'), '공격 IP': rel['src_ip'],
                                          '허니팟': rel['source'].map(lambda s: D.SOURCE_NAMES.get(s, s)),
                                          '세션 ID': rel['session_id']}), f'i_sv_rel_{host}', 8, on_select='rerun')
            if ev2.selection.rows:
                r = rel.iloc[ev2.selection.rows[0]]
                C.open_detail(source=r['source'], session=r['session_id'])

elif tab == '파일 해시':
    with C.card(f'파일 해시 · {len(files):,}개', help='실제로 받아지거나 올라온 파일의 SHA-256입니다. 백신·EDR에 등록하고 내부 서버에서 '
                                                   '같은 파일을 찾아보세요. 외부 조회는 자동으로 하지 않습니다.'):
        if files.empty:
            st.caption('이 범위에서 수집된 파일이 없습니다.')
            st.stop()
        view = pd.DataFrame({'SHA-256': files['shasum'], '파일': files['name'], '종류': files['kinds'],
                             '세션': files['sessions'], '공격 IP': files['ips'],
                             '처음': C.dtfmt(files['first'], '%m-%d %H:%M'), '최근': C.dtfmt(files['last'], '%m-%d %H:%M')})
        ev = C.compact(view, 'i_fh', 15, on_select='rerun',
                       column_config={'SHA-256': st.column_config.TextColumn(width='large')})
        st.download_button('파일 해시 CSV 내려받기', I.to_csv(files.assign(url=files['url'].map(lambda u: D.defang(u, mask_ips=False)))[
            ['shasum', 'name', 'kinds', 'sessions', 'ips', 'url', 'first', 'last']]),
            file_name=f'file_hashes_{f.start:%Y%m%d}_{f.end:%Y%m%d}.csv', mime='text/csv')
        if ev.selection.rows:
            row = files.iloc[ev.selection.rows[0]]
            obs = D.file_observations(sc, row['key'])
            ev2 = C.compact(pd.DataFrame({'시각': C.dtfmt(obs['time'], '%m-%d %H:%M'), '종류': obs['kind'].map(D.FILE_KINDS),
                                          '공격 IP': obs['src_ip'], '세션 ID': obs['session_id']}),
                            f"i_fh_rel_{row['key'][:12]}", 8, on_select='rerun')
            if ev2.selection.rows:
                r = obs.iloc[ev2.selection.rows[0]]
                C.open_detail(source=r['source'], session=r['session_id'])

elif tab == '공격 계정':
    if not sc.raw_selected:
        st.info('선택한 출처에 원본 인증 로그가 없어 미수집입니다.')
    else:
        a, b = st.columns([1.5, 1])
        with a:
            with C.card(f'아이디·비밀번호 조합 · {len(creds):,}개', help='공격자가 시도한 조합입니다. 우리 계정에 같은 조합이 없는지 '
                                                                '점검하고 비밀번호 금지 목록에 넣으세요. "성공"은 허니팟(일부러 약한 설정)에서의 결과입니다.'):
                if creds.empty:
                    st.caption('이 범위에 인증 이벤트가 없습니다.')
                    st.stop()
                view = pd.DataFrame({'아이디': creds['username'].map(lambda v: D.defang(v, 40, False)),
                                     '비밀번호': creds['password'].map(lambda v: D.defang(v, 40, False)),
                                     '시도': creds['attempts'], '성공': creds['success'], '공격 IP': creds['ips'],
                                     '마지막': C.dtfmt(creds['last'], '%m-%d %H:%M')})
                C.compact(view, 'i_cr', 15)
                st.download_button('계정 조합 CSV 내려받기', I.to_csv(creds), mime='text/csv',
                                   file_name=f'credentials_{f.start:%Y%m%d}_{f.end:%Y%m%d}.csv')
        with b:
            with C.card('비밀번호 순위', help='비밀번호 금지 목록 후보입니다.'):
                pw = I.top_values(sc, 'password')
                C.compact(pd.DataFrame({'비밀번호': pw['value'].map(lambda v: D.defang(v, 40, False)),
                                        '시도': pw['attempts'], '성공': pw['success']}), 'i_pw', 10)
                st.download_button('비밀번호 금지 목록 TXT', '\n'.join(str(v) for v in pw['value']).encode('utf-8'),
                                   file_name='password_blocklist.txt', mime='text/plain')
            with C.card('아이디 순위', help='기본 계정 비활성화·이름 변경 후보입니다.'):
                us = I.top_values(sc, 'username')
                C.compact(pd.DataFrame({'아이디': us['value'].map(lambda v: D.defang(v, 40, False)),
                                        '시도': us['attempts'], '성공': us['success']}), 'i_us', 10)

else:
    with C.card(f'서울·시드니 공통 IP · {len(shared):,}개',
                help='두 허니팟 모두에 접속한 IP입니다. 특정 지역이 아니라 인터넷 전체를 훑는 공격일 가능성이 높습니다. '
                     '시드니 데이터는 11-07까지라 기간이 겹치는 범위에서만 비교됩니다. 행을 누르면 IP 상세로 이동합니다.'):
        if shared.empty:
            st.caption('선택한 범위에 두 허니팟 모두 접속한 IP가 없습니다. 사이드바에서 서울과 시드니를 모두 고르세요.')
        else:
            cols = [c for c in ('seoul', 'syd') if c in shared.columns]
            view = pd.DataFrame({'IP': shared['src_ip'], **{D.SOURCE_NAMES[c] + ' 세션': shared[c] for c in cols},
                                 '합계': shared['total']})
            ev = C.compact(view, 'i_sh', 15, on_select='rerun')
            st.download_button('공통 IP CSV 내려받기', I.to_csv(shared), mime='text/csv',
                               file_name=f'shared_ips_{f.start:%Y%m%d}_{f.end:%Y%m%d}.csv')
            if ev.selection.rows:
                C.open_detail(ip=shared.iloc[ev.selection.rows[0]]['src_ip'])
