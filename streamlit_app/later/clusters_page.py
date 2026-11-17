"""2페이지: 공격 행동 군집화 결과 (ml_clusters)."""
import altair as alt
import pandas as pd
import streamlit as st

import common as C
import data as D
from cluster_labels import FITTED_AT, LABELS

ds, rules, f = C.dataset(), C.rules(), C.filters()
sess, cmds, dls, hits, clusters = D.subset(ds, f)

st.markdown('### 🧩 군집 분석')
meta = ds.ml_meta
if ds.clusters.empty:
    st.info('ml_clusters 표가 있는 DB가 없습니다. `python ml/cluster.py fit --db <DB>`를 먼저 실행하세요.')
    st.stop()
st.caption(f"명령 시퀀스를 정규화해 TF-IDF → SVD → HDBSCAN({meta.get('params', '')})으로 묶은 결과입니다. "
           f"fit {meta.get('fitted_at', '?')} UTC · 시드니 Telnet만 대상 (SSH는 세션이 적어 모델 없음) · 시각은 KST.")
if meta.get('fitted_at') != FITTED_AT:
    st.warning('DB의 fit 시각이 군집 이름을 붙인 fit과 다릅니다. 군집 번호의 뜻이 바뀌었을 수 있으니 '
               '`dashboard/cluster_labels.py`를 확인하세요.')
if clusters.empty:
    st.info('선택한 필터(허니팟·프로토콜·기간)에 군집 결과가 있는 세션이 없습니다. 시드니·telnet을 포함해 보세요.')
    st.stop()

units = D.attack_units(ds, clusters)
table = D.cluster_table(ds, clusters, units, LABELS)
label_of = dict(zip(table['cluster_id'], table['label']))
scale = C.cluster_scale(label_of)
novel = D.novel_view(ds.novel)

# ---------------------------------------------------------------- KPI
n_noise = int((clusters['cluster_id'] == -1).sum())
top_ip = (clusters.join(ds.sessions.set_index(['source', 'session_id'])['src_ip'], on=['source', 'session_id'])
          ['src_ip'].value_counts())
tiles = [('군집 대상 세션', f'{len(clusters):,}', '명령을 입력한 세션'),
         ('군집 수', f"{int((table['cluster_id'] != -1).sum())}", '노이즈 제외'),
         ('노이즈 세션', f'{n_noise:,}', f'{n_noise / len(clusters) * 100:.1f}%'),
         ('공격 단위', f'{len(units):,}', '같은 IP, 10초 이내 연속 세션'),
         ('신규 패턴 후보', f'{len(novel):,}종', f"{int(novel['sessions'].sum()) if not novel.empty else 0}세션"),
         ('최다 IP 비중', f'{top_ip.iloc[0] / len(clusters) * 100:.0f}%', f'{D.mask_ip(top_ip.index[0])} 한 곳')]
for col, (label, value, sub) in zip(st.columns(6), tiles):
    with col.container(border=True):
        st.metric(label, value)
        st.caption(sub)

# ---------------------------------------------------------------- 크기 + 추이
left, right = st.columns([1, 1.4])
with left:
    with C.card('군집 크기', help='막대는 세션 수. IP 수와 공격 단위 수를 함께 보세요. 한 IP의 반복이 세션 수를 크게 만듭니다.'):
        t = table.assign(text=table.apply(lambda r: f"{r['sessions']:,}세션 · IP {r['ips']} · 단위 {r['units']}", axis=1))
        base = alt.Chart(t).encode(
            y=alt.Y('label:N', sort=list(t['label']), title=None, axis=alt.Axis(labelLimit=240)),
            x=alt.X('sessions:Q', title='세션'),
            tooltip=[alt.Tooltip('label:N', title='군집'), alt.Tooltip('sessions:Q', title='세션', format=','),
                     alt.Tooltip('ips:Q', title='IP 수'), alt.Tooltip('units:Q', title='공격 단위'),
                     alt.Tooltip('top_ip_share:Q', title='최다 IP 비중(%)', format='.0f')])
        st.altair_chart((base.mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4).encode(
            color=alt.Color('label:N', scale=scale, legend=None))
            + base.mark_text(align='left', dx=4, fontSize=11).encode(text='text:N'))
            .properties(height=C.CHART_H), width='stretch')
with right:
    with C.card('군집별 일별 세션 (KST)'):
        daily = D.cluster_daily(ds, clusters, LABELS)
        daily['label'] = daily['cluster_id'].map(label_of)
        st.altair_chart(alt.Chart(daily).mark_bar().encode(
            x=alt.X('day:T', title=None, axis=alt.Axis(format='%m-%d', labelAngle=0)),
            y=alt.Y('sessions:Q', title='세션', stack=True),
            color=alt.Color('label:N', scale=scale, title=None,
                            legend=alt.Legend(orient='right', labelLimit=200)),
            tooltip=[alt.Tooltip('day:T', title='날짜', format='%m-%d'), alt.Tooltip('label:N', title='군집'),
                     alt.Tooltip('sessions:Q', title='세션', format=',')],
        ).properties(height=C.CHART_H), width='stretch')

# ---------------------------------------------------------------- 규칙 히트맵 + 공격 단위
left, right = st.columns([1.4, 1])
with left:
    with C.card('군집 × 탐지 규칙 (세션 비율 %)', help='각 군집 세션 중 그 규칙이 걸린 비율. B19는 거의 모든 Telnet 세션에 걸려 구분에 쓸모가 적습니다.'):
        mx = D.cluster_rule_matrix(rules, clusters, hits)
        mx['label'] = mx['cluster_id'].map(label_of)
        order = list(table['label'])
        heat = alt.Chart(mx).encode(
            x=alt.X('rule_id:N', title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y('label:N', sort=order, title=None, axis=alt.Axis(labelLimit=220)),
            tooltip=[alt.Tooltip('label:N', title='군집'), alt.Tooltip('rule:N', title='규칙'),
                     alt.Tooltip('sessions:Q', title='세션'), alt.Tooltip('percent:Q', title='비율(%)', format='.0f')])
        st.altair_chart((heat.mark_rect(stroke='white', strokeWidth=1).encode(
            color=alt.Color('percent:Q', title='%', scale=alt.Scale(scheme='blues', domain=[0, 100])))
            + heat.mark_text(fontSize=10).encode(
                text=alt.Text('percent:Q', format='.0f'),
                color=alt.condition('datum.percent > 60', alt.value('white'), alt.value('#333333'))))
            .properties(height=C.CHART_H + 40), width='stretch')
with right:
    with C.card('공격 단위 흐름 Top', help='같은 IP에서 10초 안에 이어진 세션을 한 공격으로 묶었을 때 군집 순서. 예: 0→1은 장비 확인 뒤 곧바로 쓰기 위치 탐색.'):
        combo = (units.groupby('combo').agg(units=('ip', 'size'), ips=('ip', 'nunique'))
                 .sort_values('units', ascending=False).head(8).reset_index())
        combo['text'] = combo.apply(lambda r: f"{r['units']:,} (IP {r['ips']})", axis=1)
        st.altair_chart(C.hbar(combo, 'combo', 'units', text='text:N', x_title='공격 단위', height=C.CHART_H + 40,
                               tooltip=[alt.Tooltip('combo:N', title='군집 순서'),
                                        alt.Tooltip('units:Q', title='공격 단위', format=','),
                                        alt.Tooltip('ips:Q', title='IP 수')]), width='stretch')

# ---------------------------------------------------------------- 군집 상세
with C.card('군집 상세'):
    ids = list(table['cluster_id'])
    cid = st.segmented_control('군집', ids, default=ids[0], format_func=lambda c: label_of[c],
                               label_visibility='collapsed')
    cid = ids[0] if cid is None else cid
    row = table.set_index('cluster_id').loc[cid]
    left, right = st.columns([1.2, 1])
    with left:
        st.markdown(f"**{label_of[cid]}**")
        st.write(LABELS.get(cid, {}).get('detail', '해석이 아직 없습니다.'))
        st.caption(f"세션 {row['sessions']:,} · IP {row['ips']} · 공격 단위 {row['units']} · "
                   f"최다 IP 비중 {row['top_ip_share']:.0f}% · "
                   f"{row['first']:%m-%d %H:%M} ~ {row['last']:%m-%d %H:%M} KST")
        summary = ds.cluster_summary
        if not summary.empty and cid in set(summary['cluster_id']):
            s = summary[summary['cluster_id'] == cid].iloc[0]
            st.markdown(f"대표 명령 시퀀스 (세션의 {s['rep_share'] * 100:.0f}%가 이 시퀀스)")
            st.code(D.sanitize(s['representative'], 1500), language=None, wrap_lines=True, height=180)
            st.markdown('자주 나온 명령')
            st.code(D.sanitize(str(s['top_commands']).replace(' | ', '\n'), 800), language=None, wrap_lines=True)
    with right:
        st.markdown('최근 세션 (행을 클릭하면 명령 전체)')
        cs = D.cluster_sessions(ds, clusters, cid)
        ev = st.dataframe(cs.drop(columns=['source']), hide_index=True, width='stretch', height=260,
                          on_select='rerun', selection_mode='single-row')
        rows = ev.selection.rows if ev and ev.selection else []
        if rows:
            r = cs.iloc[rows[0]]
            st.dataframe(D.session_commands(ds, rules, r['source'], r['session_id']), hide_index=True,
                         width='stretch', height=260,
                         column_config={'명령': st.column_config.TextColumn(width='large')})

# ---------------------------------------------------------------- 신규 패턴 후보
with C.card('신규 패턴 후보', help='노이즈이거나 이상 점수 상위 5%인 세션을 같은 정규화 시퀀스끼리 묶은 것 (novel_candidates.csv). 새 공격 도구일 수 있어 사람이 검토할 대상입니다.'):
    if novel.empty:
        st.caption('novel_candidates.csv가 DB와 같은 폴더에 없습니다.')
    else:
        novel['cluster'] = novel['cluster'].map(lambda c: label_of.get(int(c), str(c)))
        novel['first'] = (pd.to_datetime(novel['first'], utc=True, format='ISO8601')
                          .dt.tz_convert(D.KST).dt.strftime('%m-%d %H:%M'))
        st.dataframe(
            novel[['outlier', 'sessions', 'cluster', 'reasons', 'downloaded', 'ip', 'first', 'normalized_seq']],
            hide_index=True, width='stretch', height=300,
            column_config={'outlier': st.column_config.ProgressColumn('이상 점수', min_value=0, max_value=1, format='%.2f'),
                           'sessions': st.column_config.NumberColumn('세션', format='%d'),
                           'cluster': '군집', 'reasons': '사유',
                           'downloaded': st.column_config.CheckboxColumn('다운로드'),
                           'ip': 'IP', 'first': '처음(KST)',
                           'normalized_seq': st.column_config.TextColumn('정규화 시퀀스', width='large')})
