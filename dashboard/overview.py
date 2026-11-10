"""Overview-only reporting. Does not infer login attempts from session summaries."""
from collections import Counter
from datetime import datetime,timedelta,timezone,date
from html import escape
import json
from pathlib import Path
from contextlib import closing
import sqlite3

ROOT=Path(__file__).resolve().parents[1]
KST=timezone(timedelta(hours=9))


def timestamp(value):
    if not value: return None
    try:
        result=datetime.fromisoformat(value.replace('Z','+00:00'))
        return result if result.tzinfo else None
    except (ValueError,TypeError): return None


def stats(con,q,now=None):
    now=now or datetime.now(KST)
    def rows(sql,args=()):
        cursor=con.execute(sql,args); names=[c[0] for c in cursor.description]
        return [dict(zip(names,row)) for row in cursor]
    sessions=rows('SELECT source,session_id,src_ip,country,protocol,start_ts,end_ts,login_success,username,password FROM sessions WHERE excluded=0')
    valid=[(s,timestamp(s['start_ts'])) for s in sessions if timestamp(s['start_ts'])]
    latest=max((timestamp(s['end_ts']) or ts for s,ts in valid),default=None)
    latest_day=max((ts.astimezone(KST).date() for _,ts in valid),default=now.date())
    chosen=now.date() if q.get('mode')=='live' else date.fromisoformat(q.get('day') or str(latest_day))
    source=q.get('source','')
    sources=sorted({s['source'] for s in sessions})
    if source and source not in sources: raise ValueError('Unknown source')
    filtered=[s for s in sessions if not source or s['source']==source]
    start=datetime.combine(chosen,datetime.min.time(),KST)
    end=start+timedelta(days=1)
    selected=[(s,ts) for s,ts in valid if (not source or s['source']==source) and start<=ts<end]
    keys={(s['source'],s['session_id']) for s,_ in selected}
    protocols=Counter((s['protocol'] or '미상').lower() for s,_ in selected)
    hourly=[0]*24
    for s,ts in selected: hourly[ts.astimezone(KST).hour]+=1
    geo_path=ROOT/'data/overview_geo.json'
    geo=json.loads(geo_path.read_text(encoding='utf-8')) if geo_path.is_file() else {'ips':{}}
    world_path=ROOT/'dashboard/assets/world.json'
    world=json.loads(world_path.read_text(encoding='utf-8')) if world_path.is_file() else []
    countries={r['code']:r for r in world}
    events=[]
    for s,ts in selected:
        country=s['country'] or geo['ips'].get(s['src_ip'])
        position=countries.get(country)
        events.append({'source':s['source'],'session':s['session_id'],'ip':s['src_ip'],'country':country if position else None,'name':position['name'] if position else '위치 미상','x':(position['lon']+180)*2 if position else None,'y':(90-position['lat'])*2 if position else None,'second':(ts-start).total_seconds(),'time':ts.astimezone(KST).strftime('%H:%M:%S'),'protocol':s['protocol'] or '미상'})
    events.sort(key=lambda r:(r['second'],r['source'],r['session']))
    commands=0
    for r in rows('SELECT source,session_id,COUNT(*) AS n FROM commands GROUP BY source,session_id'):
        if (r['source'],r['session_id']) in keys: commands+=r['n']
    successful=[s for s,_ in selected if s['login_success']]
    user_counts=Counter(s['username'] for s in successful if s['username'] is not None)
    pass_counts=Counter(s['password'] for s in successful if s['password'] is not None)
    attempts=None;auth_scope='저장된 로그인 성공 세션 기준 · 전체 시도 통계 아님'
    sidecar=ROOT/'data/overview_auth.db'
    if sidecar.is_file():
        allowed={(s['source'],s['session_id']) for s in filtered}
        with closing(sqlite3.connect(sidecar.resolve().as_uri()+'?mode=ro',uri=True)) as auth:
            auth_rows=[]
            for so,sid,ts,user,password,event in auth.execute('SELECT source,session_id,ts,username,password,eventid FROM login_events'):
                dt=timestamp(ts)
                if (so,sid) in allowed and dt and start<=dt<end: auth_rows.append((user,password,event))
        if auth_rows:
            attempts={'total':len(auth_rows),'success':sum(r[2]=='cowrie.login.success' for r in auth_rows),'failed':sum(r[2]=='cowrie.login.failed' for r in auth_rows)}
            user_counts=Counter(r[0] for r in auth_rows if r[0] is not None)
            pass_counts=Counter(r[1] for r in auth_rows if r[1] is not None)
            auth_scope='연결된 원본 로그의 인증 이벤트 기준 · 로그 범위가 전체 수집 범위와 다를 수 있음'
    return {'day':str(chosen),'latest_day':str(latest_day),'sources':sources,'source':source,'total':len(selected),'commands':commands,'unique_ips':len({s['src_ip'] for s,_ in selected if s['src_ip']}),'success_sessions':len(successful),'protocols':dict(protocols),'hourly':hourly,'events':events,'geo_mapped':sum(e['country'] is not None for e in events),'auth':attempts,'auth_scope':auth_scope,'users':user_counts.most_common(8),'passwords':pass_counts.most_common(8),'last_seen':latest.astimezone(KST).isoformat() if latest else None,'archived':latest is None or (now-latest).total_seconds()>600,'server_time':now.isoformat(),'total_scope':len(filtered),'geo_generated_at':geo.get('generated_at'),'unplaced':sum(e['country'] is None for e in events)}


def render(con,q):
    data=stats(con,q)
    world_path=ROOT/'dashboard/assets/world.json'
    world=json.loads(world_path.read_text(encoding='utf-8')) if world_path.is_file() else []
    paths=''.join('<path d="'+escape(c['path'],quote=True)+'"/>' for c in world)
    encoded=json.dumps(data,ensure_ascii=True).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    return '''<div class="ov" id="overview-app"><div class="ov-heading"><div><span class="eyebrow">THREAT MONITORING / OVERVIEW</span><h2>공격 모니터링</h2><p>하루 동안 들어온 접속과 반복되는 행동을 한눈에 확인하세요.</p></div><div class="ov-filters"><label>기준일 · KST<input type="date" id="ov-day"></label><label>데이터 출처<select id="ov-source"></select></label><button id="ov-load">조회</button><button id="ov-yesterday" class="ov-secondary">어제</button><button id="ov-latest" class="ov-secondary">최근 수집일</button></div></div><div class="ov-status"><span id="ov-state"></span><span id="ov-range"></span></div><div class="ov-kpis" id="ov-kpis"></div><div class="ov-grid"><article class="ov-card ov-map-card"><div class="ov-card-title"><div><h3>공격 출발지 지도</h3><small>접속 세션 기준 · 국가 단위 추정</small></div><span class="ov-tag" id="ov-map-count"></span></div><div class="ov-map-controls"><button id="ov-replay">▶ 하루 재생</button><button id="ov-pause" class="ov-secondary" disabled>일시정지</button><button id="ov-reset" class="ov-secondary">전체 보기</button><label>재생 시간<select id="ov-speed"><option value="30">30초</option><option value="60" selected>60초</option><option value="120">120초</option></select></label><button id="ov-live" class="ov-secondary">● 실시간 확인</button></div><div class="ov-map-wrap"><svg viewBox="0 0 720 360" class="ov-map" aria-label="국가별 공격 출발지 지도"><defs><pattern id="ov-grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M40 0H0V40" fill="none" stroke="#243140" stroke-width=".4"/></pattern></defs><rect width="720" height="360" fill="url(#ov-grid)"/><g class="ov-land">'''+paths+'''</g><g id="ov-markers"></g></svg><div class="ov-map-overlay"><strong id="ov-clock">24:00:00</strong><span id="ov-progress">전체 하루 기록</span></div><button class="ov-country-clear ov-secondary" id="ov-country-clear" hidden>국가 선택 해제</button></div><input id="ov-scrub" aria-label="하루 재생 시각" type="range" min="0" max="86400" value="86400"><p class="ov-map-note">원의 위치는 국가 대표점이며 실제 공격자의 위치가 아닙니다. VPN·프록시의 위치일 수 있습니다. 위치 미상은 지도에서 제외하고 순위에 포함합니다.</p><div class="ov-attribution">IP Geolocation by <a href="https://db-ip.com" rel="noreferrer" target="_blank">DB-IP</a> · Map: Natural Earth · IP 외부 전송 없음</div></article><article class="ov-card ov-protocol"><div class="ov-card-title"><h3>접속 프로토콜</h3><span class="ov-tag">세션 기준</span></div><div class="ov-donut-wrap"><div class="ov-donut" id="ov-donut"><div><strong id="ov-donut-total">0</strong><span>접속 세션</span></div></div></div><div id="ov-protocol-legend"></div><div class="ov-mini-metrics" id="ov-mini"></div></article><article class="ov-card"><div class="ov-card-title"><div><h3>반복 접속 IP</h3><small>같은 날 2회 이상 접속 · 최대 10개</small></div><span class="ov-tag" id="ov-repeat-count"></span></div><div id="ov-repeat"></div></article><article class="ov-card ov-hour-card"><div class="ov-card-title"><h3>시간대별 접속</h3><span class="ov-tag">KST · 24시간</span></div><div class="ov-hours" id="ov-hours"></div><div class="ov-hour-labels"><span>00시</span><span>06시</span><span>12시</span><span>18시</span><span>23시</span></div></article><article class="ov-card"><div class="ov-card-title"><div><h3 id="ov-user-title">로그인 계정 분포</h3><small class="ov-auth-scope"></small></div><span class="ov-tag">TOP 8</span></div><div id="ov-users"></div></article><article class="ov-card"><div class="ov-card-title"><div><h3 id="ov-password-title">입력 비밀번호 분포</h3><small class="ov-auth-scope"></small></div><span class="ov-tag">TOP 8</span></div><div id="ov-passwords"></div></article><article class="ov-card ov-feed-card"><div class="ov-card-title"><div><h3>접속 기록</h3><small id="ov-feed-subtitle">선택한 하루의 최근 접속 · 최대 30개</small></div><span class="ov-tag" id="ov-country-label">전체 국가</span></div><div class="ov-feed" id="ov-feed"></div></article></div><p class="ov-bottom-note">로그인 성공은 Cowrie 허니팟의 인증 결과입니다. 실제 시스템 침해를 의미하지 않습니다. 재생은 세션 시작 시각 기준이며 로그인·명령어 이벤트의 개별 재생이 아닙니다.</p><script id="ov-payload" type="application/json">'''+encoded+'''</script><script src="/assets/overview.js" defer></script></div>'''
