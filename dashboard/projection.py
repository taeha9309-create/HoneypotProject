"""Read and display a validated, precomputed projection without ML runtime imports."""
from collections import defaultdict
from hashlib import sha256
from html import escape
import json
import math
from pathlib import Path
from urllib.parse import urlencode

from ingest import TEST_IPS

COLORS = ['#67dfbd','#68a8ff','#e6ad67','#bd91fc','#eb819d','#c7dc73']
CACHE = Path(__file__).resolve().parents[1] / 'data/cluster_projection.json'


def snapshot(con):
    records = defaultdict(lambda: {'commands': [], 'rows': []})
    rows = con.execute('''SELECT m.source,m.session_id,m.protocol,m.cluster_id,c.ts,c.command
        FROM ml_clusters m JOIN sessions s USING(source,session_id)
        JOIN commands c USING(source,session_id)
        WHERE s.excluded=0 AND (s.src_ip IS NULL OR s.src_ip NOT IN ('''+','.join('?' for _ in TEST_IPS)+'''))
        ORDER BY m.source,m.session_id,c.ts,c.rowid''',sorted(TEST_IPS))
    for source,sid,protocol,cluster,ts,command in rows:
        r = records[(source,sid)]
        r.update(source=source,session_id=sid,protocol=protocol,cluster_id=cluster)
        r['commands'].append(command)
        r['rows'].append([ts,command])
    data = list(records.values())
    digest = sha256(json.dumps(data,ensure_ascii=True,sort_keys=True).encode()).hexdigest()
    return data,digest


def esc(value):
    return escape(str(value),quote=True)


def url(**q):
    return esc('/ml?'+urlencode(q))


def render(con,q,cache=CACHE):
    if not cache.is_file():
        return '<div class="notice">군집 그림 준비 전입니다. 시각화 좌표를 먼저 생성하세요.</div>'
    try:
        payload=json.loads(cache.read_text(encoding='utf-8'))
        records,digest=snapshot(con)
        if payload.get('fingerprint')!=digest:
            return '<div class="notice">군집 그림이 현재 DB와 일치하지 않습니다. 좌표를 다시 생성하세요. 이전 데이터의 그림은 표시하지 않습니다.</div>'
        points=payload['points']
    except (ValueError,KeyError,OSError):
        return '<div class="notice">군집 그림 파일을 읽을 수 없습니다. 좌표를 다시 생성하세요.</div>'
    html='<div class="panel"><div class="panel-heading"><h3>공격 행동 군집 지도</h3><span>실제 명령어 · 2차원 투영</span></div><p class="intro">같은 정규화 명령어 흐름을 하나의 원으로 묶었습니다. 원의 크기는 세션 수, 색은 저장된 군집입니다. 원을 선택하면 세션 목록을 확인할 수 있습니다.</p>'
    for protocol in sorted({p['protocol'] for p in points}):
        group=[p for p in points if p['protocol']==protocol]
        active=q.get('cluster') if q.get('protocol')==protocol else None
        xs=[p['x'] for p in group]; ys=[p['y'] for p in group]
        def pos(v,values,span,offset):
            low,high=min(values),max(values)
            return offset+span*((v-low)/(high-low) if high>low else .5)
        html+='<h4>'+esc(protocol.upper())+' · '+str(sum(len(p['members']) for p in group))+' 세션 / '+str(len(group))+' 패턴 묶음</h4><div class="cluster-legend"><a href="/ml">전체</a>'
        for cluster in sorted({p['cluster_id'] for p in group}):
            color='#8996aa' if cluster==-1 else COLORS[cluster%len(COLORS)]
            label='미분류 / 노이즈' if cluster==-1 else '군집 '+str(cluster)
            count=sum(len(p['members']) for p in group if p['cluster_id']==cluster)
            html+='<a style="border-color:'+color+';color:'+color+'" href="'+url(protocol=protocol,cluster=cluster)+'">'+label+' · '+str(count)+'</a>'
        html+='</div><svg class="cluster-map" viewBox="0 0 920 450" role="img" aria-label="'+esc(protocol)+' 실제 군집 산점도"><rect x="35" y="20" width="850" height="390" rx="10" fill="#101925"/>'
        for x in range(80,881,100): html+=f'<path d="M{x} 30 V400" stroke="#243044" stroke-dasharray="3 6"/>'
        for y in range(70,401,70): html+=f'<path d="M45 {y} H875" stroke="#243044" stroke-dasharray="3 6"/>'
        for p in sorted(group,key=lambda v:-len(v['members'])):
            x=pos(p['x'],xs,740,90); y=pos(p['y'],ys,290,65)
            count=len(p['members']); radius=6+math.log2(count+1)*2
            color='#8996aa' if p['cluster_id']==-1 else COLORS[p['cluster_id']%len(COLORS)]
            opacity='1' if active is None or str(p['cluster_id'])==active else '.12'
            label=f"군집 {p['cluster_id']} · {count} 세션 · {p['preview']}"
            html+='<a href="'+url(protocol=protocol,cluster=p['cluster_id'],pattern=p['id'])+'"><circle tabindex="0" cx="'+str(round(x,2))+'" cy="'+str(round(y,2))+'" r="'+str(round(radius,2))+'" fill="'+color+'" fill-opacity="'+opacity+'" stroke="'+color+'" stroke-width="2"><title>'+esc(label)+'</title></circle></a>'
        html+='<text x="460" y="440" text-anchor="middle" fill="#93a3b9" font-size="12">명령어 특징의 시각화 축 1 (PCA)</text><text x="20" y="215" transform="rotate(-90 20 215)" text-anchor="middle" fill="#93a3b9" font-size="12">시각화 축 2</text></svg>'
    html+='<p class="projection-note">기존 정규화 v3 → TF-IDF(명령어 1~3-gram) → SVD·L2 특징 → PCA 2차원. 고유 패턴마다 동일한 가중치로 투영합니다. 원의 위치는 군집 번호로 만들지 않으며 기존 군집을 재학습하지 않습니다. 축과 거리는 근사치로, 겹침이나 분리 정도가 원래 고차원 거리와 다를 수 있습니다. 임의 위치 보정은 하지 않습니다.</p></div>'
    if q.get('pattern'):
        selected=next((p for p in points if p['id']==q['pattern'] and p['protocol']==q.get('protocol')),None)
        if selected:
            html+='<div class="panel"><h3>선택한 패턴 · '+str(len(selected['members']))+' 세션</h3><pre>'+esc(selected['preview'])+'</pre><p>최근 여부와 무관한 키 순서 · 최대 200개 표시</p><div class="pattern-members">'
            for source,sid in selected['members'][:200]:
                html+='<a href="'+esc('/session?'+urlencode({'source':source,'session':sid}))+'">'+esc(source+' / '+sid)+'</a>'
            html+='</div></div>'
        else:
            html+='<p>선택한 패턴 데이터 없음</p>'
    return html
