"""3D 지구본 (외부 자료·네트워크 없이 동작하는 canvas 한 장).

대시보드가 이미 가진 국가 경계(dashboard/assets/world.json, 720x360 평면 SVG 경로)를 경위도로 되돌려
정사영 지구본으로 그린다. 드래그로 돌리고, 가만히 두면 천천히 돈다.
선은 '조회 기간에 관측된 국가별 접속이 어느 허니팟으로 향했는지'를 보여 주는 연출이며 실시간 공격이 아니다.
HTML에 들어가는 값은 숫자와 우리 자산의 국가·허니팟 이름뿐이다(공격자 문자열 없음).
"""
import json
import re

NUM = re.compile(r'-?\d+(?:\.\d+)?')


def land_rings(shapes, precision=1):
    """world()의 SVG 경로 → [[lon, lat, lon, lat, ...], ...] (고리마다 평평한 리스트, 경도 0~360 평면을 -180~180으로)."""
    rings = []
    for c in shapes:
        for sub in c['path'].split('M')[1:]:
            nums = [float(x) for x in NUM.findall(sub)]
            if len(nums) < 6:
                continue
            flat, last = [], None
            for x, y in zip(nums[0::2], nums[1::2]):
                pt = (round(x / 2 - 180, precision), round(90 - y / 2, precision))
                if pt != last:
                    flat += [pt[0], pt[1]]
                    last = pt
            if len(flat) >= 6:
                rings.append(flat)
    return rings


def arcs_from(sessions, centers, honeypots, top=14):
    """국가×허니팟 접속 수 상위 top개를 선으로. sessions: country, source 열이 있는 표.
    centers: {국가코드: (lon, lat, 이름)}, honeypots: {source: (lon, lat, 이름)}."""
    g = sessions[sessions['country'].notna() & (sessions['country'] != '??')].groupby(['country', 'source']).size()
    rows = []
    for (cc, src), n in g.sort_values(ascending=False).items():
        if cc in centers and src in honeypots:
            rows.append({'from': [centers[cc][0], centers[cc][1]], 'to': [honeypots[src][0], honeypots[src][1]],
                         'n': int(n), 'name': centers[cc][2], 'c': honeypots[src][3] if len(honeypots[src]) > 3 else '#e77fb3'})
        if len(rows) >= top:
            break
    return rows


TEMPLATE = r"""<!doctype html><html><head><meta charset="utf-8"><style>
html,body{margin:0;background:__BG__;overflow:hidden;font-family:system-ui,'Malgun Gothic',sans-serif}
#wrap{position:relative;width:100%;height:__H__px}
canvas{width:100%;height:100%;display:block;cursor:grab}
canvas:active{cursor:grabbing}
#hint{position:absolute;left:12px;bottom:8px;color:#7c8896;font-size:11px;pointer-events:none}
#btns{position:absolute;left:12px;top:10px;display:flex;gap:6px;flex-wrap:wrap}
#btns button{background:#151c24;color:#b4bfca;border:1px solid #27313c;border-radius:6px;padding:4px 10px;font-size:12px;cursor:pointer}
#btns button:hover{border-color:#38d6e8;color:#e6ebf0}
</style></head><body><div id="wrap"><canvas id="c"></canvas>
<div id="btns"></div><div id="hint">드래그해서 돌려 보기 · 더블클릭: 처음 위치</div></div>
<script>
const DATA=__DATA__;
const cv=document.getElementById('c'),ctx=cv.getContext('2d');
const RAD=Math.PI/180,TILT=22*RAD,REDUCED=matchMedia('(prefers-reduced-motion: reduce)').matches;
let W=0,H=0,R=0,cx=0,cy=0,dpr=1,lam0=DATA.start*RAD,drag=null,paused=false,target=null,locked=false;
function resize(){dpr=window.devicePixelRatio||1;W=cv.clientWidth;H=cv.clientHeight;cv.width=W*dpr;cv.height=H*dpr;
  ctx.setTransform(dpr,0,0,dpr,0,0);R=Math.min(W,H)*0.46;cx=W/2;cy=H/2}
addEventListener('resize',resize);resize();
// 경위도 → 화면. 반환: [x, y, 앞쪽이면 양수]
function proj(lon,lat,s){s=s||1;const l=lon*RAD-lam0,p=lat*RAD;
  const x=Math.cos(p)*Math.sin(l),z=Math.sin(TILT)*Math.sin(p)+Math.cos(TILT)*Math.cos(p)*Math.cos(l),
        y=Math.cos(TILT)*Math.sin(p)-Math.sin(TILT)*Math.cos(p)*Math.cos(l);
  return [cx+R*s*x,cy-R*s*y,z,x*s,y*s]}
function slerp(a,b,t){const A=a.map(v=>v*RAD),B=b.map(v=>v*RAD);
  const va=[Math.cos(A[1])*Math.cos(A[0]),Math.cos(A[1])*Math.sin(A[0]),Math.sin(A[1])],
        vb=[Math.cos(B[1])*Math.cos(B[0]),Math.cos(B[1])*Math.sin(B[0]),Math.sin(B[1])];
  let d=Math.max(-1,Math.min(1,va[0]*vb[0]+va[1]*vb[1]+va[2]*vb[2]));const om=Math.acos(d);
  if(om<1e-6)return[a[0],a[1],om];const k1=Math.sin((1-t)*om)/Math.sin(om),k2=Math.sin(t*om)/Math.sin(om);
  const v=[k1*va[0]+k2*vb[0],k1*va[1]+k2*vb[1],k1*va[2]+k2*vb[2]];
  return[Math.atan2(v[1],v[0])/RAD,Math.asin(v[2])/RAD,om]}
function drawLand(){ctx.fillStyle='#27394a';ctx.strokeStyle='#4a6479';ctx.lineWidth=0.7;
  for(const ring of DATA.land){ctx.beginPath();let any=false;
    for(let i=0;i<ring.length;i+=2){const p=proj(ring[i],ring[i+1]);let x=p[0],y=p[1];
      if(p[2]<0){const dx=x-cx,dy=y-cy,L=Math.hypot(dx,dy)||1;x=cx+dx/L*R;y=cy+dy/L*R}else any=true;
      i?ctx.lineTo(x,y):ctx.moveTo(x,y)}
    if(any){ctx.closePath();ctx.fill();ctx.stroke()}}}
function drawGrid(){ctx.strokeStyle='rgba(120,150,175,0.10)';ctx.lineWidth=0.6;
  for(let lat=-60;lat<=60;lat+=30){ctx.beginPath();let on=false;
    for(let lon=-180;lon<=180;lon+=4){const p=proj(lon,lat);if(p[2]>0){on?ctx.lineTo(p[0],p[1]):ctx.moveTo(p[0],p[1]);on=true}else on=false}ctx.stroke()}
  for(let lon=-180;lon<180;lon+=30){ctx.beginPath();let on=false;
    for(let lat=-88;lat<=88;lat+=4){const p=proj(lon,lat);if(p[2]>0){on?ctx.lineTo(p[0],p[1]):ctx.moveTo(p[0],p[1]);on=true}else on=false}ctx.stroke()}}
function arcPoint(a,t){const q=slerp(a.from,a.to,t),lift=1+0.22*Math.min(q[2]/Math.PI,0.6)*Math.sin(Math.PI*t)*2;
  const p=proj(q[0],q[1],lift);const vis=p[2]*lift>0||(p[3]*p[3]+p[4]*p[4])>1;return[p[0],p[1],vis]}
function drawArcs(time){const peak=Math.max(...DATA.arcs.map(a=>a.n),1);
  DATA.arcs.forEach((a,i)=>{const w=0.8+2.2*Math.sqrt(a.n/peak),N=40;
    ctx.lineWidth=w*0.6;ctx.strokeStyle=a.c;ctx.globalAlpha=0.35;ctx.beginPath();let on=false;
    for(let k=0;k<=N;k++){const p=arcPoint(a,k/N);if(p[2]){on?ctx.lineTo(p[0],p[1]):ctx.moveTo(p[0],p[1]);on=true}else on=false}ctx.stroke();ctx.globalAlpha=1;
    const ph=REDUCED?0.5:((time/2600+i*0.173)%1),L=0.22;
    for(let k=0;k<12;k++){const t0=Math.max(0,ph-L*(1-k/12)),p=arcPoint(a,t0);if(!p[2])continue;
      ctx.globalAlpha=0.08+0.85*k/12;ctx.fillStyle=a.c;ctx.beginPath();ctx.arc(p[0],p[1],w*(0.4+k/14),0,6.3);ctx.fill();ctx.globalAlpha=1}});}
function drawNodes(time){const peak=Math.max(...DATA.pts.map(p=>p.v),1);
  DATA.pts.forEach((d,i)=>{const p=proj(d.lon,d.lat);if(p[2]<=0)return;const r=2+7*Math.sqrt(d.v/peak);
    ctx.fillStyle='rgba(231,127,179,0.30)';ctx.strokeStyle='#e77fb3';ctx.lineWidth=1;ctx.beginPath();ctx.arc(p[0],p[1],r,0,6.3);ctx.fill();ctx.stroke();
    ctx.fillStyle='#fde7f3';ctx.beginPath();ctx.arc(p[0],p[1],1.4,0,6.3);ctx.fill();
    if(i<DATA.labels&&!DATA.hp.some(h=>{const q=proj(h.lon,h.lat);return Math.hypot(q[0]-p[0],q[1]-p[1])<22})){ctx.fillStyle='#e6ebf0';ctx.font='600 13px system-ui,Malgun Gothic,sans-serif';ctx.fillText(d.n,p[0]+r+4,p[1]+4)}});
  DATA.hp.forEach(h=>{const p=proj(h.lon,h.lat);if(p[2]<=0)return;const pulse=REDUCED?0.5:((time/1500)%1);
    ctx.strokeStyle=h.c;ctx.globalAlpha=1-pulse;ctx.lineWidth=1.6;ctx.beginPath();ctx.arc(p[0],p[1],5+16*pulse,0,6.3);ctx.stroke();ctx.globalAlpha=1;
    ctx.fillStyle=h.c;ctx.beginPath();ctx.arc(p[0],p[1],4.5,0,6.3);ctx.fill();
    ctx.fillStyle='#e6ebf0';ctx.font='700 14px system-ui,Malgun Gothic,sans-serif';ctx.fillText(h.n+' 허니팟',p[0]+9,p[1]-8)})}
function frame(t){ctx.clearRect(0,0,W,H);
  const g=ctx.createRadialGradient(cx-R*0.3,cy-R*0.35,R*0.1,cx,cy,R*1.02);g.addColorStop(0,'#14212d');g.addColorStop(1,'#0a1118');
  ctx.fillStyle=g;ctx.beginPath();ctx.arc(cx,cy,R,0,6.3);ctx.fill();
  ctx.save();ctx.beginPath();ctx.arc(cx,cy,R,0,6.3);ctx.clip();drawGrid();drawLand();ctx.restore();
  ctx.strokeStyle='rgba(56,214,232,0.55)';ctx.lineWidth=1.4;ctx.shadowColor='rgba(56,214,232,0.6)';ctx.shadowBlur=14;
  ctx.beginPath();ctx.arc(cx,cy,R,0,6.3);ctx.stroke();ctx.shadowBlur=0;
  drawArcs(t);drawNodes(t);
  if(target!==null){let d=((target-lam0+Math.PI)%(2*Math.PI)+2*Math.PI)%(2*Math.PI)-Math.PI;lam0+=d*0.08;if(Math.abs(d)<0.002)target=null}
  else if(!drag&&!paused&&!locked&&!REDUCED)lam0+=0.0018*(DATA.speed||1);requestAnimationFrame(frame)}
cv.addEventListener('pointerdown',e=>{drag={x:e.clientX,l:lam0};cv.setPointerCapture(e.pointerId)});
cv.addEventListener('pointermove',e=>{if(drag)lam0=drag.l-(e.clientX-drag.x)/R});
cv.addEventListener('pointerup',()=>{drag=null});cv.addEventListener('dblclick',()=>{lam0=DATA.start*RAD});
cv.addEventListener('pointerenter',()=>{paused=true});cv.addEventListener('pointerleave',()=>{paused=false});
const B=document.getElementById('btns');
function addBtn(t,fn){const b=document.createElement('button');b.textContent=t;b.onclick=fn;B.appendChild(b);return b}
DATA.hp.forEach(h=>addBtn(h.n+' 보기',()=>{target=h.lon*RAD;locked=true;pb.textContent='▶ 돌리기'}));
const pb=addBtn('⏸ 멈추기',()=>{locked=!locked;pb.textContent=locked?'▶ 돌리기':'⏸ 멈추기'});
requestAnimationFrame(frame);
</script></body></html>"""


def globe_html(rings, pts, arcs, honeypots, height=470, start_lon=127, bg='#10151b'):
    """pts: [{n, lon, lat, v}] 접속 많은 순. honeypots: [{n, lon, lat, c}]. arcs: arcs_from() 결과."""
    data = {'land': rings, 'pts': pts, 'arcs': arcs, 'hp': honeypots, 'start': start_lon, 'labels': 8, 'speed': 1}
    blob = json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')
    return TEMPLATE.replace('__DATA__', blob).replace('__H__', str(int(height))).replace('__BG__', bg)
