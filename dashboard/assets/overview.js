/* All chart and map values come from the local SQLite snapshot. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let data = JSON.parse($('ov-payload').textContent), cutoff = 86400, country = null;
  let replay = null, live = null, generation = 0, controller = null;
  const fmt = n => Number(n).toLocaleString('ko-KR');
  const colors = {ssh:'#8b9cf6',telnet:'#59c6a5','미상':'#8795a9'};
  const node = (tag,text,cls) => {const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
  const empty = target => {target.replaceChildren(node('p','선택한 범위에 데이터가 없습니다.','ov-empty'));};
  const sessionLink = event => {const a=node('a',event.ip || 'IP 미상');a.href='/session?'+new URLSearchParams({source:event.source,session:event.session});return a;};
  function stopReplay(){if(replay)cancelAnimationFrame(replay);replay=null;$('ov-pause').disabled=true;$('ov-pause').textContent='일시정지';}
  function stopLive(){clearInterval(live);live=null;generation++;if(controller)controller.abort();$('ov-live').classList.remove('selected');}
  function status(text,error=false){$('ov-state').textContent=text;$('ov-state').classList.toggle('ov-error',error);}
  function summary(){
    $('ov-day').value=data.day;
    $('ov-range').textContent=`${data.day} 00:00–24:00 KST · 마지막 수집 ${data.last_seen ? new Date(data.last_seen).toLocaleString('ko-KR') : '없음'}`;
    const metrics=[['접속 세션',fmt(data.total),'선택한 하루 · 테스트 제외'],['고유 출발 IP',fmt(data.unique_ips),'서로 다른 출발 IP'],['로그인 시도',data.auth?fmt(data.auth.total):'데이터 없음',data.auth?'연결한 원본 로그 범위':'원본 인증 이벤트 로그 필요'],['명령어 입력',fmt(data.commands),'선택일 시작 세션의 명령어']];
    $('ov-kpis').replaceChildren(...metrics.map(([title,value,note],i)=>{const card=node('article',undefined,'ov-kpi');card.append(node('span',title),node('strong',value),node('small',note));const badge=node('b',String(i+1).padStart(2,'0'));card.append(badge);return card;}));
    const prot=Object.entries(data.protocols).sort((a,b)=>b[1]-a[1]);let angle=0;const segments=[];
    const legend=prot.map(([name,count])=>{const color=colors[name]||'#e5b77e',pct=data.total?count/data.total*100:0;segments.push(`${color} ${angle}% ${angle+pct}%`);angle+=pct;const row=node('div',undefined,'ov-legend-row'),dot=node('i');dot.style.background=color;row.append(dot,node('b',name.toUpperCase()),node('span',`${fmt(count)} · ${pct.toFixed(1)}%`));return row;});
    $('ov-donut').style.background=segments.length?`conic-gradient(${segments.join(',')})`:'#263344';$('ov-donut-total').textContent=fmt(data.total);$('ov-protocol-legend').replaceChildren(...legend);
    $('ov-mini').replaceChildren(node('span',`성공 인증 세션 ${fmt(data.success_sessions)}`),node('span',`위치 미상 ${fmt(data.unplaced)}`));
    const peak=Math.max(1,...data.hourly);
    $('ov-hours').replaceChildren(...data.hourly.map((n,i)=>{const bar=node('div',undefined,'ov-hour-col');bar.title=`${i}시 · ${fmt(n)} 세션`;const fill=node('div');fill.style.height=`${Math.max(n?2:0,n/peak*130)}px`;bar.append(fill);return bar;}));
    document.querySelectorAll('.ov-auth-scope').forEach(e=>e.textContent=data.auth_scope);
    $('ov-user-title').textContent=data.auth?'로그인 시도 계정':'저장된 성공 계정';
    $('ov-password-title').textContent=data.auth?'시도 비밀번호':'저장된 성공 비밀번호';
    bars($('ov-users'),data.users);bars($('ov-passwords'),data.passwords);
    status(data.archived?'보관 데이터 · 실시간 수집은 연결되지 않음':'최근 DB 데이터 · 실시간 확인 가능');
    paint();
  }
  function bars(target,items){if(!items.length){empty(target);return;}const peak=Math.max(...items.map(r=>r[1]));target.replaceChildren(...items.map(([name,count])=>{const row=node('div',undefined,'ov-rank-row'),label=node('code',name===''?'(빈 값)':name);label.title=name;const track=node('div',undefined,'ov-rank-track'),fill=node('div');fill.style.width=`${count/peak*100}%`;track.append(fill);row.append(label,track,node('b',fmt(count)));return row;}));}
  function paint(){
    const events=data.events.filter(e=>e.second<=cutoff), shown=country?events.filter(e=>e.country===country):events;
    const countries=new Map();for(const e of events){if(!e.country)continue;const item=countries.get(e.country)||{...e,count:0};item.count++;countries.set(e.country,item);}
    const svgNS='http://www.w3.org/2000/svg';
    $('ov-markers').replaceChildren(...[...countries.values()].map(e=>{const g=document.createElementNS(svgNS,'g'),c=document.createElementNS(svgNS,'circle'),title=document.createElementNS(svgNS,'title');c.setAttribute('cx',e.x);c.setAttribute('cy',e.y);c.setAttribute('r',4+Math.log2(e.count+1)*1.4);c.setAttribute('class','ov-dot'+(country===e.country?' picked':''));c.setAttribute('tabindex','0');c.setAttribute('role','button');c.setAttribute('aria-label',`${e.name} ${e.count} 세션`);title.textContent=`${e.name} · ${fmt(e.count)} 세션 (국가 추정)`;c.append(title);const select=()=>{country=country===e.country?null:e.country;paint();};c.addEventListener('click',select);c.addEventListener('keydown',k=>{if(k.key==='Enter'||k.key===' '){k.preventDefault();select();}});g.append(c);return g;}));
    $('ov-map-count').textContent=`${fmt(events.length)} / ${fmt(data.total)} 세션`;
    $('ov-country-clear').hidden=!country;$('ov-country-label').textContent=country?(events.find(e=>e.country===country)?.name||country):'전체 국가';
    const ips=new Map();for(const e of shown){if(!e.ip)continue;const r=ips.get(e.ip)||{event:e,count:0};r.count++;ips.set(e.ip,r);}
    const repeats=[...ips.values()].filter(r=>r.count>=2).sort((a,b)=>b.count-a.count);$('ov-repeat-count').textContent=`${fmt(repeats.length)} IP`;
    if(!repeats.length)empty($('ov-repeat'));else $('ov-repeat').replaceChildren(...repeats.slice(0,10).map(({event,count},i)=>{const row=node('div',undefined,'ov-ip-row');row.append(node('small',String(i+1).padStart(2,'0')),sessionLink(event),node('span',event.name),node('b',`${fmt(count)}회`));return row;}));
    const recent=shown.slice(-30).reverse();if(!recent.length)empty($('ov-feed'));else $('ov-feed').replaceChildren(...recent.map(e=>{const row=node('div',undefined,'ov-feed-row'),proto=node('b',e.protocol.toUpperCase(),'ov-proto-badge');row.append(node('time',e.time),sessionLink(e),node('span',e.name),proto);return row;}));
    $('ov-clock').textContent=cutoff===86400?'24:00:00':new Date(cutoff*1000).toISOString().slice(11,19);
    $('ov-progress').textContent=cutoff===86400?'선택한 하루 전체 기록':`하루 기록 재생 · ${fmt(shown.length)} 세션`;
    $('ov-scrub').value=cutoff;
  }
  async function load(mode='day'){
    const ticket=++generation;if(controller)controller.abort();controller=new AbortController();
    const query=new URLSearchParams({day:$('ov-day').value,source:$('ov-source').value,mode});
    try{const response=await fetch('/api/overview?'+query,{cache:'no-store',signal:controller.signal});if(!response.ok)throw new Error('조회 실패');const next=await response.json();if(ticket!==generation)return;data=next;country=null;cutoff=86400;summary();if(mode==='live')status(`실시간 DB 확인 중 · ${data.archived?'새 데이터 대기 (보관 DB)':'현재 데이터'} · 10초 간격`);}catch(e){if(e.name!=='AbortError'&&ticket===generation)status('조회 실패 · 서버 연결과 DB를 확인하세요.',true);}
  }
  const initialSources=[['','전체 출처'],...data.sources.map(s=>[s,s])];$('ov-source').replaceChildren(...initialSources.map(([value,label])=>{const option=node('option',label);option.value=value;return option;}));$('ov-source').value=data.source;
  $('ov-load').onclick=()=>{stopReplay();stopLive();load();};
  $('ov-latest').onclick=()=>{stopReplay();stopLive();$('ov-day').value=data.latest_day;load();};
  $('ov-yesterday').onclick=()=>{stopReplay();stopLive();const now=new Date(Date.now()+9*3600000-86400000);$('ov-day').value=now.toISOString().slice(0,10);load();};
  $('ov-replay').onclick=()=>{stopReplay();stopLive();country=null;cutoff=0;let start=performance.now();const duration=Number($('ov-speed').value)*1000;$('ov-pause').disabled=false;let lastPaint=0;function tick(t){if(!$('overview-app'))return;cutoff=Math.min(86400,(t-start)/duration*86400);if(t-lastPaint>100||cutoff===86400){paint();lastPaint=t;}if(cutoff<86400)replay=requestAnimationFrame(tick);else{stopReplay();status('하루 기록 재생 완료');}}replay=requestAnimationFrame(tick);status('과거 기록 재생 중 · 실제 실시간 접속이 아닙니다.');};
  $('ov-pause').onclick=()=>{stopReplay();status('재생 일시정지 · 슬라이더로 원하는 시각을 확인하세요.');};
  $('ov-reset').onclick=()=>{stopReplay();stopLive();country=null;cutoff=86400;paint();status('선택한 하루 전체 기록');};
  $('ov-country-clear').onclick=()=>{country=null;paint();};
  $('ov-scrub').oninput=()=>{stopReplay();stopLive();cutoff=Number($('ov-scrub').value);paint();status('선택 시각까지의 과거 기록');};
  $('ov-live').onclick=()=>{stopReplay();if(live){stopLive();status('실시간 확인 중지');return;}$('ov-live').classList.add('selected');load('live');live=setInterval(()=>load('live'),10000);};
  window.addEventListener('pagehide',()=>{stopReplay();stopLive();});
  summary();
})();
