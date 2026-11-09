"""Local, read-only dashboard over the team's existing SQLite database."""
import argparse
from contextlib import closing
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
from urllib.parse import parse_qs, urlencode, urlsplit
import json

from match_signatures import load_rules, match, rule_paths
from explain_signatures import explain_session

ROOT = Path(__file__).resolve().parents[1]


def h(value):
    return escape(str(value if value is not None else '데이터 없음'), quote=True)


def link(path, **params):
    return h(path + '?' + urlencode(params))


def table(rows):
    rows = list(rows)
    if not rows:
        return '<p>데이터 없음</p>'
    return '<table><thead><tr>' + ''.join('<th>'+h(k)+'</th>' for k in rows[0]) + '</tr></thead><tbody>' + ''.join('<tr>'+''.join('<td>'+h(v)+'</td>' for v in r.values())+'</tr>' for r in rows)+'</tbody></table>'


class Dashboard:
    def __init__(self, db, rules):
        self.db = Path(db).resolve()
        self.rules = load_rules(rules)
        self.names = {r['id']: r.get('name', r['id']) for r in self.rules}

    def render(self, path, q):
        nav = '<nav>' + ' · '.join(f'<a href="/{p}">{label}</a>' for p, label in [('overview','Overview'),('sessions','Sessions'),('detection','Detection'),('ml','ML Analysis')]) + '</nav>'
        body = '<p>데이터 없음: SQLite 파일이 없습니다. 기존 ingest로 데이터를 준비하세요.</p>'
        if self.db.is_file():
            with closing(sqlite3.connect(self.db.as_uri()+'?mode=ro', uri=True)) as con:
                con.row_factory = sqlite3.Row
                con.execute('PRAGMA query_only=ON')
                body = self.content(con, path, q)
        return ('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Honeypot MVP</title><style>body{font:16px system-ui;margin:24px;line-height:1.6;color:#17212b}nav{margin-bottom:24px}table{border-collapse:collapse;display:block;overflow:auto}td,th{border:1px solid #ccc;padding:8px;text-align:left;white-space:pre-wrap;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f4f5;padding:12px}input,select,button{padding:6px;margin:4px}a{color:#1457a0}</style><h1>Honeypot 대시보드 MVP</h1>'+nav+'<p>DB: '+h(self.db)+' · 읽기 전용 · 기본 집계에서 테스트 세션 제외 · 시각은 DB 원문 기준</p>'+body+'</html>')

    def content(self, con, path, q):
        def rows(sql, args=()):
            return [dict(r) for r in con.execute(sql, args)]
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'sessions','commands'} <= tables:
            return '<p>데이터 없음: ingest 스키마가 없습니다.</p>'
        if path in ('/', '/overview'):
            n = con.execute('SELECT COUNT(*) FROM sessions WHERE excluded=0').fetchone()[0]
            c = con.execute('SELECT COUNT(*) FROM commands c JOIN sessions s USING(source,session_id) WHERE s.excluded=0').fetchone()[0]
            events = con.execute('SELECT SUM(n_events) FROM ingested_files').fetchone()[0] if 'ingested_files' in tables else None
            return '<h2>Overview</h2>'+table([{'전체 수집 이벤트 (파일 집계 합)': events, '전체 세션 (테스트 제외)':n,'로그인 시도':'미구현: 기존 DB에 시도 이벤트 미저장','명령어 입력 (중복 제거)':c}])+ '<p>이벤트 수는 ingest가 수락한 파일별 이벤트 합입니다. 테스트 포함, 파일 간 중복 가능. 고유 원본 이벤트 총수가 아니며 기간별 이벤트 추이는 제공하지 않습니다. 로그인 성공 세션 수로 로그인 시도를 대신하지 않습니다.</p><h3>일별 세션 시작 추이</h3>'+table(rows('SELECT substr(start_ts,1,10) AS 날짜, COUNT(*) AS 세션 FROM sessions WHERE excluded=0 GROUP BY 1 ORDER BY 1'))+'<h3>SSH / Telnet (세션 기준)</h3>'+table(rows("SELECT COALESCE(protocol,'미상') AS 프로토콜, COUNT(*) AS 세션, ROUND(100.0*COUNT(*)/NULLIF((SELECT COUNT(*) FROM sessions WHERE excluded=0),0),2) AS 비율 FROM sessions WHERE excluded=0 GROUP BY protocol"))
        if path == '/sessions':
            fields = [('source','출처'),('ip','IP 포함'),('since','시작일 이상'),('until','시작일 이하')]
            form = '<form>'+''.join(f'<label>{label}<input name="{key}" value="{h(q.get(key,""))}"></label>' for key,label in fields)+'<label>프로토콜<select name="protocol">'+''.join(f'<option value="{v}"'+(' selected' if q.get('protocol','')==v else '')+'>'+h(v or '전체')+'</option>' for v in ('','ssh','telnet'))+'</select></label><label><input type="checkbox" name="commands" value="1"'+(' checked' if q.get('commands') else '')+'>명령어 있음</label><button>조회</button></form>'
            where, args = ['s.excluded=0'], []
            for key, sql in [('source','s.source=?'),('ip',"instr(COALESCE(s.src_ip,''),?)>0"),('protocol','lower(s.protocol)=?'),('since','substr(s.start_ts,1,10)>=?'),('until','substr(s.start_ts,1,10)<=?')]:
                if q.get(key): where.append(sql); args.append(q[key])
            if q.get('commands'): where.append('EXISTS(SELECT 1 FROM commands c WHERE c.source=s.source AND c.session_id=s.session_id)')
            page = max(0, int(q.get('page','0')))
            total = con.execute('SELECT COUNT(*) FROM sessions s WHERE '+' AND '.join(where),args).fetchone()[0]
            data = rows('SELECT s.source,s.session_id,s.src_ip,s.protocol,s.sensor,s.start_ts,s.n_commands FROM sessions s WHERE '+' AND '.join(where)+' ORDER BY s.start_ts DESC,s.source,s.session_id LIMIT 50 OFFSET ?',[*args,page*50])
            return '<h2>Sessions</h2>'+form+f'<p>총 {total}개 · 페이지 {page+1}</p>'+''.join(f'<p><a href="{link("/session",source=r["source"],session=r["session_id"])}">{h(r["source"])} / {h(r["session_id"])}</a></p>'+table([r]) for r in data)+('<p>데이터 없음</p>' if not data else '')+f'<a href="{link("/sessions",**dict(q,page=max(0,page-1)))}">이전</a> · <a href="{link("/sessions",**dict(q,page=page+1))}">다음</a>'
        if path == '/session':
            key = (q.get('source',''),q.get('session',''))
            session = rows('SELECT source,session_id,src_ip,protocol,sensor,country,start_ts,end_ts,login_success,username,excluded FROM sessions WHERE source=? AND session_id=?',key)
            if not session: return '<p>세션 데이터 없음</p>'
            cmds = con.execute('SELECT ts,command FROM commands WHERE source=? AND session_id=? ORDER BY ts,command',key).fetchall()
            body = '<h2>세션 상세</h2>'+table(session)+'<p>로그인 시도 내역: 미구현 (DB 미저장). login_success는 성공 여부 요약입니다.</p><h3>명령어 흐름 (0부터 시작)</h3>'+table([{'인덱스':i,'시각':r[0],'입력':r[1]} for i,r in enumerate(cmds)])
            stored = rows('SELECT rule_id,first_ts,n_hits FROM signature_hits WHERE source=? AND session_id=? ORDER BY rule_id',key) if 'signature_hits' in tables else []
            body += '<h3>저장된 탐지 결과</h3>'+table([{'한국어명':self.names.get(r['rule_id'],'알 수 없는 규칙'),**r} for r in stored])
            body += '<p>아래 근거는 현재 규칙으로 읽기 시 재평가합니다. 저장 결과와 다르면 규칙/데이터 변경 가능성이 있습니다. 관측 입력의 규칙 일치이며 실행 성공이나 악성 확정이 아닙니다.</p>'
            detailed = {r['rule_id']:r for r in explain_session(self.rules,cmds)['matches']}
            current = match(self.rules,cmds)
            for hit in stored:
                rid = hit['rule_id']; rule = next((r for r in self.rules if r['id']==rid),None)
                evidence = detailed.get(rid)
                if evidence is None and rule and rid in current:
                    if 'sequence' in rule or 'session_detector' in rule:
                        evidence = {'순서 근거':rule_paths(rule,cmds)}
                    else:
                        evidence = {'명령어 근거':[{'index':i,'ts':ts,'command':cmd} for i,(ts,cmd) in enumerate(cmds) if rid in match([rule],[(ts,cmd)])]}
                body += '<h4>'+h(self.names.get(rid,rid))+' ('+h(rid)+')</h4><pre>'+h(json.dumps(evidence or {'상태':'현재 규칙과 불일치 또는 근거 미지원'},ensure_ascii=False,indent=2))+'</pre>'
            body += '<h3>ML 결과</h3>'+table(rows('SELECT protocol,cluster_id,is_noise,outlier_score,probability,assigned_by,assigned_at,params FROM ml_clusters WHERE source=? AND session_id=?',key) if 'ml_clusters' in tables else [])
            return body
        if path == '/detection':
            if 'signature_hits' not in tables: return '<h2>Detection</h2><p>데이터 없음: match_signatures.py 실행 결과가 없습니다.</p>'
            data = rows('SELECT h.rule_id,COUNT(*) AS 세션,SUM(h.n_hits) AS 일치수 FROM signature_hits h JOIN sessions s USING(source,session_id) WHERE s.excluded=0 GROUP BY h.rule_id ORDER BY h.rule_id')
            body = '<h2>Detection</h2><p>규칙 일치 관측입니다. 규칙별 n_hits의 의미는 다릅니다 (명령 줄 수 또는 완성 경로 수).</p>'+table([{'한국어명':self.names.get(r['rule_id'],'알 수 없는 규칙'),**r} for r in data])
            body += '<form><label>규칙 코드<input name="rule" value="'+h(q.get('rule',''))+'"></label><button>탐지 세션 조회</button></form>'
            if q.get('rule'):
                for r in rows('SELECT h.source,h.session_id,h.n_hits FROM signature_hits h JOIN sessions s USING(source,session_id) WHERE s.excluded=0 AND h.rule_id=? ORDER BY h.first_ts DESC LIMIT 200',(q['rule'],)):
                    body += '<p><a href="'+link('/session',source=r['source'],session=r['session_id'])+'">'+h(r['source'])+' / '+h(r['session_id'])+'</a> · '+h(r['n_hits'])+'</p>'
                body += '<p>최근 최대 200개 표시. 탐지 근거는 세션 상세에서 확인하세요.</p>'
            return body
        if path == '/ml':
            if 'ml_clusters' not in tables: return '<h2>ML Analysis</h2><p>데이터 없음: 실제 ml_clusters 결과가 없습니다. 문서의 과거 통계를 현재 데이터로 표시하지 않습니다.</p>'
            body = '<h2>ML Analysis</h2><p>저장된 배정 결과만 조회합니다. 군집 키는 프로토콜 + 군집 ID이며 -1은 노이즈입니다. 대표 행동 요약은 미구현이며 실제 멤버 명령은 세션 상세에서 확인합니다.</p>'
            data = rows('SELECT m.protocol,m.cluster_id,COUNT(*) AS 세션,COUNT(DISTINCT s.src_ip) AS IP,MIN(m.assigned_at) AS 최초배정,MAX(m.assigned_at) AS 최근배정 FROM ml_clusters m JOIN sessions s USING(source,session_id) WHERE s.excluded=0 GROUP BY m.protocol,m.cluster_id ORDER BY m.protocol,m.cluster_id')
            body += table(data)
            for r in data:
                body += '<p><a href="'+link('/ml',protocol=r['protocol'],cluster=r['cluster_id'])+'">'+h(r['protocol'])+' / '+h(r['cluster_id'])+' 상세</a></p>'
            if 'cluster' in q:
                members = rows('SELECT m.source,m.session_id,m.model,m.params,m.outlier_score,m.probability,m.assigned_by,m.assigned_at FROM ml_clusters m JOIN sessions s USING(source,session_id) WHERE s.excluded=0 AND m.protocol=? AND m.cluster_id=? ORDER BY m.source,m.session_id LIMIT 200',(q.get('protocol',''),int(q['cluster'])))
                body += '<h3>군집 멤버 (최대 200개)</h3>'+table(members)
                body += ''.join('<p><a href="'+link('/session',source=r['source'],session=r['session_id'])+'">'+h(r['source'])+' / '+h(r['session_id'])+' 명령어·탐지 근거</a></p>' for r in members)
            return body
        return '<p>페이지 없음</p>'


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlsplit(self.path)
            try:
                body = app.render(url.path,{k:v[-1] for k,v in parse_qs(url.query).items()})
                status = 200
            except (ValueError, sqlite3.Error):
                body, status = '<meta charset="utf-8"><p>조회 실패: 필터 값 또는 DB 스키마를 확인하세요.</p>', 400
            data = body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(data)))
            self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header('Cache-Control','no-store')
            self.end_headers()
            self.wfile.write(data)
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db',default=str(ROOT/'data/honeypot.db'))
    parser.add_argument('--rules',default=str(ROOT/'signatures/rules.yaml'))
    parser.add_argument('--port',type=int,default=8000)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1',args.port),make_handler(Dashboard(args.db,args.rules)))
    print(f'Local dashboard: http://127.0.0.1:{args.port}',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == '__main__':
    main()
