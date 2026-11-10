"""Import genuine Cowrie authentication events into a dashboard-only sidecar."""
import argparse
from contextlib import closing
from pathlib import Path
import sqlite3
from dashboard.app import ROOT,default_db
from dashboard.overview import timestamp
from ingest import iter_events,iter_files


def import_logs(db,paths,source,out):
    with closing(sqlite3.connect(Path(db).resolve().as_uri()+'?mode=ro',uri=True)) as original:
        sessions={sid:(ip,timestamp(start),timestamp(end)) for sid,ip,start,end in original.execute('SELECT session_id,src_ip,start_ts,end_ts FROM sessions WHERE source=? AND excluded=0',(source,))}
    if not sessions: raise ValueError('No matching source sessions in selected database')
    target=Path(out);target.parent.mkdir(parents=True,exist_ok=True)
    accepted=0
    with closing(sqlite3.connect(target)) as con:
        con.execute('''CREATE TABLE IF NOT EXISTS login_events(
            source TEXT NOT NULL,session_id TEXT NOT NULL,ts TEXT NOT NULL,eventid TEXT NOT NULL,
            username TEXT NOT NULL,password TEXT NOT NULL,
            PRIMARY KEY(source,session_id,ts,eventid,username,password))''')
        for path in iter_files(paths):
            for event in iter_events(path):
                sid=event.get('session') or event.get('session_id'); ts=timestamp(event.get('timestamp'))
                if event.get('eventid') not in ('cowrie.login.success','cowrie.login.failed') or sid not in sessions or ts is None: continue
                ip,start,end=sessions[sid]
                if start is None or end is None or not start<=ts<=end: continue
                if event.get('src_ip') and ip and event['src_ip']!=ip: continue
                values=(source,sid,ts.isoformat(),event['eventid'],str(event.get('username') or ''),str(event.get('password') or ''))
                accepted+=con.execute('INSERT OR IGNORE INTO login_events VALUES(?,?,?,?,?,?)',values).rowcount
        con.commit()
    return accepted


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('paths',nargs='+')
    p.add_argument('--db',default=default_db());p.add_argument('--source',required=True)
    p.add_argument('--out',default=str(ROOT/'data/overview_auth.db'))
    a=p.parse_args()
    print('Imported authentication events:',import_logs(a.db,a.paths,a.source,a.out))


if __name__=='__main__':main()
