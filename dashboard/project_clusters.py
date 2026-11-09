"""Generate visualization coordinates, preserving existing cluster assignments."""
import argparse
from collections import defaultdict
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path

import numpy as np
from sklearn.decomposition import PCA
from ml.cluster import normalize_session, features
from dashboard.app import default_db
from dashboard.projection import CACHE, snapshot
import sqlite3


def build(con):
    records,digest=snapshot(con)
    points=[]
    for protocol in sorted({r['protocol'] for r in records}):
        groups=defaultdict(list)
        for r in records:
            if r['protocol']==protocol:
                groups[(normalize_session(r['commands']),r['cluster_id'])].append([r['source'],r['session_id']])
        seqs=sorted({seq for seq,cluster in groups})
        if len(seqs)>1 and any(seqs):
            _,_,_,z=features(seqs)
            components=min(2,z.shape[0],z.shape[1])
            coords=PCA(n_components=components,svd_solver='full').fit_transform(z)
            if components==1: coords=np.column_stack([coords[:,0],np.zeros(len(coords))])
        else:
            coords=np.zeros((len(seqs),2))
        lookup={seq:xy for seq,xy in zip(seqs,coords)}
        for (seq,cluster),members in sorted(groups.items()):
            xy=lookup[seq]
            ident=sha256(json.dumps([protocol,cluster,seq],ensure_ascii=True).encode()).hexdigest()[:20]
            points.append({'id':ident,'protocol':protocol,'cluster_id':cluster,'x':float(xy[0]),'y':float(xy[1]),'members':members,'preview':' ; '.join(seq)})
    return {'schema_version':1,'fingerprint':digest,'method':'normalized command TF-IDF / SVD-L2 / PCA2, unique sequence weight','points':points}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db',default=default_db())
    parser.add_argument('--out',default=str(CACHE))
    args=parser.parse_args()
    with closing(sqlite3.connect(Path(args.db).resolve().as_uri()+'?mode=ro',uri=True)) as con:
        con.execute('PRAGMA query_only=ON')
        payload=build(con)
    out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(payload,ensure_ascii=True,allow_nan=False),encoding='utf-8')
    print(f"Saved {len(payload['points'])} pattern groups / {sum(len(p['members']) for p in payload['points'])} sessions: {out}")


if __name__=='__main__': main()
