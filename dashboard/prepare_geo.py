"""Prepare local country-level GeoIP and a lightweight Natural Earth basemap."""
import argparse
import csv
from bisect import bisect_right
from contextlib import closing
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sqlite3
from dashboard.app import ROOT, default_db


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db',default=default_db())
    p.add_argument('--countries',required=True)
    p.add_argument('--world',required=True)
    a=p.parse_args()
    ranges=[]
    with open(a.countries,encoding='utf-8') as f:
        for first,last,country in csv.reader(f):
            ranges.append((int(ipaddress.ip_address(first)),int(ipaddress.ip_address(last)),country))
    ranges.sort(); starts=[r[0] for r in ranges]
    geo={}
    with closing(sqlite3.connect(Path(a.db).resolve().as_uri()+'?mode=ro',uri=True)) as con:
        for ip, in con.execute('SELECT DISTINCT src_ip FROM sessions WHERE excluded=0 AND src_ip IS NOT NULL'):
            try:
                address=ipaddress.ip_address(ip)
                if address.version!=4 or not address.is_global: continue
                index=bisect_right(starts,int(address))-1
                if index>=0 and int(address)<=ranges[index][1]: geo[ip]=ranges[index][2]
            except ValueError: pass
    world=json.loads(Path(a.world).read_text(encoding='utf-8'))
    countries=[]
    for feature in world['features']:
        prop=feature['properties']; code=prop.get('ISO_A2_EH') or prop.get('ISO_A2')
        polygons=feature['geometry']['coordinates']
        if feature['geometry']['type']=='Polygon': polygons=[polygons]
        paths=[]
        for polygon in polygons:
            for ring in polygon:
                paths.append('M'+'L'.join(f'{(lon+180)*2:.2f},{(90-lat)*2:.2f}' for lon,lat,*_ in ring)+'Z')
        countries.append({'code':code,'name':prop.get('NAME_KO') or prop['NAME'],'lon':prop['LABEL_X'],'lat':prop['LABEL_Y'],'path':''.join(paths)})
    out=ROOT/'dashboard/assets/world.json';out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(countries,ensure_ascii=True),encoding='utf-8')
    target=ROOT/'data/overview_geo.json';target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps({'generated_at':datetime.now(timezone.utc).isoformat(),'provider':'DB-IP Country Lite / ip-location-db','basis':'country representative point; not host coordinates','ips':geo},ensure_ascii=True),encoding='utf-8')
    print(f'Prepared {len(geo)} IP country lookups and {len(countries)} country shapes')


if __name__=='__main__':main()
