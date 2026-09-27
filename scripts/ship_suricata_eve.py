#!/usr/bin/env python3
"""Tail or replay Suricata eve.json into Stage 2CS SIEM."""
import argparse, json, os, time
from urllib.request import Request, urlopen

parser=argparse.ArgumentParser()
parser.add_argument('file',help='Path to eve.json')
parser.add_argument('--follow',action='store_true',help='Follow the file after EOF')
parser.add_argument('--url',default=os.getenv('SIEM_URL','http://127.0.0.1:8000'))
args=parser.parse_args()
key=os.getenv('SIEM_API_KEY','') or os.getenv('SIEM_INGEST_API_KEY','')

def send(obj):
    headers={'Content-Type':'application/json'}
    if key: headers['X-API-Key']=key
    req=Request(args.url+'/api/ingest/suricata',data=json.dumps(obj).encode(),headers=headers,method='POST')
    with urlopen(req,timeout=5) as r: r.read()

with open(args.file,'r',encoding='utf-8',errors='replace') as f:
    while True:
        line=f.readline()
        if not line:
            if args.follow:
                time.sleep(.5); continue
            break
        try: send(json.loads(line))
        except Exception as e: print('ship error:',e)
