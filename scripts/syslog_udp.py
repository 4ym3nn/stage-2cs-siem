#!/usr/bin/env python3
"""Minimal lab UDP syslog forwarder for Stage 2CS SIEM."""
import json, os, re, socket
from urllib.request import Request, urlopen

HOST=os.getenv('SYSLOG_BIND','0.0.0.0'); PORT=int(os.getenv('SYSLOG_PORT','5514'))
URL=os.getenv('SIEM_URL','http://127.0.0.1:8000'); KEY=os.getenv('SIEM_API_KEY','') or os.getenv('SIEM_INGEST_API_KEY','')
IP_RE=re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')

def send(msg,peer):
    ips=IP_RE.findall(msg)
    body={"source":"linux","host":peer[0],"event_type":"syslog","src_ip":ips[0] if ips else peer[0],"message":msg,"raw":{"peer":peer[0]}}
    headers={'Content-Type':'application/json'}
    if KEY: headers['X-API-Key']=KEY
    req=Request(URL+'/api/events',data=json.dumps(body).encode(),headers=headers,method='POST')
    with urlopen(req,timeout=3) as r:r.read()

sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind((HOST,PORT))
print(f'Listening for UDP syslog on {HOST}:{PORT} -> {URL}')
while True:
    data,peer=sock.recvfrom(65535)
    try: send(data.decode(errors='replace').strip(),peer)
    except Exception as e: print('forward error:',e)
