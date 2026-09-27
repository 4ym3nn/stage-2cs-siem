#!/usr/bin/env python3
"""Stream Linux journal entries into Stage 2CS SIEM using stdlib and journalctl."""
import argparse, json, os, re, subprocess
from urllib.request import Request, urlopen

parser=argparse.ArgumentParser()
parser.add_argument('--url',default=os.getenv('SIEM_URL','http://127.0.0.1:8000'))
parser.add_argument('--unit',help='Optional systemd unit, e.g. ssh.service')
args=parser.parse_args()
key=os.getenv('SIEM_API_KEY','') or os.getenv('SIEM_INGEST_API_KEY','')
ip_re=re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')

cmd=['journalctl','-f','-n','0','-o','json']
if args.unit: cmd += ['-u',args.unit]
proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,text=True,bufsize=1)

def send(body):
    headers={'Content-Type':'application/json'}
    if key: headers['X-API-Key']=key
    req=Request(args.url+'/api/ingest/linux',data=json.dumps(body).encode(),headers=headers,method='POST')
    with urlopen(req,timeout=5) as r:r.read()

print('Streaming journalctl ->',args.url)
for line in proc.stdout:
    try:
        rec=json.loads(line)
        msg=rec.get('MESSAGE','')
        ips=ip_re.findall(str(msg))
        body={
            'timestamp': rec.get('__REALTIME_TIMESTAMP'),
            'host': rec.get('_HOSTNAME','linux-host'),
            'event_type': 'journal',
            'src_ip': ips[0] if ips else None,
            'user': rec.get('_SYSTEMD_UNIT') or rec.get('SYSLOG_IDENTIFIER'),
            'message': str(msg),
            'raw': rec,
        }
        # journal realtime is microseconds since epoch; omit unsupported numeric timestamps.
        body.pop('timestamp',None)
        send(body)
    except KeyboardInterrupt:
        break
    except Exception as e:
        print('forward error:',e)
