import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.jobs import JobStore
from forensic_app.queue_control import QueueControl
from forensic_app.storage import Storage

AUTH = {'Authorization':'Bearer history-test'}


def insert(storage, *, name='Own.zip', status='queued', mode='own-mode', created='2026-10-21T12:00:00Z'):
    ident = str(uuid4())
    plan = {'filename':name,'mode':{'id':mode,'name':'Eigener Modus ÄÖÜ'},'tool':{},'command':'Own metadata only'}
    with sqlite3.connect(storage.database) as connection:
        connection.execute('INSERT INTO jobs(id,status,phase,config_json,created_at) VALUES (?,?,?,?,?)',
                           (ident,status,'Own fixture',json.dumps(plan),created))
    return ident


@pytest.fixture
def setup(tmp_path):
    storage = Storage(tmp_path/'state')
    with TestClient(create_app(storage,'history-test'),base_url='http://127.0.0.1',headers=AUTH) as client:
        yield client, storage


def test_history_filters_literal_search_unicode_dates_and_pagination(setup):
    client, storage = setup
    for index in range(65):
        insert(storage,name=f'Own-{index}.zip',status='succeeded')
    special = insert(storage,name='Ärger_100%.zip',status='failed',mode='other',created='2026-10-20T23:59:59Z')
    first = client.get('/api/jobs').json()
    assert first['total'] == 66 and len(first['jobs']) == 50
    second = client.get('/api/jobs?offset=50').json()
    assert len(second['jobs']) == 16
    assert not {job['id'] for job in first['jobs']} & {job['id'] for job in second['jobs']}
    # The simplified list retains pagination but exposes no search or filter API.
    assert special in {item['id'] for item in second['jobs']}
    for params in ({'limit':101},{'offset':-1}):
        assert client.get('/api/jobs',params=params).status_code == 422
    assert client.get('/api/jobs',headers={'Authorization':''}).status_code == 401
    assert 'log_tail' not in first['jobs'][0]


def test_pause_blocks_claim_and_resume_claims_once(setup):
    client, storage = setup
    ident = insert(storage)
    assert client.put('/api/queue',json={'paused':True}).json()['waiting'] == 1
    control = QueueControl(storage)
    assert control.claim() is None
    assert JobStore(storage).get(ident)['status'] == 'queued'
    client.put('/api/queue',json={'paused':False})
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda _:control.claim(),range(2)))
    assert sum(row is not None for row in claims) == 1
    assert client.get('/api/queue').json()['running'] == [ident]
    client.put('/api/queue',json={'paused':True})
    assert JobStore(storage).get(ident)['status'] == 'running'


def test_queued_cancel_works_while_paused(setup):
    client, storage = setup
    ident = insert(storage)
    client.put('/api/queue',json={'paused':True})
    assert client.post(f'/api/jobs/{ident}/cancel').status_code == 200
    assert JobStore(storage).get(ident)['status'] == 'cancelled'
    assert client.get('/api/queue').json()['waiting'] == 0
    client.put('/api/queue',json={'paused':False})
    assert QueueControl(storage).claim() is None


def test_pause_auth_strict_validation_audit_and_restart(setup):
    client, storage = setup
    for method in (client.get,client.put):
        assert method('/api/queue',headers={'Authorization':''}).status_code == 401
    for value in ['true',1,None]:
        assert client.put('/api/queue',json={'paused':value}).status_code == 422
    client.put('/api/queue',json={'paused':True})
    client.put('/api/queue',json={'paused':True})
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute('SELECT count(*) FROM queue_control_events').fetchone()[0] == 1
    with TestClient(create_app(storage,'history-test'),base_url='http://127.0.0.1',headers=AUTH) as restarted:
        assert restarted.get('/api/queue').json()['paused']
