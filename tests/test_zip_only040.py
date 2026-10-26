import copy
import json
import sqlite3
import threading
from uuid import uuid4

import pytest
from fastapi import HTTPException
from test_processing import setup as setup  # noqa: PLC0414
from test_processing import upload

from forensic_app.jobs import JobStore
from forensic_app.worker import process_job


def test_legacy_unsupported_job_is_passive_and_not_exposed(setup):
    client, storage, mode, _ = setup
    forensic = upload(client, mode).json()['id']
    store = JobStore(storage)
    legacy = str(uuid4())
    plan = copy.deepcopy(store.plan(forensic))
    plan['workspace'] = 'malware'
    raw = json.dumps(plan)
    with sqlite3.connect(storage.database) as connection:
        connection.execute("INSERT INTO jobs(id,status,phase,config_json) VALUES (?,'queued','historical',?)", (legacy, raw))
    assert legacy not in {job['id'] for job in client.get('/api/jobs').json()['jobs']}
    for suffix in ['', '/log', '/report', '/source', '/events']:
        assert client.get('/api/jobs/'+legacy+suffix).status_code == 404
    process_job(store, legacy, plan, threading.Event(), runner=lambda *args: pytest.fail('Historical sample must not run.'))
    store.recover()
    with sqlite3.connect(storage.database) as connection:
        row = connection.execute('SELECT status,config_json FROM jobs WHERE id=?', (legacy,)).fetchone()
    assert row == ('queued', raw)
    with pytest.raises(HTTPException):
        store.get(legacy)


def test_removed_analysis_apis_and_non_zip_scope(setup):
    client, _, mode, _ = setup
    assert client.get('/api/jobs/catalog', params={'workspace': 'malware'}).status_code == 422
    assert client.post('/api/jobs/local', json={'mode_id': mode, 'path': 'unused', 'workspace': 'malware'}).status_code == 422
    ident = upload(client, mode).json()['id']
    for suffix in ['preview', 'csv', 'summary', 'indicators']:
        assert client.get('/api/jobs/'+ident+'/'+suffix).status_code == 404


def test_legacy_work_does_not_block_queue_or_graceful_stop(setup):
    from forensic_app.queue_control import QueueControl
    from forensic_app.server_control import ServerControl

    client, storage, mode, _ = setup
    ident = upload(client, mode).json()['id']
    with sqlite3.connect(storage.database) as connection:
        plan = json.loads(connection.execute('SELECT config_json FROM jobs WHERE id=?', (ident,)).fetchone()[0])
        plan['workspace'] = 'malware'
        connection.execute("UPDATE jobs SET status='running',config_json=? WHERE id=?", (json.dumps(plan), ident))
    state = QueueControl(storage).get()
    assert state['running'] == [] and state['waiting'] == 0
    stopped = threading.Event()
    control = ServerControl(storage, None, stopped.set)
    try:
        assert control.status()['active_jobs'] == 0
        control.request()
        assert stopped.wait(3)
    finally:
        control.close()
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute('SELECT status FROM jobs WHERE id=?', (ident,)).fetchone()[0] == 'running'
