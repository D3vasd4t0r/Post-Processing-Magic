import sqlite3
import threading

from test_large_batch import new_job, run_synthetic
from test_processing import setup as setup  # noqa: PLC0414

from forensic_app.artifacts import ArchiveQueue
from forensic_app.jobs import JobStore
from forensic_app.queue_control import QueueControl
from forensic_app.server_control import ServerControl


def test_drain_finishes_current_work_and_blocks_admission_and_claims(setup):
    client,storage,mode,_ = setup
    one,two = new_job(client,mode,zip=False),new_job(client,mode,zip=False)
    queue = QueueControl(storage)
    row = queue.claim()
    assert row[0] in (one,two)
    current,waiting = row[0],two if row[0] == one else one
    stopped = threading.Event()
    control = ServerControl(storage,None,stopped.set)
    try:
        control.request()
        assert not stopped.wait(.4)
        assert queue.claim() is None
        assert client.post('/api/jobs',params={'mode_id':mode},content=b'ZIP',headers={'Content-Type':'application/zip'}).status_code == 409
        assert client.post('/api/settings/cleanup/preview',json={'category':'cache'}).status_code == 409
        queue.set(False)
        assert queue.claim() is None  # Web queue resume cannot override draining.
        run_synthetic(storage,current)
        assert stopped.wait(3)
        assert JobStore(storage).get(current)['status'] == 'succeeded'
        assert JobStore(storage).get(waiting)['status'] == 'queued'
        assert client.post('/api/jobs/'+current+'/archive').status_code == 409
    finally:
        control.close()


def test_drain_waits_for_archive_but_does_not_claim_pending_archive(setup):
    client,storage,mode,_ = setup
    one,two = new_job(client,mode,zip=False),new_job(client,mode,zip=False)
    for ident in [one,two]:
        run_synthetic(storage,ident)
        assert client.post('/api/jobs/'+ident+'/archive').status_code == 200
    queue = ArchiveQueue(JobStore(storage))
    current = queue.claim()
    stopped = threading.Event()
    control = ServerControl(storage,None,stopped.set)
    try:
        control.request()
        assert queue.claim() is None
        assert not stopped.wait(.4)
        queue.run(current,threading.Event())
        assert stopped.wait(3)
        assert JobStore(storage).get(current)['result_available']
    finally:
        control.close()


def test_force_recovery_retains_completed_results_and_marks_open_work(setup):
    client,storage,mode,_ = setup
    completed,waiting = new_job(client,mode),new_job(client,mode,zip=False)
    run_synthetic(storage,completed)
    store = JobStore(storage)
    original = store.paths(waiting)[0]/'evidence'/waiting/'Evidence.zip'
    content = original.read_bytes()
    store.recover(reason='Force Shutdown: synthetischer Test')
    assert store.get(waiting)['status'] == 'interrupted'
    assert original.read_bytes() == content
    assert store.get(completed)['status'] == 'succeeded'
    assert store.get(completed)['result_available']


def test_control_status_requires_auth_and_reports_upload_in_progress(setup):
    client,storage,mode,_ = setup
    response = client.get('/api/system/control')
    assert response.status_code == 200 and not response.json()['stopping']
    assert client.get('/api/system/control',headers={'Authorization':''}).status_code == 401
    ident = new_job(client,mode)
    with sqlite3.connect(storage.database) as c:
        c.execute("UPDATE jobs SET status='uploading' WHERE id=?",(ident,))
    assert client.get('/api/system/control').json()['active_jobs'] == 1
