import hashlib
import io
import json
import sqlite3
import threading
from pathlib import Path
from zipfile import ZipFile

from test_processing import (
    archive_bytes,
    plan_for,
)
from test_processing import setup as setup  # noqa: PLC0414

from forensic_app.artifacts import ArchiveQueue
from forensic_app.jobs import JobStore
from forensic_app.queue_control import QueueControl
from forensic_app.worker import process_job


def run_synthetic(storage,ident,*,name='result.txt',code=0):
    def runner(plan,work,check,emit):
        output = work/'PostMortem'
        (output/'Empty folder').mkdir(parents=True)
        (output/name).write_text('Own synthetic result',encoding='utf-8')
        emit('Synthetic only')
        return code
    process_job(JobStore(storage),ident,plan_for(storage,ident),threading.Event(),runner=runner)


def new_job(client,mode,*,zip=True):
    response = client.post('/api/jobs',params={'mode_id':mode,'filename':'synthetic.zip','create_zip':zip},
                           content=archive_bytes(),headers={'Content-Type':'application/zip'})
    assert response.status_code == 200,response.text
    return response.json()['id']


def test_workspace_snapshot_original_locations_and_report_hashes(setup,tmp_path):
    client,storage,mode,_ = setup
    old = new_job(client,mode)
    volume = tmp_path/'own-volume'
    volume.mkdir()
    response = client.put('/api/settings/workspace',json={'folder':str(volume)})
    assert response.status_code == 200,response.text
    destination = Path(response.json()['path'])
    other = new_job(client,mode)
    assert plan_for(storage,old)['data_root'] == str(storage.root.resolve())
    assert plan_for(storage,other)['data_root'] == str(destination)
    assert (storage.root/'evidence'/old/'Evidence.zip').exists()
    assert (destination/'evidence'/other/'Evidence.zip').exists()
    reset = client.put('/api/settings/workspace',json={'folder':None}).json()
    assert not reset['custom'] and reset['folder'] == ''
    assert reset['path'] == reset['default_path'] == str(storage.root.resolve())
    for ident in [old,other]:
        run_synthetic(storage,ident)
        state = client.get('/api/jobs/'+ident).json()
        assert state['status'] == 'succeeded',state
        assert state['report_available'] and state['input_sha1'] == hashlib.sha1(archive_bytes()).hexdigest()
        report = client.get('/api/jobs/'+ident+'/report?format=json').json()
        content = client.get('/api/jobs/'+ident+'/download').content
        assert report['archive']['sha1'] == hashlib.sha1(content).hexdigest()
        assert report['archive']['sha256'] == hashlib.sha256(content).hexdigest()
        assert 'Empty folder' in report['directories']
        assert 'Targets/C' in report['work_directories'] and 'PostMortem/Empty folder' in report['work_directories']
        assert report['command_runs'][0]['exit_code'] == 0
        assert report['command_runs'][0]['ended_at_utc'] >= report['command_runs'][0]['started_at_utc']
        with ZipFile(io.BytesIO(content)) as archive:
            assert '<h2>Hashwerte</h2>' in archive.read('Abschlussbericht.html').decode('utf-8')
            embedded = json.loads(archive.read('Aufbereitungsprotokoll.json'))
            assert embedded['archive']['sha256'] is None and embedded['input']['sha1']
    overview = client.post('/api/settings/storage/scan').json()
    assert len(overview['locations']) == 2 and overview['scan']['complete']
    assert not (storage.root/'work'/other).exists()
    assert (destination/'work'/other/'PostMortem'/'result.txt').exists()
    # Host-specific destination is intentionally excluded from transferable workflows.
    exported = client.get('/api/settings/configuration/export').json()
    assert 'workspace' not in exported and 'data_root' not in exported


def test_optional_zip_manual_queue_pause_cancel_and_no_second_analysis(setup):
    client,storage,mode,_ = setup
    ident = new_job(client,mode,zip=False)
    run_synthetic(storage,ident)
    state = client.get('/api/jobs/'+ident).json()
    assert state['status'] == 'succeeded' and not state['result_available'] and state['report_available']
    report = client.get('/api/jobs/'+ident+'/report?format=json').json()
    assert report['archive'] == {'created':False,'sha1':None,'sha256':None}
    assert client.get('/api/jobs/'+ident+'/download').status_code == 404
    queue = ArchiveQueue(JobStore(storage))
    assert client.post('/api/jobs/'+ident+'/archive').status_code == 200
    assert client.post('/api/jobs/'+ident+'/archive').status_code == 409
    assert client.post('/api/settings/cleanup/preview',json={'category':'cache'}).status_code == 409
    QueueControl(storage).set(True)
    assert queue.claim() is None
    QueueControl(storage).set(False)
    assert queue.claim() == ident
    queue.run(ident,threading.Event())
    assert client.get('/api/jobs/'+ident).json()['archive_status'] == 'done'
    assert client.get('/api/jobs/'+ident+'/download').status_code == 200
    with sqlite3.connect(storage.database) as c:
        assert c.execute("SELECT count(*) FROM job_events WHERE job_id=? AND kind='status' AND json_extract(payload,'$.current_step')=0",(ident,)).fetchone()[0] == 1
    assert client.post('/api/jobs/'+ident+'/archive').status_code == 409


def test_targeted_cleanup_does_not_remove_another_jobs_data(setup):
    client,storage,mode,_ = setup
    one,two = new_job(client,mode),new_job(client,mode)
    for ident in [one,two]:
        run_synthetic(storage,ident)
    for category in ['cache','evidence','results']:
        response = client.post('/api/settings/cleanup/preview',json={'category':category,'job_id':one})
        assert response.status_code == 200,response.text
        result = client.post('/api/settings/cleanup/apply',json={'ticket':response.json()['ticket'],'confirmed':True})
        assert result.status_code == 200 and not result.json()['errors']
    assert not client.get('/api/jobs/'+one).json()['report_available']
    assert not client.get('/api/jobs/'+one).json()['result_available']
    assert client.get('/api/jobs/'+two).json()['result_available']
    assert (storage.root/'work'/two/'Targets'/'C'/'file.txt').exists()
    assert (storage.root/'evidence'/two/'Evidence.zip').exists()


def test_unregistered_missing_or_replaced_destinations_are_not_followed(setup,tmp_path):
    client,storage,mode,_ = setup
    volume = tmp_path/'own-volume'
    volume.mkdir()
    data = client.put('/api/settings/workspace',json={'folder':str(volume)}).json()
    ident = new_job(client,mode,zip=False)
    run_synthetic(storage,ident)
    marker = Path(data['path'])/'.ppm-owner.json'
    marker.write_text('{"owner":"wrong"}',encoding='utf-8')
    state = client.get('/api/jobs/'+ident).json()
    assert state['storage_error'] and not state['report_available']
    assert client.get('/api/jobs/'+ident+'/download').status_code == 409
    assert client.put('/api/settings/workspace',json={'folder':None}).status_code == 200
    assert client.put('/api/settings/workspace',json={'folder':'relative'}).status_code == 422
    assert client.put('/api/settings/workspace',json={'folder':str(storage.root/'work')}).status_code == 422


def test_report_escapes_names_and_failed_commands_have_report(setup):
    client,storage,mode,_ = setup
    ident = new_job(client,mode,zip=False)
    run_synthetic(storage,ident,name='a & b.txt',code=7)
    state = client.get('/api/jobs/'+ident).json()
    assert state['status'] == 'failed' and state['report_available']
    body = client.get('/api/jobs/'+ident+'/report').text
    assert '<script>' not in body and '<table>' in body and '<pre>' not in body
    assert '<h2>Ausgeführte Befehle</h2>' in body and '<td>7</td>' in body
    report = client.get('/api/jobs/'+ident+'/report?format=json').json()
    assert report['command_runs'][0]['exit_code'] == 7 and report['error']
    assert client.get('/api/jobs/'+ident+'/report',headers={'Authorization':''}).status_code == 401


def test_archiving_cancellation_keeps_completed_analysis_and_output(setup):
    client,storage,mode,_ = setup
    ident = new_job(client,mode,zip=False)
    run_synthetic(storage,ident)
    assert client.post('/api/jobs/'+ident+'/archive').status_code == 200
    client.post('/api/jobs/'+ident+'/cancel')
    queue = ArchiveQueue(JobStore(storage))
    assert queue.claim() == ident
    queue.run(ident,threading.Event())
    state = client.get('/api/jobs/'+ident).json()
    assert state['archive_status'] == 'cancelled' and state['status'] == 'succeeded'
    assert (storage.root/'work'/ident/'PostMortem'/'result.txt').exists()
    assert not (storage.root/'results'/(ident+'.part')).exists()


def test_custom_workspace_cleanup_and_unregistered_plan_rejection(setup,tmp_path):
    client,storage,mode,_ = setup
    target = tmp_path/'volume'
    target.mkdir()
    selected = Path(client.put('/api/settings/workspace',json={'folder':str(target)}).json()['path'])
    ident = new_job(client,mode)
    run_synthetic(storage,ident)
    ticket = client.post('/api/settings/cleanup/preview',json={'category':'results','job_id':ident}).json()['ticket']
    result = client.post('/api/settings/cleanup/apply',json={'ticket':ticket,'confirmed':True})
    assert result.status_code == 200 and not result.json()['errors']
    assert not (selected/'results'/(ident+'.zip')).exists()
    assert not (selected/'results'/ident).exists()
    assert (selected/'evidence'/ident/'Evidence.zip').exists()
    plan = plan_for(storage,ident)
    plan['data_root'] = str(tmp_path/'not-registered')
    with sqlite3.connect(storage.database) as c:
        c.execute('UPDATE jobs SET config_json=? WHERE id=?',(json.dumps(plan),ident))
    assert client.get('/api/jobs/'+ident).json()['storage_error']
    assert client.get('/api/jobs/'+ident+'/report').status_code == 409
