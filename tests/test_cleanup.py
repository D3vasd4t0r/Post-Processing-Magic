import json
import sqlite3
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.cleanup import Cleanup
from forensic_app.storage import Storage
from forensic_app.storage_overview import StorageOverview


@pytest.fixture
def sample(tmp_path):
    storage = Storage(tmp_path/'state')
    with TestClient(create_app(storage,'cleanup-test'),base_url='http://127.0.0.1',headers={'Authorization':'Bearer cleanup-test'}) as client:
        ident = str(uuid4())
        plan = {'mode':{'name':'Synthetic only','output_folder':'Export/Results'},'tool':{},'command':'never execute'}
        with sqlite3.connect(storage.database) as c:
            c.execute("INSERT INTO jobs(id,status,phase,config_json) VALUES (?,'succeeded','Done',?)",(ident,json.dumps(plan)))
        work = storage.root/'work'/ident
        output = work/'Export'/'Results'
        output.mkdir(parents=True)
        (output/'report.txt').write_text('own result')
        (work/'Targets').mkdir()
        (work/'Targets'/'input.txt').write_text('own extracted')
        (work/'command.log').write_text('own log')
        evidence = storage.root/'evidence'/ident
        evidence.mkdir()
        (evidence/'Evidence.zip').write_bytes(b'own upload fixture')
        archive = storage.root/'results'/(ident+'.zip')
        archive.write_bytes(b'own result archive')
        yield client,storage,ident,work,output,evidence,archive


def preview(client,category):
    response = client.post('/api/settings/cleanup/preview',json={'category':category})
    assert response.status_code == 200,response.text
    return response.json()


def apply(client,ticket):
    return client.post('/api/settings/cleanup/apply',json={'ticket':ticket,'confirmed':True})


@pytest.mark.parametrize('category',['cache','evidence','results'])
def test_separate_categories_preserve_originals_history_and_settings(sample,category):
    client,storage,ident,work,output,evidence,archive = sample
    original = storage.root.parent/'referenced-original.zip'
    original.write_bytes(b'never delete')
    second = str(uuid4())
    with sqlite3.connect(storage.database) as c:
        plan = {'source_kind':'local','local_input':{'path':str(original)},'mode':{'output_folder':'PostMortem'}}
        c.execute("INSERT INTO jobs(id,status,phase,config_json) VALUES (?,'failed','Synthetic',?)",(second,json.dumps(plan)))
    info = preview(client,category)
    assert info['files'] > 0 and info['bytes'] > 0
    assert archive.exists() and output.exists() and evidence.exists()
    response = apply(client,info['ticket'])
    assert response.status_code == 200,response.text
    assert not response.json()['errors']
    assert (work/'Targets').exists() == (category != 'cache')
    assert output.exists() == (category != 'results')
    assert archive.exists() == (category != 'results')
    assert evidence.exists() == (category != 'evidence')
    assert original.read_bytes() == b'never delete'
    state = client.get('/api/jobs/'+ident).json()
    assert state['status'] == 'succeeded'
    assert state['result_available'] == (category != 'results')
    with sqlite3.connect(storage.database) as c:
        assert c.execute('SELECT status FROM cleanup_events').fetchone()[0] == 'done'
        assert c.execute('SELECT active FROM cleanup_state').fetchone()[0] == 0
    assert apply(client,info['ticket']).status_code == 409


def test_in_app_local_reference_is_protected_in_all_categories(sample):
    client,storage,ident,_work,output,_evidence,_archive = sample
    original = output/'report.txt'
    with sqlite3.connect(storage.database) as c:
        plan = json.loads(c.execute('SELECT config_json FROM jobs WHERE id=?',(ident,)).fetchone()[0])
        plan.update(source_kind='local',local_input={'path':str(original)})
        c.execute('UPDATE jobs SET config_json=? WHERE id=?',(json.dumps(plan),ident))
    for category in ['cache','results','evidence']:
        assert apply(client,preview(client,category)['ticket']).status_code == 200
        assert original.read_text() == 'own result'


@pytest.mark.parametrize('confirmation',[False,1,'true',None])
def test_confirmation_is_explicit_strict_boolean(sample,confirmation):
    client,*_ = sample
    ticket = preview(client,'cache')['ticket']
    assert client.post('/api/settings/cleanup/apply',json={'ticket':ticket,'confirmed':confirmation}).status_code == 422


def test_auth_active_jobs_and_changed_preview_block_deletion(sample):
    client,storage,_ident,work,*_ = sample
    assert client.post('/api/settings/cleanup/preview',json={'category':'cache'},headers={'Authorization':''}).status_code == 401
    ticket = preview(client,'cache')['ticket']
    (work/'command.log').write_text('changed after preview')
    assert apply(client,ticket).status_code == 409
    assert (work/'Targets'/'input.txt').exists()
    with sqlite3.connect(storage.database) as c:
        c.execute("UPDATE jobs SET status='queued'")
    assert client.post('/api/settings/cleanup/preview',json={'category':'cache'}).status_code == 409


def test_reparse_point_does_not_delete_external_files(sample,tmp_path):
    import subprocess
    client,_,_,work,*_ = sample
    external = tmp_path/'external'
    external.mkdir()
    (external/'keep.txt').write_text('original')
    link = work/'external-link'
    subprocess.run(['cmd','/c','mklink','/J',str(link),str(external)],check=True,capture_output=True)
    try:
        info = preview(client,'cache')
        assert info['skipped_links'] == 1
        response = apply(client,info['ticket']).json()
        assert not response['errors'] and link.exists() # Protected result keeps the parent directory.
        assert (external/'keep.txt').read_text() == 'original'
    finally:
        link.rmdir()


def test_cleanup_flag_blocks_claim_and_startup_recovers_it(sample):
    from forensic_app.queue_control import QueueControl
    _,storage,*_ = sample
    with sqlite3.connect(storage.database) as c:
        c.execute('UPDATE cleanup_state SET active=1')
        c.execute("INSERT INTO cleanup_events(category,status,detail) VALUES ('cache','running','{}')")
    assert QueueControl(storage).claim() is None
    cleaner = Cleanup(storage,StorageOverview(storage))
    cleaner.initialize()
    with sqlite3.connect(storage.database) as c:
        assert c.execute('SELECT active FROM cleanup_state').fetchone()[0] == 0
        assert c.execute('SELECT status FROM cleanup_events').fetchone()[0] == 'interrupted'
