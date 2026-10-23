"""Synthetic local viewer contracts; subprocess is replaced, no GUI starts."""
import hashlib
import json
import sqlite3
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from forensic_app import result_viewers as viewers
from forensic_app.api import create_app
from forensic_app.storage import Storage


@pytest.fixture
def setup(tmp_path,monkeypatch):
    storage=Storage(tmp_path/'state')
    app=create_app(storage,'viewer-secret',lan=True)
    monkeypatch.setattr(viewers,'interactive_desktop',lambda:True)
    opened=[]
    monkeypatch.setattr(viewers.subprocess,'Popen',lambda args,**kwargs: opened.append((args,kwargs)) or SimpleNamespace(pid=123))
    with TestClient(app,base_url='http://127.0.0.1',client=('127.0.0.1',3210),headers={'Authorization':'Bearer viewer-secret'}) as client:
        ident=str(uuid4())
        plan={'mode':{'name':'Synthetic viewer fixture','output_folder':'PostMortem'},'command':'Own fixture never execute','tool':{}}
        with sqlite3.connect(storage.database) as connection:
            connection.execute("INSERT INTO jobs(id,status,phase,config_json) VALUES (?,'succeeded','Done',?)",(ident,json.dumps(plan)))
        output=storage.root/'work'/ident/'PostMortem';output.mkdir(parents=True)
        (output/'own.csv').write_text('Name,Value\nOwn,42\n')
        report=storage.root/'results'/ident;report.mkdir()
        (report/'Abschlussbericht.json').write_text(json.dumps({'files':[{'path':'own.csv','bytes':18}]}))
        exe=tmp_path/'TimelineExplorer.exe';exe.write_bytes(b'own synthetic exe, never run')
        dll=exe.with_suffix('.dll');dll.write_bytes(b'own synthetic dll')
        monkeypatch.setitem(viewers.VIEWERS,'timeline',('Timeline Explorer','TimelineExplorer','.csv',hashlib.sha256(exe.read_bytes()).hexdigest(),hashlib.sha256(dll.read_bytes()).hexdigest()))
        storage.save_tool('viewer-own','Timeline Explorer',str(exe),create=True)
        yield client,app,storage,ident,output,exe,opened


def test_click_launch_uses_exact_argument_list_and_audit(setup):
    client,_,storage,ident,output,exe,opened=setup
    url='/api/jobs/'+ident+'/viewer'
    assert client.get(url,params={'path':'own.csv'}).json()['available']
    assert not opened
    assert client.post(url,json={'kind':'timeline','path':'own.csv'}).json()['requested']
    args,options=opened[0]
    assert args==[str(exe),str(output/'own.csv')] and options['shell'] is False
    with sqlite3.connect(storage.database) as c:
        event=json.loads(c.execute("SELECT payload FROM job_events WHERE kind='viewer'").fetchone()[0])
    assert event['actor']=='authenticated-local' and event['result']=='own.csv'


def test_auth_remote_forwarded_header_and_path_checks(setup):
    client,app,_,ident,_,_,opened=setup
    url='/api/jobs/'+ident+'/viewer'
    payload={'kind':'timeline','path':'own.csv'}
    assert client.post(url,json=payload,headers={'Authorization':''}).status_code==401
    with TestClient(app,base_url='http://192.0.2.1',client=('192.0.2.7',42),headers={'Authorization':'Bearer viewer-secret'}) as remote:
        assert remote.post(url,json=payload,headers={'X-Forwarded-For':'127.0.0.1'}).status_code==403
    for path in ['../own.csv','C:/own.csv','own.csv:stream']:
        assert client.post(url,json={'kind':'timeline','path':path}).status_code==422
    assert client.post(url,json={'kind':'timeline','path':'missing.csv'}).status_code==404
    assert not opened


def test_changed_missing_viewer_desktop_and_cleanup_are_blocked(setup,monkeypatch):
    client,_,storage,ident,_,exe,opened=setup
    url='/api/jobs/'+ident+'/viewer';payload={'kind':'timeline','path':'own.csv'}
    exe.with_suffix('.dll').write_bytes(b'changed version')
    assert client.post(url,json=payload).status_code==409
    assert 'nicht' in client.get(url,params={'path':'own.csv'}).json()['reason']
    exe.unlink()
    assert not client.get(url,params={'path':'own.csv'}).json()['available']
    monkeypatch.setattr(viewers,'interactive_desktop',lambda:False)
    assert client.post(url,json=payload).status_code==409
    monkeypatch.setattr(viewers,'interactive_desktop',lambda:True)
    with sqlite3.connect(storage.database) as c:c.execute('UPDATE cleanup_state SET active=1 WHERE id=1')
    assert client.post(url,json=payload).status_code==409
    assert not opened
