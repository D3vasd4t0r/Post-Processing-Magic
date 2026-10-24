"""Synthetic end-to-end evidence extensions; no real sample or KAPE execution."""
import copy
import json
import sqlite3
import struct
import threading

import pytest
from fastapi.testclient import TestClient
from test_pe_details import directory, imports
from test_static_analysis import fixture_bytes, mode_document, run_upload

from forensic_app.api import create_app
from forensic_app.jobs import JobService, JobStore
from forensic_app.kape_plan import compile_plan
from forensic_app.modes import KAPE_TEMPLATE
from forensic_app.storage import Storage
from forensic_app.worker import execute, process_job


def synthetic_pe(bits=64):
    data,dirs,_section=imports(bits)
    struct.pack_into('<H',data,0x84,0x8664 if bits==64 else 0x14c)
    directory(data,dirs,2,0x1500,0x100)
    struct.pack_into('<HH',data,0x900+12,0,1)
    struct.pack_into('<II',data,0x910,10,0x20)
    struct.pack_into('<4I',data,0x920,0x1800,3,0,0)
    data[0xc00:0xc03]=b'OWN'
    directory(data,dirs,4,0x1800,16)
    struct.pack_into('<IHH',data,0x1800,12,0x200,2)
    marker=b' http://evidence.invalid/test 192.0.2.23 C:\\Own\\file.txt '
    data[0x1f00:0x1f00+len(marker)]=marker
    return bytes(data)


@pytest.fixture
def own(tmp_path,monkeypatch):
    storage=Storage(tmp_path/'state')
    monkeypatch.setattr(JobService,'available',lambda self:True)
    with TestClient(create_app(storage,'own-extended',test_no_admin=True),base_url='http://127.0.0.1',headers={'Authorization':'Bearer own-extended'}) as client:
        yield client,storage


@pytest.mark.parametrize('bits',[32,64])
def test_pe_and_indicator_snapshots_html_and_authorized_export(own,bits):
    client,storage=own
    content=synthetic_pe(bits)
    ident,store=run_upload(client,storage,'EXE',content)
    state=store.get(ident)
    assert state['status']=='succeeded',state
    assert store.plan(ident)['report_features']=={'pe_details':1,'indicators':1}
    summary=client.get('/api/jobs/'+ident+'/summary').json()
    pe=summary['pe_details'][0]
    assert pe['imports']['entries'][0]['dll']=='EXAMPLE.dll'
    assert pe['imports']['function_count']==2
    assert pe['resources']['entries'][0]['bytes']==3
    assert pe['overlay']['signature_verification']=='not_performed'
    assert len(pe['overlay']['certificate_entries'])==1
    indicators=summary['indicators']['indicators']
    url=next(item for item in indicators if item['type']=='url')
    assert url['value']=='http://evidence.invalid/test'
    assert url['sources'][0]['byte_offset']==content.index(url['value'].encode())
    assert client.get('/api/jobs/'+ident+'/indicators',headers={'Authorization':''}).status_code==401
    exported=client.get('/api/jobs/'+ident+'/indicators')
    assert 'attachment' in exported.headers['content-disposition']
    assert exported.json()==summary['indicators']
    raw=client.get('/api/jobs/'+ident+'/report?format=json').json()
    assert raw['indicators']==exported.json()
    html=client.get('/api/jobs/'+ident+'/report').text
    assert 'Deklarierte PE-Importe' in html and 'EXAMPLE.dll' in html
    assert '<a href="http://evidence.invalid' not in html
    assert 'Zertifikatbereiche' in html and 'Indikatoren mit Quellen' in html


def test_old_snapshot_does_not_reextract_indicators(own):
    client,storage=own
    mode=client.post('/api/settings/malware',json=mode_document('PDF')).json()['id']
    response=client.post('/api/jobs',params={'workspace':'malware','mode_id':mode,'filename':'own.pdf'},headers={'Content-Type':'application/octet-stream'},content=fixture_bytes('PDF'))
    ident=response.json()['id'];store=JobStore(storage);plan=store.plan(ident);plan.pop('report_features')
    with sqlite3.connect(storage.database) as connection:
        connection.execute('UPDATE jobs SET config_json=? WHERE id=?',(json.dumps(plan),ident))
    process_job(store,ident,plan,threading.Event(),runner=lambda *args:pytest.fail('No external tool'))
    assert store.get(ident)['status']=='succeeded'
    assert client.get('/api/jobs/'+ident+'/summary').json()['indicators'] is None
    assert client.get('/api/jobs/'+ident+'/indicators').status_code==409
    assert 'indicators' not in client.get('/api/jobs/'+ident+'/report?format=json').json()


def test_module_manifest_freeze_and_verify_before_process(tmp_path,monkeypatch):
    executable=tmp_path/'kape.exe';executable.write_bytes(b'Own placeholder never run')
    folder=tmp_path/'Modules';folder.mkdir();module=folder/'Own.mkape';module.write_text('Description: Own synthetic module\n',encoding='utf-8')
    mode=copy.deepcopy(KAPE_TEMPLATE.model_dump());mode['id']='own';mode['steps'][0]['tool_id']='own'
    mode['steps'][0]['parameters']=r'--msource .\Targets\C --mdest .\PostMortem --module Own --gui'
    tools=[{'id':'own','name':'Own','path':str(executable)}]
    preview=compile_plan(mode,tools)
    assert 'module_manifest' not in preview['commands'][0]
    plan=compile_plan(mode,tools,capture=True)['commands'][0];plan['test_no_admin']=True
    assert plan['module_manifest']['files'][0]['relative_path']=='Modules/Own.mkape'
    module.write_text('Description: Modified after capture\n',encoding='utf-8')
    monkeypatch.setattr('forensic_app.worker.subprocess.Popen',lambda *args,**kwargs:pytest.fail('Changed module must prevent process start'))
    with pytest.raises(ValueError,match='KAPE-Modul'):
        execute(plan,tmp_path,lambda:None,lambda text:None)


@pytest.mark.parametrize('locale',['de','en'])
def test_extended_html_escapes_values_and_retains_print_sections(locale):
    from forensic_app.artifacts import render_report
    raw='<script>own()</script>'
    detail={'imports':{'status':'limited','entries':[{'dll':raw,'functions':[{'kind':'name','name':raw}]}]},
            'resources':{'status':'completed','entries':[{'path':[{'name':raw}],'bytes':1}]},
            'overlay':{'status':'error','entries':[]}}
    report={'configuration':{'locale':locale},'pe_details':[detail],
            'indicators':{'status':'completed','indicators':[{'type':'url','value':raw,'sources':[{'source_step':raw,'byte_offset':0}]}]}}
    original=copy.deepcopy(report)
    html=render_report(report)
    assert raw not in html and '&lt;script&gt;own()&lt;/script&gt;' in html
    assert '<a href=' not in html and report==original
    assert html.count('class="print-content"')==html.count('<section>')


def test_manifest_schema_boolean_rejected():
    from forensic_app.kape_manifest import ManifestVerificationError, verify_manifest
    with pytest.raises(ManifestVerificationError):
        verify_manifest({'schema_version':True,'scope':'direct_kape_files','tool_root':'','files':[]})
