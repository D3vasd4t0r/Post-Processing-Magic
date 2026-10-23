import copy
import hashlib
import io
import json
import struct
import threading
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from forensic_app.api import create_app
from forensic_app.jobs import JobService, JobStore
from forensic_app.malware_modes import MalwareMode, compile_static
from forensic_app.static_analysis import inspect_sample
from forensic_app.storage import Storage
from forensic_app.worker import process_job


def fixture_bytes(kind):
    if kind=='PDF':
        return b'%PDF-1.7\n% harmless synthetic raw bytes\n/Java#53cript /OpenAction\n</pre><script>alert(1)</script>\n%%EOF'
    if kind=='OFFICE':
        stream=io.BytesIO()
        with ZipFile(stream,'w',compression=ZIP_DEFLATED) as z:
            z.writestr('[Content_Types].xml','Synthetic XML; never parsed')
            z.writestr('word/document.xml','A'*2_000_000)
            z.writestr('word/vbaProject.bin',b'Own non-executable marker')
        return stream.getvalue()
    data=bytearray(512)
    data[:2]=b'MZ'
    struct.pack_into('<I',data,60,128)
    data[128:132]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',data,132,0x8664,1,0,0,0,0,0)
    data[152:160]=b'.sample\0'
    struct.pack_into('<IIII',data,160,32,4096,32,256)
    data[256:288]=b'Own data. No runnable machinecode'
    return bytes(data)


def mode_document(kind='PDF'):
    inspector={'PDF':'pdf','OFFICE':'office','EXE':'pe'}[kind]
    return {'name':'Synthetic '+kind,'evidence_format':kind,'effort':'Medium','output_folder':'Analysis',
            'steps':[{'id':'meta','name':'Metadaten','inspector':'metadata'},
                     {'id':'structure','name':'Struktur','inspector':inspector},
                     {'id':'strings','name':'Strings','inspector':'strings'}]}


@pytest.fixture
def setup(tmp_path,monkeypatch):
    storage=Storage(tmp_path/'state')
    monkeypatch.setattr(JobService,'available',lambda self:True)
    with TestClient(create_app(storage,'static-secret',test_no_admin=True),base_url='http://127.0.0.1',headers={'Authorization':'Bearer static-secret'}) as client:
        yield client,storage


def run_upload(client,storage,kind,content=None):
    mode=client.post('/api/settings/malware',json=mode_document(kind))
    assert mode.status_code==201,mode.text
    response=client.post('/api/jobs',params={'workspace':'malware','mode_id':mode.json()['id'],'filename':'own.'+{'PDF':'pdf','OFFICE':'docm','EXE':'exe'}[kind]},
                         headers={'Content-Type':'application/octet-stream'},content=content if content is not None else fixture_bytes(kind))
    assert response.status_code==200,response.text
    ident=response.json()['id']
    store=JobStore(storage)
    process_job(store,ident,store.plan(ident),threading.Event(),runner=lambda *args:pytest.fail('No process may execute for static steps'))
    return ident,store


@pytest.mark.parametrize('kind',['PDF','OFFICE','EXE'])
def test_static_end_to_end_reports_hashes_and_original_not_exported(setup,kind):
    client,storage=setup
    content=fixture_bytes(kind)
    ident,store=run_upload(client,storage,kind)
    state=store.get(ident)
    assert state['status']=='succeeded',state
    assert state['workspace']=='malware' and state['completed']==3
    assert state['input_sha256']==hashlib.sha256(content).hexdigest()
    assert state['input_sha1']==hashlib.sha1(content).hexdigest()
    assert (store.paths(ident)[1]/'Sample/input.bin').read_bytes()==content
    archive=client.get('/api/jobs/'+ident+'/download')
    assert archive.status_code==200
    with ZipFile(io.BytesIO(archive.content)) as z:
        assert not any(n.lower().endswith(('.exe','.bin','.pdf','.docm')) for n in z.namelist())
        result=json.loads(z.read('Analysis/Pruefung-structure.json'))
        if kind=='PDF':
            assert result['findings']['keyword_counts']['JavaScript']==1
            page=z.read('Analysis/Pruefung-strings.html').decode()
            assert '<script>alert(1)</script>' not in page and '&lt;script&gt;' in page
        elif kind=='OFFICE':
            assert result['findings']['macro_named_entries']==['word/vbaProject.bin']
            assert (store.paths(ident)[1]/'Sample').iterdir()
        else:
            assert result['findings']['sections'][0]['raw_range_valid']
    assert client.get('/api/jobs',params={'workspace':'forensics'}).json()['total']==0
    assert client.get('/api/jobs',params={'workspace':'malware'}).json()['total']==1
    assert client.get('/api/jobs',params={'workspace':'forensics'}).json()['modes']==[]


@pytest.mark.parametrize('kind',['PDF','OFFICE','EXE'])
def test_invalid_signature_never_calls_runner_or_publishes_results(setup,kind):
    client,storage=setup
    ident,store=run_upload(client,storage,kind,b'Plain text instead of selected format')
    state=store.get(ident)
    assert state['status']=='failed' and state['error_detail']
    assert client.get('/api/jobs/'+ident+'/download').status_code==409


def test_module_partition_slots_shared_tool_warning_and_external_block(setup,tmp_path):
    client,_=setup
    assert client.get('/api/settings/malware',headers={'Authorization':''}).status_code==401
    mode=client.post('/api/settings/malware',json=mode_document()).json()
    assert client.post('/api/settings/malware',json={**mode_document(),'name':'Duplicate slot'}).status_code==409
    assert client.post('/api/settings/malware',json=mode_document('EXE')).status_code==201
    assert len(client.get('/api/settings/modes').json()['modes'])==1
    tool=client.post('/api/settings/tools',json={'name':'Parser draft','path':str(tmp_path/'not-started.exe')}).json()
    draft=mode_document()
    draft['steps']=[{'name':'External draft','type':'external','tool_id':tool['id'],'parameters':'--input {input}'}]
    assert client.put('/api/settings/malware/'+mode['id'],json=draft).status_code==200
    assert client.delete('/api/settings/tools/'+tool['id']).status_code==409
    assert client.get('/api/settings/tools').json()['tools'][0]['used_by'][0]['id']==mode['id']
    response=client.post('/api/jobs',params={'workspace':'malware','mode_id':mode['id'],'filename':'own.pdf'},headers={'Content-Type':'application/octet-stream'},content=fixture_bytes('PDF'))
    assert response.status_code==422 and 'Entwürfe' in response.text
    assert client.post('/api/jobs/local',json={'mode_id':mode['id'],'path':str(tmp_path/'missing.pdf')}).status_code==422


@pytest.mark.parametrize('change',[{'output_folder':'Sample/child'},{'steps':[{'id':'../../escape','name':'bad'}]},
    {'steps':[{'name':'Execute','type':'powershell','script':'evil'}]},
    {'steps':[{'name':'PE','inspector':'pe'}]},{'output_folder':'../outside'}])
def test_static_config_rejects_escape_and_execution_types(change):
    with pytest.raises(ValidationError):
        MalwareMode.model_validate({**mode_document(),**change})


def test_static_limits_partial_scan_and_no_office_extraction(tmp_path):
    pdf=tmp_path/'data.bin'
    pdf.write_bytes(fixture_bytes('PDF')+b'A'*(8*1024**2))
    strings=inspect_sample('strings',pdf,'PDF',lambda:None)
    assert strings['partial'] and strings['inspected_bytes']==8*1024**2 and len(strings['strings'])<=2000
    doc=tmp_path/'office.bin'
    doc.write_bytes(fixture_bytes('OFFICE'))
    result=inspect_sample('office',doc,'OFFICE',lambda:None)
    assert len(result['entries'])==3
    assert len(list(tmp_path.iterdir()))==2


def test_configuration_v3_roundtrip_stale_preview_and_legacy_preservation(setup):
    client,_=setup
    original=client.get('/api/settings/configuration/export').json()
    assert original['schema_version']==3 and original['malware_modes']==[]
    original['schema_version']=2
    original.pop('malware_modes')
    saved=client.post('/api/settings/malware',json=mode_document()).json()
    exported=client.get('/api/settings/configuration/export').json()
    assert exported['schema_version']==3 and exported['malware_modes'][0]['id']==saved['id']
    preview=client.post('/api/settings/configuration/preview',json={'document':exported}).json()
    assert preview['valid'] and preview['changes']['malware_modes']['unchanged']==1
    edited=copy.deepcopy(mode_document());edited['description']='Changed during preview'
    client.put('/api/settings/malware/'+saved['id'],json=edited)
    assert client.post('/api/settings/configuration/apply',json={'ticket':preview['ticket']}).status_code==409
    legacy=client.post('/api/settings/configuration/preview',json={'strategy':'replace','document':original}).json()
    assert legacy['valid'] and legacy['total_malware_modes']==1
    assert client.post('/api/settings/configuration/apply',json={'ticket':legacy['ticket'],'confirm_replace':True}).status_code==200
    assert client.get('/api/settings/malware').json()['modes'][0]['description']==edited['description']
    current=client.get('/api/settings/configuration/export').json()
    current['malware_modes']=[]
    preview=client.post('/api/settings/configuration/preview',json={'strategy':'replace','document':current}).json()
    assert client.post('/api/settings/configuration/apply',json={'ticket':preview['ticket'],'confirm_replace':True}).status_code==200
    assert client.get('/api/settings/malware').json()['modes']==[]


def test_local_change_abort_and_workspace_mismatch(setup,tmp_path):
    client,storage=setup
    mode=client.post('/api/settings/malware',json=mode_document()).json()
    file=tmp_path/'own.pdf';file.write_bytes(fixture_bytes('PDF'))
    bad=client.post('/api/jobs/local',json={'mode_id':mode['id'],'path':str(file),'workspace':'forensics'})
    assert bad.status_code==422
    ident=client.post('/api/jobs/local',json={'mode_id':mode['id'],'path':str(file),'workspace':'malware'}).json()['id']
    file.write_bytes(fixture_bytes('PDF')+b'changed')
    store=JobStore(storage)
    process_job(store,ident,store.plan(ident),threading.Event())
    assert store.get(ident)['status']=='failed' and 'verändert' in store.get(ident)['error']
    ident=client.post('/api/jobs/local',json={'mode_id':mode['id'],'path':str(file),'workspace':'malware'}).json()['id']
    stop=threading.Event();stop.set()
    process_job(store,ident,store.plan(ident),stop)
    assert store.get(ident)['status']=='interrupted' and file.read_bytes().endswith(b'changed')
    assert compile_static(mode)['commands'][0]['argv']==[]


@pytest.mark.parametrize('source',['upload','local'])
def test_static_case_device_snapshot(setup,tmp_path,source):
    client,storage=setup
    mode=client.post('/api/settings/malware',json=mode_document()).json()['id']
    metadata={'case_number':'Static case','device_name':'Own device'}
    if source=='local':
        path=tmp_path/'own.pdf'
        path.write_bytes(fixture_bytes('PDF'))
        response=client.post('/api/jobs/local',json={'workspace':'malware','mode_id':mode,'path':str(path),**metadata})
    else:
        response=client.post('/api/jobs',params={'workspace':'malware','mode_id':mode,'filename':'own.pdf',**metadata},content=fixture_bytes('PDF'),headers={'Content-Type':'application/octet-stream'})
    assert response.status_code==200,response.text
    store=JobStore(storage)
    ident=response.json()['id']
    assert store.plan(ident)['case_number']=='Static case'
    assert store.get(ident)['device_name']=='Own device'
    assert store.search(q='Own device',workspace='malware')['total']==1


def test_static_result_includes_readable_summary(tmp_path):
    from forensic_app.static_analysis import run_static
    folder=tmp_path/'Sample'
    folder.mkdir()
    (folder/'input.bin').write_bytes(fixture_bytes('PDF'))
    plan={'id':'own','inspector':'pdf','static_input':{'bytes':len(fixture_bytes('PDF'))},'mode':{'output_folder':'Analysis','evidence_format':'PDF'}}
    run_static(plan,tmp_path,lambda:None,lambda text:None)
    result=json.loads((tmp_path/'Analysis/Pruefung-own.json').read_text(encoding='utf-8'))
    assert result['summary']['inspector']['id']=='pdf'
    assert 'findings' in result
    page=(tmp_path/'Analysis/Pruefung-own.html').read_text(encoding='utf-8')
    assert 'PDF-Tokenlimit erreicht' in page and 'Rohbefund' in page
    assert '<script>' not in page


@pytest.mark.parametrize('kind',['PDF','OFFICE','EXE'])
def test_aggregated_summary_in_authorized_report_and_archive(setup,kind):
    client,storage=setup
    ident,store=run_upload(client,storage,kind)
    endpoint='/api/jobs/'+ident+'/report'
    response=client.get(endpoint+'?format=json')
    assert response.status_code==200
    report=response.json()
    summaries=report['finding_summaries']
    assert len(summaries)==3
    assert {item['inspector']['id'] for item in summaries}=={'metadata','strings',{'PDF':'pdf','OFFICE':'office','EXE':'pe'}[kind]}
    assert all('scope' in item['inspector'] and item['inspector']['limitations'] for item in summaries)
    assert all('strings' not in item['observations'] for item in summaries)
    metadata=next(item for item in summaries if item['inspector']['id']=='metadata')
    assert metadata['input']['hash_scope']=='whole_input'
    assert metadata['input']['sha256']==store.get(ident)['input_sha256']
    assert metadata['observations']['entropy_scope']=='first_1_mib'
    html=client.get(endpoint).text
    assert 'PDF-Tokenlimit' not in html or kind=='PDF'
    assert '<script>alert(1)</script>' not in html
    assert 'inspected_bytes' in html
    assert client.get(endpoint+'?format=json',headers={'Authorization':''}).status_code==401
    with ZipFile(io.BytesIO(client.get('/api/jobs/'+ident+'/download').content)) as archive:
        embedded=json.loads(archive.read('Aufbereitungsprotokoll.json'))
        assert embedded['finding_summaries']==summaries
