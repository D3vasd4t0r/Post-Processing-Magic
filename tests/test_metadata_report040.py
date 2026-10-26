"""Only synthetic output files; reports never include script or content findings."""
import copy
import json
from types import SimpleNamespace
from uuid import uuid4
from zipfile import ZipFile

from forensic_app.artifacts import (
    archive_files,
    make_archive,
    metadata_report,
    prepare_report,
    render_report,
)


def test_projection_is_recursive_allowlist_and_idempotent():
    original={'configuration':{'locale':'en','case_number':'CASE','device_name':'DEVICE','mode':{'name':'Medium','output_folder':'PostMortem','script':'SECRET_SCRIPT'},
               'commands':[{'command':'SECRET_COMMAND','tool':{'name':'KAPE','version':'1','sha256':'b'*64,'path':'SECRET_PATH'}}]},
               'command_runs':[{'index':1,'started_at_utc':'start','ended_at_utc':'end','exit_code':0,'stdout':'SECRET_STDOUT'}],
               'input':{'sha1':'a'*40,'sha256':'b'*64,'bytes':10,'findings':'SECRET_INPUT'},
               'archive':{'created':True,'filename':'own.zip','sha1':'a'*40,'sha256':'b'*64,'output':'SECRET_ARCHIVE'},
               'error':'SECRET_ERROR_OUTPUT','log_tail':'SECRET_TERMINAL',
               'pe_details':['SECRET_PE'],'indicators':['SECRET_IOC'],'finding_summaries':['SECRET_FINDING'],
               'files':[{'path':'own.txt','bytes':10,'content':'SECRET_FILE'}],
               'input_inventory':{'files':1,'bytes':10,'groups':{'analysis':'SECRET_CLASSIFICATION'},'files_metadata':[{'path':'C/own','bytes':10,'parsed':'SECRET_PARSED'}]}}
    before=copy.deepcopy(original)
    clean=metadata_report(original)
    assert original==before
    assert 'SECRET_' not in json.dumps(clean)
    assert 'SECRET_' not in render_report(original)
    assert metadata_report(clean)==clean
    assert clean['case_number']=='CASE' and clean['device_name']=='DEVICE'
    assert clean['command_runs'][0]['tool']=={'name':'KAPE','version':'1','sha256':'b'*64}
    assert clean['input']['sha1']=='a'*40 and clean['archive']['filename']=='own.zip'
    assert clean['error_present'] is True


class SyntheticStore:
    def __init__(self,root,ident):
        self.storage=SimpleNamespace(root=root)
        self.ident=ident
        self.state={'input_sha1':'a'*40,'input_sha256':'b'*64,'input_size':9,'created_at':'2026-01-01T00:00:00Z','exit_code':0,'input_inventory':None}
    def get(self,ident):
        assert ident==self.ident
        return self.state.copy()
    def paths(self,ident):
        return self.storage.root,self.storage.root/'work'/ident,self.storage.root/'results'/(ident+'.zip')
    def update(self,ident,**fields):
        assert ident==self.ident
        self.state.update(fields)


def test_archive_contains_fresh_metadata_and_outputs_without_old_findings_or_terminal(tmp_path):
    ident=str(uuid4())
    for folder in ('work','results','evidence'):
        (tmp_path/folder).mkdir()
    store=SyntheticStore(tmp_path,ident)
    work=tmp_path/'work'/ident;output=work/'PostMortem';output.mkdir(parents=True)
    contents={name:b'SYNTHETIC_USER_OUTPUT' for name in ('command.log','KAPE-Kommandozeile.log','Pruefung-old.json','Pruefung-old.html','Abschlussbericht.json','Abschlussbericht.html','Aufbereitungsprotokoll.json','CustomTool/command.log','Reports/pruefung-fall.json')}
    contents['table.csv']=b'name,value\nexample,3\n'
    for name,body in contents.items():
        (output/name).parent.mkdir(parents=True,exist_ok=True)
        (output/name).write_bytes(body)
    (work/'command.log').write_text('SECRET_COMMAND_LOG')
    historical=tmp_path/'results'/'previous-job'/'Abschlussbericht.json'
    historical.parent.mkdir()
    historical.write_bytes(b'SECRET_HISTORICAL_APP_REPORT')
    plan={'filename':'input.zip','mode':{'name':'Medium','output_folder':'PostMortem'},'commands':[{'command':'SECRET_COMMAND'}]}
    report=prepare_report(store,ident,plan,[{'index':1,'exit_code':0}])
    make_archive(store,ident,plan,report,lambda:None)
    path=tmp_path/'results'/(ident+'.zip')
    with ZipFile(path) as archive:
        assert set(archive.namelist())=={'PostMortem/'+name for name in contents}|{'Aufbereitungsprotokoll.json','Abschlussbericht.html'}
        for name,body in contents.items():
            assert archive.read('PostMortem/'+name)==body
        assert archive.read('PostMortem/table.csv')==contents['table.csv']
        for name in ('Aufbereitungsprotokoll.json','Abschlussbericht.html'):
            assert b'SECRET_' not in archive.read(name)
    for name,body in contents.items():
        assert (output/name).read_bytes()==body
    saved=json.loads((tmp_path/'results'/ident/'Abschlussbericht.json').read_text(encoding='utf-8'))
    assert saved['archive']['filename']==path.name
    assert saved['archive']['sha1']==store.state['result_sha1']
    assert saved['archive']['sha256']==store.state['result_sha256']
    assert historical.read_bytes()==b'SECRET_HISTORICAL_APP_REPORT'
    assert saved['result_file_count']==len(contents)
    assert saved['directory_statistics']==[{'path':'.','files':8},{'path':'CustomTool','files':1},{'path':'Reports','files':1}]
    assert not any('SECRET_' in str(value) for value in saved.values())


def test_legacy_archive_requests_remain_passive_and_do_not_block_forensics(tmp_path):
    import sqlite3
    import threading

    from forensic_app.artifacts import ArchiveQueue

    database=tmp_path/'synthetic.sqlite'
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE jobs(id TEXT PRIMARY KEY,config_json TEXT);
            CREATE TABLE archive_requests(job_id TEXT,status TEXT,updated_at TEXT);
            CREATE TABLE server_control(id INTEGER,stopping INTEGER);
            CREATE TABLE cleanup_state(id INTEGER,active INTEGER);
            CREATE TABLE queue_control(id INTEGER,paused INTEGER);
            INSERT INTO server_control VALUES(1,0);
            INSERT INTO cleanup_state VALUES(1,0);
            INSERT INTO queue_control VALUES(1,0);
            INSERT INTO jobs VALUES('legacy','{"workspace":"malware"}');
            INSERT INTO jobs VALUES('current','{}');
            INSERT INTO archive_requests VALUES('legacy','queued','2020');
            INSERT INTO archive_requests VALUES('current','queued','2021');
        """)
    queue=ArchiveQueue(SimpleNamespace(storage=SimpleNamespace(database=database)))
    assert queue.claim()=='current'
    assert queue.claim() is None
    queue.run('legacy',threading.Event())
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT status FROM archive_requests WHERE job_id='legacy'").fetchone()[0]=='queued'



def test_only_explicit_provenance_paths_are_excluded_not_matching_basenames(tmp_path):
    output=tmp_path/'output';output.mkdir()
    owned=output/'old-app'/'Abschlussbericht.json';owned.parent.mkdir();owned.write_bytes(b'old app report')
    user=output/'CustomTool'/'Abschlussbericht.json';user.parent.mkdir();user.write_bytes(b'user report')
    assert set(archive_files(output,1024))=={owned,user}
    assert archive_files(output,1024,app_artifact_paths=(owned,))==[user]
    assert owned.read_bytes()==b'old app report'


def test_directory_statistics_are_direct_bounded_metadata_with_zero_folders():
    files=[{'path':'Top/file.txt','bytes':1},{'path':'Top/Child/own.csv','bytes':2}]
    report=metadata_report({'files':files,'directories':['.','Top','Top/Child','Empty']})
    assert report['directory_statistics']==[{'path':'.','files':0},{'path':'Empty','files':0},{'path':'Top','files':1},{'path':'Top/Child','files':1}]
    assert report['directory_statistics_truncated'] is False
    assert 'Dateien direkt in diesem Ordner' in render_report(report)
    large=metadata_report({'directories':[f'folder-{index:04d}' for index in range(1005)]})
    assert len(large['directory_statistics'])==1000
    assert large['directory_statistics_truncated'] is True
    assert metadata_report(large)==large
