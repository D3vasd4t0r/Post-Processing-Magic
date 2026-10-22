import hashlib
import io
import json
import os
import time
from pathlib import Path
from zipfile import ZipFile

import pytest
from pydantic import ValidationError
from test_processing import setup as setup  # noqa: PLC0414

from forensic_app.diagnostics import Diagnostics
from forensic_app.server_preferences import PreferenceStore, ServerPreferences, prune_server_logs


def test_diagnostics_excludes_secrets_paths_commands_and_feedback_and_matches_preview(setup,monkeypatch):
    client,storage,_,_ = setup
    secrets = ['processing-secret','OLD_ACCESS_TOKEN_123456789','PRIVATE_EVIDENCE_NAME','SECRET_COMMAND_OUTPUT','PRIVATE_FEEDBACK']
    lines = ['2026-10-22 12:00:00,000 INFO Application startup complete.',
             '2026-10-22 12:00:01,000 INFO Server: http://127.0.0.1 | Token-Datei: C:/PRIVATE_EVIDENCE_NAME/token',
             '2026-10-22 12:00:02,000 ERROR Aufbereitung aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa fehlgeschlagen',
             'ValueError: '+secrets[3],*secrets,'  File "C:/PRIVATE_EVIDENCE_NAME/file.py", line 30',
             '2026-10-22 12:00:03,000 INFO Application startup complete. '+secrets[1]]
    (storage.root/'logs/server.log').write_text('\n'.join(lines),encoding='utf-8')
    client.post('/api/feedback',json={'category':'bug','title':secrets[4],'text':'Private only'})
    original_open = Path.open
    def safe_open(path,*args,**kwargs):
        assert not any(path.is_relative_to(storage.root/name) for name in ['evidence','work','results'])
        return original_open(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',safe_open)
    response = client.post('/api/diagnostics/preview')
    assert response.status_code == 200,response.text
    preview = response.json()
    (storage.root/'logs/server.log').write_text('Changed after preview',encoding='utf-8')
    result = client.post('/api/diagnostics/export',json={'ticket':preview['ticket']})
    assert result.status_code == 200
    with ZipFile(io.BytesIO(result.content)) as archive:
        assert set(archive.namelist()) == {file['name'] for file in preview['files']}
        for file in preview['files']:
            assert archive.read(file['name']).decode('utf-8') == file['text']
        all_text = '\n'.join(archive.read(name).decode('utf-8') for name in archive.namelist())
        assert not any(secret in all_text for secret in secrets)
        assert 'Fehlerklasse: ValueError' in all_text
        manifest = json.loads(archive.read('Manifest.json'))
        for item in manifest['files']:
            assert hashlib.sha256(archive.read(item['name'])).hexdigest() == item['sha256']
    assert client.post('/api/diagnostics/export',json={'ticket':preview['ticket']}).status_code == 410
    assert client.post('/api/diagnostics/preview',headers={'Authorization':''}).status_code == 401


def test_diagnostic_preview_expiration_and_hardlink_rejection(setup,tmp_path):
    _,storage,_,_ = setup
    other = tmp_path/'private.txt'
    other.write_text('PRIVATE OUTSIDE FILE',encoding='utf-8')
    os.link(other,storage.root/'logs/server.log')
    service = Diagnostics(storage)
    preview = service.preview()
    info = json.loads(preview['files'][0]['text'])
    assert info['log_filter']['skipped_files'] == 1
    assert 'PRIVATE OUTSIDE FILE' not in str(preview)
    _expiry,content = service.tickets[preview['ticket']]
    service.tickets[preview['ticket']] = (time.monotonic()-1,content)
    with pytest.raises(Exception) as error:
        service.export(preview['ticket'])
    assert error.value.status_code == 410
    for _ in range(7):
        service.preview()
    assert len(service.tickets) == 4


def test_feedback_local_export_validation_and_config_exclusion(setup):
    client,storage,_,_ = setup
    value = {'category':'wish','title':'<script>literal title</script>','text':'Do not execute: mkdir C:/Example\nOwn feedback'}
    saved = client.post('/api/feedback',json=value)
    assert saved.status_code == 200,saved.text
    item = client.get('/api/feedback').json()['items'][0]
    assert item['title'] == value['title'] and item['text'] == value['text']
    export = client.get('/api/feedback/export').json()
    assert export['schema_version'] == 1 and export['feedback'][0]['text'] == value['text']
    assert 'feedback' not in client.get('/api/settings/configuration/export').json()
    assert client.post('/api/feedback',json={**value,'category':'execute'}).status_code == 422
    assert client.post('/api/feedback',json={**value,'text':'x'*8001}).status_code == 422
    assert client.post('/api/feedback',content=b'x'*65537).status_code == 413
    assert client.get('/api/feedback/export',headers={'Authorization':''}).status_code == 401
    from forensic_app.feedback import FeedbackStore
    assert FeedbackStore(storage).list()[0]['id'] == item['id']


def test_server_preferences_persist_and_rotation_only_removes_owned_numbered_logs(setup):
    client,storage,_,_ = setup
    prefs = PreferenceStore(storage)
    assert prefs.get()[0].log_max_bytes == 2_000_000
    prefs.save(ServerPreferences(port=8999,lan=True,log_max_bytes=100000,log_backups=1))
    assert PreferenceStore(storage).get()[0].port == 8999
    assert prefs.get()[1] == 1
    for name in ['server.log.1','server.log.2','command.log','evidence.zip','server.log.backup']:
        (storage.root/'logs'/name).write_text('Synthetic log',encoding='utf-8')
    target = storage.root/'evidence/original.txt'
    target.write_text('Keep original',encoding='utf-8')
    os.link(target,storage.root/'logs/server.log.3')
    prune_server_logs(storage,1)
    assert not (storage.root/'logs/server.log.2').exists()
    for name in ['server.log.1','server.log.3','command.log','evidence.zip','server.log.backup']:
        assert (storage.root/'logs'/name).exists()
    assert target.read_text(encoding='utf-8') == 'Keep original'
    assert 'server_preferences' not in client.get('/api/settings/configuration/export').json()


@pytest.mark.parametrize('field,value',[('port',0),('port',True),('lan','true'),('log_max_bytes',99999),('log_backups',0),('log_backups',21)])
def test_server_preferences_reject_invalid_values(field,value):
    with pytest.raises(ValidationError):
        ServerPreferences.model_validate({field:value})


def test_launcher_loads_saved_preferences_and_respects_explicit_cli(setup,monkeypatch):
    _,storage,_,_ = setup
    PreferenceStore(storage).save(ServerPreferences(port=8999,lan=True))
    from forensic_app.launcher import main
    observed = []
    monkeypatch.setattr('forensic_app.desktop.run_panel',lambda args:observed.append((args.port,args.lan)) or 0)
    assert main(['--test-no-admin','--data-dir',str(storage.root)]) == 0
    assert observed[-1] == (8999,True)
    assert main(['--test-no-admin','--data-dir',str(storage.root),'--port','8998','--local']) == 0
    assert observed[-1] == (8998,False)
