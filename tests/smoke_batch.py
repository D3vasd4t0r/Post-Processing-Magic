"""EXE-only integration of workspace, optional archive, reports and selected cleanup.
Always uses newly generated fixtures. Never accepts a user's evidence path.
"""
import argparse
import hashlib
import io
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen
from zipfile import ZipFile

from forensic_app.modes import ModeDraft, ModeStore
from forensic_app.processing_settings import ProcessingSettings
from forensic_app.storage import Storage


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe',type=Path,required=True)
    args = parser.parse_args()
    folder = Path(__file__).resolve().parents[1]/'.local-data'/('batch-smoke-'+str(time.time_ns()))
    storage = Storage(folder/'state')
    storage.initialize()
    ProcessingSettings(storage).initialize()
    modes = ModeStore(storage)
    modes.initialize()
    mode = modes.list_modes()[0]['id']
    modes.save(mode,ModeDraft(name='Synthetic batch only',effort='Medium',steps=[{'type':'powershell',
        'script':"New-Item -ItemType Directory PostMortem/Empty -Force | Out-Null; Set-Content PostMortem/result.txt 'Own synthetic batch'; Write-Output 'Synthetic only'"}]),create=False)
    stream = io.BytesIO()
    with ZipFile(stream,'w') as z:
        z.writestr('C/example.txt','Own synthetic input')
    evidence = stream.getvalue()
    original = folder/'own-original.zip'
    original.write_bytes(evidence)
    volume = folder/'volume'
    volume.mkdir()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port = sock.getsockname()[1]
    with (folder/'server.log').open('w') as log:
        process = subprocess.Popen([str(args.exe.resolve()),'--test-no-admin','--no-browser','--port',str(port),'--data-dir',str(storage.root)],
                                   stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            endpoint = f'http://127.0.0.1:{port}'
            for _ in range(120):
                try:
                    urlopen(endpoint+'/health',timeout=1).close()
                    break
                except URLError:
                    time.sleep(.25)
            else:
                raise RuntimeError('Own server failed to start')
            token = (storage.root/'config'/'access-token.txt').read_text().strip()
            def api(path,method='GET',body=None,raw=False):
                headers = {'Authorization':'Bearer '+token}
                data = None
                if body is not None:
                    if isinstance(body,bytes):
                        data = body
                        headers['Content-Type'] = 'application/zip'
                    else:
                        data = json.dumps(body).encode()
                        headers['Content-Type'] = 'application/json'
                with urlopen(Request(endpoint+path,data=data,method=method,headers=headers),timeout=30) as response:
                    content = response.read()
                    return content if raw else json.loads(content)
            def wait(ident,field,expected):
                for _ in range(240):
                    state = api('/api/jobs/'+ident)
                    if state[field] == expected:
                        return state
                    if state['status'] == 'failed' or state.get('archive_status') == 'failed':
                        raise AssertionError(state)
                    time.sleep(.25)
                raise RuntimeError('Own job did not finish')
            first = api('/api/jobs?mode_id='+mode+'&filename=own-upload.zip','POST',evidence)['id']
            wait(first,'status','succeeded')
            alternate = api('/api/settings/workspace','PUT',{'folder':str(volume)})['path']
            second = api('/api/jobs/local','POST',{'mode_id':mode,'path':str(original),'create_zip':False})['id']
            api('/api/settings/workspace','PUT',{'folder':None})
            state = wait(second,'status','succeeded')
            assert state['data_root'] == alternate and not state['result_available'] and state['report_available']
            assert state['input_sha1'] == hashlib.sha1(evidence).hexdigest()
            initial = api('/api/jobs/'+second+'/report?format=json')
            assert initial['archive']['created'] is False and 'Targets/C' in initial['work_directories']
            api('/api/jobs/'+second+'/archive','POST')
            wait(second,'archive_status','done')
            for ident in [first,second]:
                report = api('/api/jobs/'+ident+'/report?format=json')
                content = api('/api/jobs/'+ident+'/download',raw=True)
                assert report['archive']['sha1'] == hashlib.sha1(content).hexdigest()
                assert report['archive']['sha256'] == hashlib.sha256(content).hexdigest()
                assert report['command_runs'][0]['exit_code'] == 0
                assert api('/api/jobs/'+ident+'/report',raw=True).startswith(b'<!doctype html>')
                with ZipFile(io.BytesIO(content)) as z:
                    assert json.loads(z.read('Aufbereitungsprotokoll.json'))['archive']['sha256'] is None
            exported = api('/api/settings/configuration/export')
            preview = api('/api/settings/configuration/preview','POST',{'strategy':'merge','document':exported})
            assert preview['valid']
            api('/api/settings/configuration/apply','POST',{'ticket':preview['ticket']})
            for category in ['cache','evidence','results']:
                preview = api('/api/settings/cleanup/preview','POST',{'category':category,'job_id':second})
                result = api('/api/settings/cleanup/apply','POST',{'ticket':preview['ticket'],'confirmed':True})
                assert not result['errors'],result
            assert api('/api/jobs/'+first)['result_available']
            assert not api('/api/jobs/'+second)['report_available']
            assert original.read_bytes() == evidence
            assert (storage.root/'work'/first/'Targets'/'C'/'example.txt').exists()
            report = {'passed':True,'version':api('/api/system')['version'],'first':first,'second':second,
                      'checks':['frozen work destination','upload and local SHA1/SHA256','completion without ZIP',
                                'serial archive without rerunning analysis','final report and ZIP hashes','configuration round trip',
                                'selected cleanup across workspaces','local original and other job preserved']}
            (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps({'passed':True,'report':str(folder/'report.json'),'checks':len(report['checks'])}))
        finally:
            subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,check=False,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            process.wait(timeout=10)


if __name__ == '__main__':
    if os.name != 'nt':
        raise SystemExit('Windows only')
    main()
