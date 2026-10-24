"""Real Windows EXE static pipeline; generated harmless fixtures only."""
import argparse
import hashlib
import io
import json
import socket
import time
from pathlib import Path
from urllib.request import Request, urlopen
from zipfile import ZipFile

from smoke_support import wait_ready
from test_extended_evidence import synthetic_pe
from test_static_analysis import fixture_bytes, mode_document

from forensic_app import __version__
from forensic_app.desktop_session import DesktopSession
from forensic_app.launcher import parser
from forensic_app.malware_modes import MalwareMode, MalwareModes
from forensic_app.storage import Storage


def main():
    options=argparse.ArgumentParser()
    options.add_argument('--exe',type=Path,required=True)
    exe=options.parse_args().exe.resolve()
    folder=Path(__file__).resolve().parents[1]/'.local-data'/('static-smoke-'+str(time.time_ns()))
    storage=Storage(folder/'state');storage.initialize()
    modes=MalwareModes(storage);modes.initialize()
    # Tool table is initialized by Storage, before the EXE initializes all remaining services.
    ids={kind:'synthetic-'+kind.lower() for kind in ('PDF','OFFICE','EXE')}
    for kind,ident in ids.items():
        modes.save(ident,MalwareMode.model_validate(mode_document(kind)),True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    session=DesktopSession(parser().parse_args(['--data-dir',str(storage.root),'--port',str(port),'--test-no-admin']),executable=exe)

    def wait(check,timeout=40):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            result=check()
            if result:
                return result
            time.sleep(.15)
        raise TimeoutError('Own static EXE smoke timed out')

    def api(path,method='GET',body=None,raw=False,mime='application/json'):
        data=body if isinstance(body,bytes) else json.dumps(body).encode() if body is not None else None
        request=Request(session.url+path,method=method,data=data,headers={'Authorization':'Bearer '+session.token,'Content-Type':mime})
        with urlopen(request,timeout=10) as response:
            return response.read() if raw else json.load(response)

    try:
        session.start();wait_ready(session)
        assert api('/api/system')['version']==__version__
        assert len(api('/api/jobs/catalog?workspace=malware')['modes'])==3
        for kind in ('PDF','OFFICE','EXE'):
            content=synthetic_pe() if kind=='EXE' else fixture_bytes(kind)
            extension={'PDF':'pdf','OFFICE':'docm','EXE':'exe'}[kind]
            path=folder/('own.'+extension);path.write_bytes(content)
            if kind=='PDF':
                ident=api('/api/jobs/local','POST',{'workspace':'malware','mode_id':ids[kind],'path':str(path)})['id']
            else:
                ident=api('/api/jobs?workspace=malware&mode_id='+ids[kind]+'&filename=own.'+extension,'POST',content,mime='application/octet-stream')['id']
            state=wait(lambda job_id=ident:(s if (s:=api('/api/jobs/'+job_id))['status'] in ('succeeded','failed','interrupted') else None))
            assert state['status']=='succeeded',state
            assert state['completed']==3 and state['workspace']=='malware'
            assert state['input_sha256']==hashlib.sha256(content).hexdigest()
            assert path.read_bytes()==content
            report=api('/api/jobs/'+ident+'/report',raw=True).decode()
            assert 'Statische Malware-Analyse' in report
            if kind=='EXE':
                details=api('/api/jobs/'+ident+'/summary')
                assert details['pe_details'][0]['imports']['function_count']==2
                assert details['pe_details'][0]['resources']['entries'][0]['bytes']==3
                assert details['pe_details'][0]['overlay']['signature_verification']=='not_performed'
                assert details['pe_details'][0]['overlay']['certificate_entries']
                indicators=api('/api/jobs/'+ident+'/indicators')
                assert any(item['value']=='http://evidence.invalid/test' for item in indicators['indicators'])
                assert 'Deklarierte PE-Importe' in report and 'EXAMPLE.dll' in report

            archive=api('/api/jobs/'+ident+'/download',raw=True)
            with ZipFile(io.BytesIO(archive)) as z:
                assert z.testzip() is None
                assert any(n.endswith('Pruefung-structure.json') for n in z.namelist())
                assert not any(n.endswith(('.exe','.pdf','.docm','.bin')) for n in z.namelist())
        # Offline catalogs, shared preferences, and immutable report language in the real EXE.
        with urlopen(session.url+'/locales/web/en.json',timeout=10) as response:
            assert json.load(response)['web.s495'].startswith('Shared configuration')
        assert not api('/api/settings/onboarding')['dismissed']
        api('/api/settings/interface','PUT',{'locale':'en','onboarding_dismissed':True})
        english_id=api('/api/jobs/local','POST',{'workspace':'malware','mode_id':ids['PDF'],'path':str(folder/'own.pdf')})['id']
        english_state=wait(lambda:(s if (s:=api('/api/jobs/'+english_id))['status'] in ('succeeded','failed','interrupted') else None))
        assert english_state['status']=='succeeded' and english_state['locale']=='en'
        raw_before=api('/api/jobs/'+english_id+'/report?format=json',raw=True)
        assert '<html lang="en">' in api('/api/jobs/'+english_id+'/report',raw=True).decode('utf-8')
        api('/api/settings/interface','PUT',{'locale':'de'})
        assert '<html lang="en">' in api('/api/jobs/'+english_id+'/report',raw=True).decode('utf-8')
        assert api('/api/jobs/'+english_id+'/report?format=json',raw=True)==raw_before
        assert api('/api/settings/onboarding')['dismissed']
        assert api('/api/jobs?workspace=forensics')['total']==0
        assert api('/api/jobs?workspace=malware')['total']==4
        exported=api('/api/settings/configuration/export')
        assert exported['schema_version']==3 and len(exported['malware_modes'])==3
        session.stop();wait(lambda:not session.poll()['alive'])
        session.start();wait_ready(session)
        assert api('/api/jobs?workspace=malware')['total']==4
        assert len(api('/api/settings/malware')['modes'])==3
        session.stop();wait(lambda:not session.poll()['alive'])
        report={'passed':True,'version':__version__,'checks':['PDF local static run','Office upload static run','PE upload static run',
            'originals and hashes','HTML reports and sample-free ZIPs','separate histories and schema 3 configuration','restart persistence','offline DE/EN catalogs and frozen English report with unchanged raw JSON','PE imports/resources/overlay and indicator provenance export']}
        (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'passed':True,'report':str(folder/'report.json'),'checks':len(report['checks'])}))
    finally:
        if session.guard:
            session.force()


if __name__=='__main__':
    main()
