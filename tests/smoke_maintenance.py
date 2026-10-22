"""Real EXE, own settings/logs/feedback only; never user evidence."""
import argparse
import io
import json
import socket
import time
from pathlib import Path
from urllib.request import Request, urlopen
from zipfile import ZipFile

from smoke_support import wait_ready

from forensic_app import __version__
from forensic_app.desktop_session import DesktopSession
from forensic_app.diagnostics import Diagnostics
from forensic_app.launcher import parser
from forensic_app.server_preferences import ServerPreferences
from forensic_app.storage import Storage


def main():
    options = argparse.ArgumentParser()
    options.add_argument('--exe',type=Path,required=True)
    exe = options.parse_args().exe.resolve()
    folder = Path(__file__).resolve().parents[1]/'.local-data'/('maintenance-smoke-'+str(time.time_ns()))
    root = folder/'state'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); first_port = sock.getsockname()[1]
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); second_port = sock.getsockname()[1]
    args = parser().parse_args(['--data-dir',str(root),'--port',str(first_port),'--test-no-admin'])
    session = DesktopSession(args,executable=exe)
    def wait(check):
        end = time.monotonic()+40
        while time.monotonic()<end:
            if check(): return
            time.sleep(.15)
        raise TimeoutError('Own maintenance smoke timed out')
    def api(path,method='GET',body=None,raw=False):
        req = Request(session.url+path,method=method,data=json.dumps(body).encode() if body is not None else None,
                      headers={'Authorization':'Bearer '+session.token,'Content-Type':'application/json'})
        with urlopen(req,context=session.context(),timeout=5) as response:
            return response.read() if raw else json.load(response)
    try:
        session.start(); wait_ready(session)
        first_token = session.token
        api('/api/feedback','POST',{'category':'bug','title':'OWN_PRIVATE_FEEDBACK','text':'Synthetic text only'})
        preview = api('/api/diagnostics/preview','POST')
        content = api('/api/diagnostics/export','POST',{'ticket':preview['ticket']},raw=True)
        with ZipFile(io.BytesIO(content)) as archive:
            text = '\n'.join(archive.read(name).decode('utf-8') for name in archive.namelist())
            assert first_token not in text and 'OWN_PRIVATE_FEEDBACK' not in text
            assert json.loads(archive.read('Systemstatus.json'))['active_server']['port'] == first_port
        session.configure(ServerPreferences(port=second_port,lan=True,log_max_bytes=100000,log_backups=1))
        assert session.poll()['restart_required']
        assert session.url == 'http://127.0.0.1:'+str(first_port)
        session.stop(); wait(lambda:not session.poll()['alive'])
        session.start(); wait_ready(session)
        assert session.url == 'https://127.0.0.1:'+str(second_port)
        assert session.token != first_token
        system = api('/api/system')
        assert system['mode'] == 'LAN / HTTPS' and system['runtime']['log_max_bytes'] == 100000
        assert system['runtime']['log_backups'] == 1
        assert api('/api/feedback')['items'][0]['title'] == 'OWN_PRIVATE_FEEDBACK'
        assert api('/api/feedback/export')['feedback'][0]['text'] == 'Synthetic text only'
        with (root/'logs/server.log').open('ab') as stream:
            stream.write(b'OWN_SYNTHETIC_LOG_LINE\n'*6000)
        session.stop(); wait(lambda:not session.poll()['alive'])
        assert (root/'logs/server.log.1').exists()
        offline = Diagnostics(Storage(root)).preview()
        assert json.loads(offline['files'][0]['text'])['server_running'] is False
        session.configure(ServerPreferences(port=first_port,lan=False,log_max_bytes=100000,log_backups=1))
        session.start(); wait_ready(session)
        assert session.url == 'http://127.0.0.1:'+str(first_port)
        assert api('/api/system')['runtime']['lan'] is False
        session.stop(); wait(lambda:not session.poll()['alive'])
        report = {'passed':True,'version':__version__,'checks':['diagnostic privacy and exact preview export',
            'feedback persists and exports','settings deferred until deliberate stop/start',
            'changed port and certificate-validated self-signed HTTPS','configured log threshold and backups active',
            'actual technical log rotation','offline diagnostic preview','return to local HTTP']}
        (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'passed':True,'report':str(folder/'report.json'),'checks':len(report['checks'])}))
    finally:
        if session.guard: session.force()


if __name__ == '__main__':
    main()
