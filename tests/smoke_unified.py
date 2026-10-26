"""Unified configuration against a real EXE, with synthetic drafts and no analysis."""
import argparse
import json
import socket
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from smoke_support import wait_ready

from forensic_app import __version__
from forensic_app.desktop_session import DesktopSession
from forensic_app.launcher import parser


def main():
    options=argparse.ArgumentParser()
    options.add_argument('--exe',type=Path,required=True)
    exe=options.parse_args().exe.resolve()
    folder=Path(__file__).resolve().parents[1]/'.local-data'/('unified-smoke-'+str(time.time_ns()))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    session=DesktopSession(parser().parse_args(['--data-dir',str(folder/'state'),'--port',str(port),'--test-no-admin']),executable=exe)

    def wait(check):
        end=time.monotonic()+40
        while time.monotonic()<end:
            if result:=check():
                return result
            time.sleep(.15)
        raise TimeoutError('Own unified EXE smoke timed out')

    def api(path,body=None):
        req=Request(session.url+path,data=json.dumps(body).encode() if body is not None else None,
                    headers={'Authorization':'Bearer '+session.token,'Content-Type':'application/json'})
        with urlopen(req,timeout=8) as response:
            return json.load(response)

    try:
        session.start();wait_ready(session)
        original=api('/api/settings/configuration/export')
        assert original['schema_version'] == 4 and 'malware_modes' not in original and original['modes']
        document = dict(original, schema_version=3, malware_modes=[{'id':'legacy', 'never_execute':True}])
        preview = api('/api/settings/configuration/preview', {'document':document})
        assert preview['valid'] and preview['requires_legacy_confirmation']
        try:
            api('/api/settings/configuration/apply', {'ticket':preview['ticket']})
            raise AssertionError('Legacy omission accepted without confirmation')
        except HTTPError as exc:
            assert exc.code == 422
        api('/api/settings/configuration/apply', {'ticket':preview['ticket'], 'confirm_legacy_fields':True})
        assert api('/api/jobs')['total'] == 0
        session.stop();wait(lambda:not session.poll()['alive'])
        session.start();wait_ready(session)
        after=api('/api/settings/configuration/export')
        assert after['modes']==original['modes'] and 'malware_modes' not in after
        assert api('/api/jobs')['total']==0
        session.stop();wait(lambda:not session.poll()['alive'])
        report={'passed':True,'version':__version__,'checks':['schema 4 forensic export', 'legacy omission preview and explicit confirmation',
            'atomic import without jobs', 'restart preserves forensic configuration']}
        (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'passed':True,'report':str(folder/'report.json'),'checks':len(report['checks'])}))
    finally:
        if session.guard:
            session.force()


if __name__=='__main__':
    main()
