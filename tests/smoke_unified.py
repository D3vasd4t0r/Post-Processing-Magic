"""Unified configuration against a real EXE, with synthetic drafts and no analysis."""
import argparse
import json
import socket
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

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
        session.start();wait(lambda:session.poll()['ready'])
        original=api('/api/settings/configuration/export')
        assert original['schema_version']==3 and original['malware_modes']==[] and original['modes']
        saved=api('/api/settings/malware',{'name':'Own unified PDF draft','evidence_format':'PDF','effort':'Medium',
                                          'steps':[{'name':'Metadata only','inspector':'metadata'}]})
        document=api('/api/settings/configuration/export')
        assert document['malware_modes'][0]['id']==saved['id'] and document['modes']==original['modes']
        (folder/'own-export.json').write_text(json.dumps(document),encoding='utf-8')
        broken={k:v for k,v in document.items() if k!='malware_modes'}
        try:
            api('/api/settings/configuration/preview',{'document':broken,'strategy':'replace'})
            raise AssertionError('Incomplete schema 3 accepted')
        except HTTPError as exc:
            assert exc.code==422
        preview=api('/api/settings/configuration/preview',{'document':document})
        assert preview['valid'] and preview['total_modes']==preview['total_malware_modes']==1
        api('/api/settings/configuration/apply',{'ticket':preview['ticket']})
        assert api('/api/jobs')['total']==0
        session.stop();wait(lambda:not session.poll()['alive'])
        session.start();wait(lambda:session.poll()['ready'])
        after=api('/api/settings/configuration/export')
        assert after['modes']==document['modes'] and after['malware_modes']==document['malware_modes']
        assert api('/api/jobs')['total']==0
        session.stop();wait(lambda:not session.poll()['alive'])
        report={'passed':True,'version':__version__,'checks':['both categories even when empty','one export with both workflow categories',
            'incomplete schema 3 rejected','preview and atomic import without jobs','restart preserves both categories']}
        (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'passed':True,'report':str(folder/'report.json'),'checks':len(report['checks'])}))
    finally:
        if session.guard:
            session.force()


if __name__=='__main__':
    main()
