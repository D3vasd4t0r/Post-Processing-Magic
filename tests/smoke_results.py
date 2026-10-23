"""Real EXE result previews; only self-generated ZIP/CSV/valid XLSX fixtures."""
import argparse
import json
import runpy
import socket
import time
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from zipfile import ZIP_DEFLATED, ZipFile

from smoke_support import wait_ready

from forensic_app import __version__
from forensic_app.desktop_session import DesktopSession
from forensic_app.launcher import parser
from forensic_app.modes import ModeDraft, ModeStore
from forensic_app.storage import Storage


def main():
    options=argparse.ArgumentParser();options.add_argument('--exe',type=Path,required=True)
    exe=options.parse_args().exe.resolve()
    folder=Path(__file__).resolve().parents[1]/'.local-data'/('results-smoke-'+str(time.time_ns()))
    storage=Storage(folder/'state');storage.initialize()
    modes=ModeStore(storage);modes.initialize();mode=modes.list_modes()[0]['id']
    modes.save(mode,ModeDraft(name='Own result smoke',effort='Medium',steps=[{'type':'powershell',
        'script':"New-Item -ItemType Directory PostMortem -Force | Out-Null; Copy-Item Targets/C/* PostMortem/"}]),create=False)
    workbook=folder/'own.xlsx'
    runpy.run_path(str(Path(__file__).with_name('test_xlsx_preview.py')))['package'](workbook)
    with ZipFile(workbook) as z:parts={name:z.read(name) for name in z.namelist()}
    parts['_rels/.rels']=parts['_rels/.rels'].replace(b'Type="officeDocument"',b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"')
    parts['[Content_Types].xml']=b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
    with ZipFile(workbook,'w',ZIP_DEFLATED) as z:
        for name,data in parts.items():z.writestr(name,data)
    evidence=folder/'own.zip'
    with ZipFile(evidence,'w',ZIP_DEFLATED) as z:
        z.write(workbook,'C/own.xlsx');z.writestr('C/own.csv','Name,Value\nC,10\nA,2\nB,1\n')
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    session=DesktopSession(parser().parse_args(['--data-dir',str(storage.root),'--port',str(port),'--test-no-admin']),executable=exe)
    def api(path,body=None,raw=False):
        request=Request(session.url+path,data=json.dumps(body).encode() if body is not None else None,
                        headers={'Authorization':'Bearer '+session.token,'Content-Type':'application/json'})
        with urlopen(request,timeout=10) as response:
            data=response.read();return data if raw else json.loads(data)
    try:
        session.start();wait_ready(session)
        ident=api('/api/jobs/local',{'mode_id':mode,'path':str(evidence),'create_zip':False})['id']
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            state=api('/api/jobs/'+ident)
            if state['status'] in ('succeeded','failed','cancelled'):break
            time.sleep(.15)
        assert state['status']=='succeeded',state.get('error_detail')
        base='/api/jobs/'+ident
        assert sorted(api(base+'/preview?format=all')['files'])==['own.csv','own.xlsx']
        csv=api(base+'/preview?'+urlencode({'format':'csv','path':'own.csv','sort_column':1,'sort_kind':'number','limit':1}))
        assert csv['rows'][0]['values']==['B','1'] and csv['scanned_rows']==3 and csv['has_more']
        xlsx=api(base+'/preview?'+urlencode({'format':'xlsx','path':'own.xlsx','sort_column':1,'sort_kind':'number'}))
        assert xlsx['sheets'][0]['name']=='Evidence' and xlsx['rows'][0]['values']==['Alpha','2']
        html=api(base+'/report',raw=True)
        assert b'<details open>' in html and b'print-content' in html
        assert not api(base+'/viewer?path=own.csv')['available']
        assert api('/api/settings/viewers')['viewers'][0]['tool'] is None
        assert state['input_inventory']['classifier_version']==2
        session.stop()
        report={'passed':True,'version':__version__,'checks':['real ZIP worker','recorded result files','CSV numeric before page','XLSX sheet and numeric sort','collapsible and print report','missing viewer blocked','no automatic viewer config','inventory classifier 2']}
        (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'passed':True,'report':str(folder/'report.json'),'checks':len(report['checks'])}))
    finally:
        if session.guard:session.force()


if __name__=='__main__':main()
