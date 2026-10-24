"""Completion reports and explicitly requested serial result archives."""

import hashlib
import html
import json
import logging
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import HTTPException

from forensic_app import __version__
from forensic_app.app_errors import AppValueError, ErrorText
from forensic_app.processing_settings import ProcessingLimits
from forensic_app.report_i18n import ReportText
from forensic_app.server_control import accepting, draining
from forensic_app.windows_access import locked_input
from forensic_app.workspaces import job_paths, no_links
from forensic_app.zip_safety import ensure_space, output_files


def utc():
    return datetime.now(UTC).isoformat()


def hashes(path,check):
    sha1,sha256 = hashlib.sha1(),hashlib.sha256()
    with locked_input(path) as source:
        while chunk := source.read(8*1024**2):
            check()
            sha1.update(chunk)
            sha256.update(chunk)
    return {'sha1':sha1.hexdigest(),'sha256':sha256.hexdigest()}


def report_folder(store,ident):
    return store.paths(ident)[0]/'results'/ident


def render_report(report):
    """Readable, self-contained report; every value is untrusted text."""
    plan = report.get('configuration',{})
    t = ReportText(plan.get('locale','de'))

    def escape(value):
        return html.escape(str(value) if value is not None else t('absent'))

    def table(headers,rows):
        return '<div class="table"><table><thead><tr>'+''.join('<th>'+escape(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join(
            '<tr>'+''.join('<td>'+escape(value)+'</td>' for value in row)+'</tr>' for row in rows)+'</tbody></table></div>'

    def section(title,content):
        return '<section><details open><summary><h2>'+escape(title)+'</h2></summary>'+content+'</details><div class="print-content"><h2>'+escape(title)+'</h2>'+content+'</div></section>'

    mode = plan.get('mode',{})
    parts = [section(t('job'),table([t('field'),t('value')],[
        (t('case'),plan.get('case_number') or t('unspecified')),(t('device'),plan.get('device_name') or t('unspecified')),
        (t('job_id'),report.get('job_id')),(t('input'),report.get('input_filename')),
        (t('app_version'),report.get('app_version')),(t('mode'),mode.get('name')),
        (t('start'),report.get('created_at_utc')),(t('completed'),report.get('completed_at_utc')),
        (t('exit_code'),report.get('exit_code')),(t('error'),report.get('error') or t('no_error'))]))]
    inventory=report.get('input_inventory')
    if inventory:
        groups=inventory.get('groups',{})
        rows=[(t.known_text(group['label'],prefix='inventory.group.'),group['files'],group['bytes'],'; '.join(group['samples'])) for group in groups.values()]
        parts.append(section(t('inventory'), '<p>'+escape(t.known_text(inventory['scope_note'],prefix='inventory.scope'))+'</p><p>'+escape(t('inventory_complete') if inventory['complete'] else t('inventory_partial',reasons=', '.join(t('inventory.reason.'+reason) if 'inventory.reason.'+reason in t.de else reason for reason in inventory['partial_reasons'])))+'</p>'+table([t('group'),t('files'),t('logical_bytes'),t('examples')],rows)))
    elif plan.get('workspace','forensics')=='forensics':
        parts.append(section(t('inventory'),'<p>'+escape(t('inventory_missing'))+'</p>'))
    for summary in report.get('finding_summaries',[]):
        inspector=t.inspector(summary['inspector'])
        parts.append(section(inspector['name'],table([t('scope'),t('status')],[(inspector['scope'],inspector['status'])])+ '<p>'+escape(' '.join(inspector['limitations']))+'</p>'+table([t('feature'),t('value')],t.coverage(summary))))
    input_data,archive = report.get('input',{}),report.get('archive',{})
    parts.append(section(t('hashes'),table([t('file'),'SHA-1','SHA-256'],[
        (t('input'),input_data.get('sha1'),input_data.get('sha256')),
        (t('archive') if archive.get('created') else t('archive_missing'),archive.get('sha1'),archive.get('sha256'))])+
        '<p>'+escape(t.known_text(archive.get('note'),prefix='archive_') if archive.get('note') else t('archive_note'))+'</p>'))
    commands = plan.get('commands',[])
    rows = []
    for index,command in enumerate(commands):
        timing = next((run for run in report.get('command_runs',[]) if run.get('index') == index+1),{})
        rows.append((index+1,command.get('type',command.get('kind',t('tool'))),
                     command.get('tool',{}).get('path',''),
                     command.get('command',''),
                     command.get('working_directory','.'),command.get('timeout_seconds',86400),timing.get('started_at_utc'),timing.get('ended_at_utc'),timing.get('exit_code')))
    parts.append(section(t('commands'),table([t('number'),t('type'),t('program'),t('parameters'),t('work_folder'),t('timeout'),t('start'),t('end'),t('exit_code')],rows)))
    parts.append(section(t('tool_versions'),table([t('command'),t('tool'),t('version'),'SHA-256'],[
        (index+1,command.get('tool',{}).get('name'),command.get('tool',{}).get('version'),command.get('tool',{}).get('sha256'))
        for index,command in enumerate(commands)])))
    for key,title in [('work_directories',t('work_dirs')),('directories',t('result_dirs'))]:
        parts.append(section(title,table([t('relative_path')],[(value,) for value in report.get(key,[])[:2000]])))
    parts.append(section(t('result_files'),table([t('relative_path'),t('bytes')],[(item['path'],item['bytes']) for item in report.get('files',[])[:2000]])))
    heading = t('heading_malware') if plan.get('workspace')=='malware' else t('heading_forensics')
    return '<!doctype html><html lang="'+t.locale+'"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>'+escape(t('title'))+'</title><style>body{font:16px/1.5 system-ui;max-width:1200px;margin:40px auto;background:#eef3fa;color:#10223a;padding:20px}section{background:white;padding:24px;margin:20px 0;border:1px solid #c3d3e4;border-radius:12px}h1,h2{color:#174a83}.print-content{display:none}summary{cursor:pointer}summary h2{display:inline;margin:0}summary:focus-visible{outline:2px solid #174a83;outline-offset:4px}details[open]>summary{margin-bottom:16px}.table{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #c3d3e4;overflow-wrap:anywhere;white-space:pre-wrap}th{background:#e6eff9}@media print{details{display:none}.print-content{display:block}body{background:white;margin:0}section{break-inside:avoid}}</style><h1>'+escape(t('heading',workspace=heading))+'</h1><p>'+escape(t('hash_notice'))+'</p>'+''.join(parts)+'<p>'+escape(t('list_notice'))+'</p></html>'


def save_report(store,ident,report):
    folder = report_folder(store,ident)
    folder.mkdir(exist_ok=True)
    if folder.is_symlink() or folder.is_junction():
        raise AppValueError('error.6320d7a26e6c')
    encoded = json.dumps(report,ensure_ascii=False,indent=2)
    body = render_report(report)
    for name,content in [('Abschlussbericht.json',encoded),('Abschlussbericht.html',body)]:
        temporary = folder/(name+'.part')
        temporary.write_text(content,encoding='utf-8')
        temporary.replace(folder/name)


def prepare_report(store,ident,plan,command_runs,*,error=None):
    _root,work,_ = job_paths(store.storage,plan,ident)
    output = work/Path(*PureWindowsPath(plan['mode']['output_folder']).parts)
    state = store.get(ident)
    report = {'report_schema_version':1,'app_version':__version__,'job_id':ident,'input_filename':plan.get('filename','Evidence.zip'),
              'input':{'sha1':state.get('input_sha1'),'sha256':state.get('input_sha256'),'bytes':state['input_size']},
              'case_number':plan.get('case_number',''),'device_name':plan.get('device_name',''),
              'input_inventory':state.get('input_inventory'),
              'configuration':plan,'created_at_utc':state['created_at'],'completed_at_utc':utc(),
              'command_runs':command_runs,'exit_code':state['exit_code'],'error':error,
              'directories':[],'directories_scope':'Unterordner im Ergebnisordner', 'work_directories':[],
              'work_directories_note':'Vorhandene Unterordner im eigenen Arbeitsordner am Ende; Verknüpfungen werden nicht verfolgt.', 'files':[], 'archive':{'created':False,'sha1':None,'sha256':None},
              'note':'Exitcodes und vorhandene Ausgaben geprüft; fachliche Vollständigkeit manuell beurteilen.'}
    if state.get('input_sha1') is None:
        report['input']['note'] = 'Kein SHA-1 gespeichert (älterer oder unvollständiger Auftrag). Original nicht nachträglich gelesen.'
    if work.exists():
        no_links(work)
        for current,subdirs,_ in os.walk(work,followlinks=False):
            subdirs[:] = [name for name in subdirs if not (Path(current)/name).is_symlink() and not (Path(current)/name).is_junction()]
            report['work_directories'].extend((Path(current)/name).relative_to(work).as_posix() for name in subdirs)
            if len(report['work_directories']) >= 200_000:
                report['work_directories'] = report['work_directories'][:200_000]
                report['work_directories_note'] += ' Liste bei 200.000 Einträgen begrenzt.'
                break
    if error is None:
        no_links(output)
        if not output.resolve().is_relative_to(work.resolve()):
            raise AppValueError('error.89045519c588')
        files = output_files(output,max_bytes=ProcessingLimits.model_validate(plan.get('limits',{})).max_extract_bytes)
        report['files'] = [{'path':p.relative_to(output).as_posix(),'bytes':p.stat().st_size} for p in files]
        directories = ['.']
        for current,subdirs,_ in os.walk(output,followlinks=False):
            directories.extend((Path(current)/name).relative_to(output).as_posix() for name in subdirs)
        report['directories'] = sorted(directories)
    if plan.get('workspace')=='malware' and output.is_dir():
        from forensic_app.finding_summary import summarize_finding
        summaries=[]
        no_links(output)
        for path in sorted(output.glob('Pruefung-*.json'))[:64]:
            no_links(path)
            if path.stat().st_size > 4*1024**2:
                continue
            try:
                data=json.loads(path.read_text(encoding='utf-8'))
                summaries.append(summarize_finding(data))
            except (ValueError,OSError):
                continue
        report['finding_summaries']=summaries
    save_report(store,ident,report)
    return report


def make_archive(store,ident,plan,report,check):
    root,work,result = job_paths(store.storage,plan,ident)
    output = work/Path(*PureWindowsPath(plan['mode']['output_folder']).parts)
    if not output.resolve().is_relative_to(work.resolve()):
        raise AppValueError('error.89045519c588')
    files = output_files(output,max_bytes=ProcessingLimits.model_validate(plan.get('limits',{})).max_extract_bytes)
    ensure_space(root,sum(p.stat().st_size for p in files))
    temporary = result.with_suffix('.part')
    if result.exists():
        raise AppValueError('error.cebc3390dbde')
    embedded = dict(report,archive={'created':True,'sha1':None,'sha256':None,
        'note':'Hash des fertigen ZIP steht im separat herunterladbaren Abschlussbericht; kein selbstreferenzieller Archivhash.'})
    try:
        with ZipFile(temporary,'x',compression=ZIP_DEFLATED,allowZip64=True) as archive:
            for path in files:
                check()
                with path.open('rb') as source, archive.open(output.name+'/'+path.relative_to(output).as_posix(),'w',force_zip64=True) as target:
                    while chunk := source.read(1024**2):
                        check()
                        target.write(chunk)
            archive.writestr('Aufbereitungsprotokoll.json',json.dumps(embedded,ensure_ascii=False,indent=2))
            archive.writestr('Abschlussbericht.html',render_report(embedded))
            log = work/'command.log'
            if log.is_file():
                archive.write(log,'KAPE-Kommandozeile.log')
            else:
                archive.writestr('KAPE-Kommandozeile.log','Vollständiger Command-Log wurde bereits bereinigt.\n'+store.get(ident)['log_tail'])
        check()
        digest = hashes(temporary,check)
        temporary.replace(result)
        store.update(ident,result_sha1=digest['sha1'],result_sha256=digest['sha256'])
        report['archive'] = {'created':True,'created_at_utc':utc(),**digest}
        save_report(store,ident,report)
    finally:
        temporary.unlink(missing_ok=True)


class ArchiveQueue:
    def __init__(self,store):
        self.store = store
        self.storage = store.storage

    def request(self,ident):
        state = self.store.get(ident)
        if state['status'] != 'succeeded' or state['result_available']:
            raise HTTPException(409,ErrorText('error.5e9534a3c737'))
        from forensic_app.explorer import ResultExplorer
        ResultExplorer(self.storage,self.store).folder(ident)
        with closing(sqlite3.connect(self.storage.database)) as c,c:
            c.execute('BEGIN IMMEDIATE')
            accepting(c)
            if c.execute('SELECT active FROM cleanup_state WHERE id=1').fetchone()[0]:
                raise HTTPException(409,ErrorText('error.ebe88a997f31'))
            if c.execute("SELECT count(*) FROM archive_requests WHERE status IN ('queued','running')").fetchone()[0] >= 16:
                raise HTTPException(409,ErrorText('error.4afff115c0a7'))
            if c.execute("SELECT 1 FROM archive_requests WHERE job_id=? AND status IN ('queued','running')",(ident,)).fetchone():
                raise HTTPException(409,ErrorText('error.3e6ef8eddf18'))
            c.execute("INSERT INTO archive_requests(job_id,status) VALUES (?,'queued') ON CONFLICT(job_id) DO UPDATE SET status='queued',error=NULL,cancel_requested=0,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",(ident,))
            c.execute("INSERT INTO job_events(job_id,kind,payload) VALUES (?,'archive',?)",(ident,json.dumps({'status':'queued','actor':'authenticated-user'})))
        return {'queued':True}

    def claim(self):
        with closing(sqlite3.connect(self.storage.database)) as c,c:
            c.execute('BEGIN IMMEDIATE')
            if draining(c):
                return None
            if c.execute('SELECT active FROM cleanup_state WHERE id=1').fetchone()[0] or c.execute('SELECT paused FROM queue_control WHERE id=1').fetchone()[0]:
                return None
            row = c.execute("SELECT job_id FROM archive_requests WHERE status='queued' ORDER BY updated_at,job_id LIMIT 1").fetchone()
            if row:
                c.execute("UPDATE archive_requests SET status='running' WHERE job_id=?",(row[0],))
            return row[0] if row else None

    def run(self,ident,stop):
        def check():
            if stop.is_set():
                raise InterruptedError('Dienst beendet. Keine automatische Wiederholung.')
            with closing(sqlite3.connect(self.storage.database)) as c:
                if c.execute('SELECT cancel_requested FROM archive_requests WHERE job_id=?',(ident,)).fetchone()[0]:
                    raise InterruptedError('Archivierung abgebrochen; Ergebnisordner bleibt erhalten.')
        status,error = 'done',None
        try:
            plan = self.store.plan(ident)
            previous = report_folder(self.store,ident)/'Abschlussbericht.json'
            report = json.loads(previous.read_text(encoding='utf-8')) if previous.is_file() else prepare_report(self.store,ident,plan,[])
            check()
            # Re-scan output metadata; user may have changed the result folder after completion.
            fresh = prepare_report(self.store,ident,plan,report.get('command_runs',[]))
            fresh['completed_at_utc'] = report['completed_at_utc']
            make_archive(self.store,ident,plan,fresh,check)
        except InterruptedError as exc:
            status,error = ('interrupted' if stop.is_set() else 'cancelled'),str(exc)
        except Exception as exc:
            logging.getLogger(__name__).exception('Archivierung %s fehlgeschlagen',ident)
            status,error = 'failed',str(exc)
        with closing(sqlite3.connect(self.storage.database)) as c,c:
            c.execute('UPDATE archive_requests SET status=?,error=?,updated_at=? WHERE job_id=?',(status,error,utc(),ident))
            c.execute("INSERT INTO job_events(job_id,kind,payload) VALUES (?,'archive',?)",(ident,json.dumps({'status':status,'error':error})))
