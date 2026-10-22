"""Bounded technical snapshots: allowlisted events instead of raw log redaction."""
import hashlib
import io
import json
import platform
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
from contextlib import closing
from datetime import UTC, datetime
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from forensic_app import __version__
from forensic_app.server_preferences import PreferenceStore
from forensic_app.workspaces import no_links

STATIC = {
    'Waiting for application startup.':'Anwendungsstart wird vorbereitet.',
    'Application startup complete.':'Anwendung gestartet.',
    'Shutting down':'Server wird beendet.',
    'Waiting for application shutdown.':'Anwendung wird beendet.',
    'Application shutdown complete.':'Anwendung beendet.',
    'Server gestartet. Steuerung über Serverfenster oder Weboberfläche.':'Server gestartet.',
    'Geordnetes Stoppen angefordert. Neue Aufträge gesperrt, wartende zurückgehalten.':'Geordnetes Stoppen angefordert.',
    'Laufende Arbeiten abgeschlossen. Server wird gestoppt.':'Laufende Arbeiten abgeschlossen; Server stoppt.',
    'Stopstatus konnte nicht geprüft werden; erneuter Versuch folgt.':'Stopstatus-Prüfung fehlgeschlagen.',
    'Self-Signed: Browser-Vertrauen muss auf jedem Gerät bestätigt werden.':'Selbstsigniertes HTTPS aktiv.',
}


def technical_event(message):
    if message in STATIC:
        return STATIC[message]
    if re.fullmatch(r'(Started|Finished) server process \[[0-9]+\]',message):
        return 'Serverprozess '+('gestartet.' if message.startswith('Started') else 'beendet.')
    if re.fullmatch(r'Aufbereitung [0-9a-f-]{36} fehlgeschlagen',message):
        return 'Aufbereitung fehlgeschlagen; Auftragsdetails ausgelassen.'
    if message.startswith('Server: ') and ' | Token-Datei: ' in message:
        return 'Serveradresse und Token-Datei eingerichtet; Werte ausgelassen.'
    if re.fullmatch(r'(ValueError|OSError|PermissionError|RuntimeError|FileNotFoundError|TimeoutError|HTTPException):.*',message):
        return 'Fehlerklasse: '+message.split(':',1)[0]+' (Details ausgelassen).'
    return None


class Diagnostics:
    def __init__(self,storage,status=dict):
        self.storage,self.status = storage,status
        self.lock = threading.Lock()
        self.tickets = {}

    def preview(self):
        now = datetime.now(UTC).isoformat()
        current = self.status()
        prefs,_ = PreferenceStore(self.storage).get()
        info = {'schema_version':1,'created_at_utc':now,'app_version':__version__,
                'python_version':'.'.join(map(str,sys.version_info[:3])),
                'os':platform.system(),'os_release':platform.release(),'architecture':platform.machine(),
                'server_running':bool(current.get('server_running',False)),
                'worker_running':bool(current.get('worker_running',False)),
                'administrator':bool(current.get('administrator',False)),
                'configured_server_settings':prefs.model_dump(), 'queue_counts':{},'database_available':False}
        info['active_server'] = {key:current[key] for key in ('port','log_max_bytes','log_backups') if type(current.get(key)) is int}
        info['active_server']['lan'] = bool(current.get('lan',False))
        try:
            with closing(sqlite3.connect('file:'+self.storage.database.as_posix()+'?mode=ro',uri=True)) as c:
                c.execute('BEGIN')
                info['queue_counts'] = {status:c.execute('SELECT count(*) FROM jobs WHERE status=?',(status,)).fetchone()[0]
                                       for status in ('queued','running','uploading','validating','failed','interrupted','succeeded','cancelled')}
                info['database_available'] = True
        except sqlite3.Error:
            pass
        events,omitted,read,skipped,truncated = [],0,0,0,0
        for name in ('server.log.3','server.log.2','server.log.1','server.log'):
            path = self.storage.root/'logs'/name
            try:
                no_links(path)
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    skipped += 1
                    continue
                with path.open('rb') as stream:
                    start = max(0,metadata.st_size-65536)
                    stream.seek(start)
                    data = stream.read(65536)
                if start:
                    truncated += 1
                    data = data.split(b'\n',1)[-1] if b'\n' in data else b''
                read += 1
                for line in data.decode('utf-8',errors='replace').splitlines():
                    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (INFO|WARNING|ERROR|CRITICAL) (.*)',line)
                    message = match[3] if match else line
                    mapped = technical_event(message)
                    if mapped:
                        prefix = match[1]+' '+match[2]+' ' if match else ''
                        events.append(prefix+mapped)
                    else:
                        omitted += 1
            except FileNotFoundError:
                continue
            except (OSError,ValueError):
                skipped += 1
        info['log_filter'] = {'read_files':read,'skipped_files':skipped,'omitted_lines':omitted,
                              'truncated_sources':truncated,'exported_events':min(800,len(events))}
        texts = {
            'Systemstatus.json':json.dumps(info,ensure_ascii=False,indent=2),
            'Serverereignisse.txt':'Bereinigte technische Ereignisse; Quelllogzeit ohne Zeitzonenangabe.\n'+ '\n'.join(events[-800:]),
            'HINWEISE.txt':'Dieses Paket enthält ausschließlich technische Statusdaten und erkannte, normalisierte Serverereignisse.\n'
                'Unbekannte Logmeldungen, Stacktrace-Details, Pfade, Namen und Werte werden ausgelassen.\n'
                'Keine Tokens, Schlüssel, Evidenzen, Ergebnisse, Toolbefehle, Befehlsausgaben oder Feedbacktexte.\n'
                'Aktuelle Logdatei und bis zu drei letzte Rotationen, je höchstens 64 KiB; höchstens 800 erkannte Ereignisse.\n'
                'Export bleibt lokal. Zum Teilen ist eine eigene bewusste Übermittlung nötig.\n'}
        manifest = [{'name':name,'bytes':len(value.encode('utf-8')),'sha256':hashlib.sha256(value.encode('utf-8')).hexdigest()}
                    for name,value in texts.items()]
        texts['Manifest.json'] = json.dumps({'schema_version':1,'files':manifest},indent=2)
        output = io.BytesIO()
        with ZipFile(output,'w',compression=ZIP_DEFLATED) as archive:
            for name,value in texts.items():
                archive.writestr(name,value)
        ticket = secrets.token_urlsafe(24)
        with self.lock:
            self.tickets = {key:value for key,value in self.tickets.items() if value[0]>time.monotonic()}
            while len(self.tickets)>=4:
                self.tickets.pop(next(iter(self.tickets)))
            self.tickets[ticket] = (time.monotonic()+600,output.getvalue())
        return {'ticket':ticket,'expires_seconds':600,'files':[{'name':name,'bytes':len(value.encode('utf-8')),'text':value} for name,value in texts.items()],
                'message':'Vorschau entspricht exakt dem Export. Unbekannte Logdetails werden ausgelassen; kein automatischer Versand.'}

    def export(self,ticket):
        with self.lock:
            record = self.tickets.pop(ticket,None)
        if not record or record[0] <= time.monotonic():
            raise HTTPException(410,'Vorschau abgelaufen oder bereits exportiert. Bitte neu erstellen.')
        return record[1]


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ticket: str = Field(min_length=1,max_length=100)


def diagnostics_router(service,authorize):
    router = APIRouter(prefix='/api/diagnostics',dependencies=[Depends(authorize)])
    @router.post('/preview')
    def preview():
        return service.preview()
    @router.post('/export')
    def export(value:ExportRequest):
        return Response(service.export(value.ticket),media_type='application/zip',
                        headers={'Content-Disposition':'attachment; filename="Diagnosepaket.zip"'})
    return router
