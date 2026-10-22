"""Persistent upload/queue/event API. Analysis only runs in the separate worker."""

import asyncio
import hashlib
import json
import multiprocessing
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from datetime import date
from pathlib import Path, PureWindowsPath
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from forensic_app.config_transfer import ConfigurationTransfer
from forensic_app.explorer import ResultExplorer
from forensic_app.file_browser import BrowseRequest, browse
from forensic_app.job_errors import describe_error
from forensic_app.kape_plan import compile_plan
from forensic_app.local_paths import validate_local_path
from forensic_app.malware_modes import MAX_SAMPLE_BYTES, MalwareModes, compile_static
from forensic_app.processing_settings import ProcessingSettings
from forensic_app.server_control import accepting
from forensic_app.static_analysis import EXTENSIONS, validate_name
from forensic_app.storage import Storage
from forensic_app.windows_access import input_identity, is_admin, locked_input
from forensic_app.workspaces import Workspaces, job_paths, no_links
from forensic_app.zip_safety import ensure_space

MAX_UPLOAD = 50 * 1024**3
TERMINAL = ("succeeded", "failed", "cancelled", "interrupted")


class LocalJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode_id: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=4096)
    allow_high_compression: bool = False
    create_zip: bool = True
    workspace: Literal['forensics','malware'] = 'forensics'


class JobStore:
    def __init__(self, storage: Storage):
        self.storage = storage

    def initialize(self):
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, status TEXT NOT NULL, phase TEXT NOT NULL,
                    config_json TEXT NOT NULL, completed INTEGER NOT NULL DEFAULT 0,
                    cancel_requested INTEGER NOT NULL DEFAULT 0, input_size INTEGER NOT NULL DEFAULT 0,
                    input_sha256 TEXT, result_sha256 TEXT, error TEXT, exit_code INTEGER,
                    log_tail TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS job_events (
                    id INTEGER PRIMARY KEY, job_id TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL,
                    occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE INDEX IF NOT EXISTS job_event_cursor ON job_events(job_id,id);
            """)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
            for name in ("error_detail", "effective_json", "input_sha1", "result_sha1"):
                if name not in columns:
                    connection.execute(f"ALTER TABLE jobs ADD COLUMN {name} TEXT")
            if "current_step" not in columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN current_step INTEGER NOT NULL DEFAULT 0")

    def recover(self, reason='Server wurde neu gestartet. Keine automatische Wiederholung.'):
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("UPDATE archive_requests SET status='interrupted',error=? WHERE status IN ('queued','running')",(reason,))
            for ident, in connection.execute("SELECT id FROM jobs WHERE status NOT IN (?,?,?,?)", TERMINAL):
                connection.execute("UPDATE jobs SET status='interrupted',phase='Unterbrochen',error=? WHERE id=?",
                                   (reason, ident))
                connection.execute("INSERT INTO job_events(job_id,kind,payload) VALUES (?,'status',?)",
                                   (ident, json.dumps({"status": "interrupted"})))

    def search(self, *, q='', status=None, mode_id=None, date_from=None, date_to=None, limit=50, offset=0, workspace=None):
        if date_from and date_to and date_from > date_to:
            raise HTTPException(422, "Das Startdatum darf nicht nach dem Enddatum liegen.")
        conditions, values = [], []
        if workspace:
            conditions.append("COALESCE(json_extract(config_json,'$.workspace'),'forensics')=?")
            values.append(workspace)
        if q.strip():
            conditions.append("instr(casefold(COALESCE(json_extract(config_json,'$.filename'),'Evidence.zip') || ' ' || json_extract(config_json,'$.mode.name')),?)>0")
            values.append(q.strip().casefold())
        for condition, value in (("status=?",status), ("json_extract(config_json,'$.mode.id')=?",mode_id),
                                 ("substr(created_at,1,10)>=?",date_from.isoformat() if date_from else None),
                                 ("substr(created_at,1,10)<=?",date_to.isoformat() if date_to else None)):
            if value:
                conditions.append(condition)
                values.append(value)
        where = ' WHERE '+' AND '.join(conditions) if conditions else ''
        with closing(sqlite3.connect(self.storage.database)) as connection:
            connection.row_factory = sqlite3.Row
            connection.create_function('casefold',1,lambda value: str(value or '').casefold(),deterministic=True)
            connection.execute('BEGIN')
            total = connection.execute('SELECT count(*) FROM jobs'+where,values).fetchone()[0]
            if total and offset >= total:
                offset = ((total-1)//limit)*limit
            rows = connection.execute("SELECT id,status,phase,created_at,error,"
                "COALESCE(json_extract(config_json,'$.filename'),'Evidence.zip') AS filename,"
                "COALESCE(json_extract(config_json,'$.source_kind'),'upload') AS source_kind,"
                "json_extract(config_json,'$.mode.name') AS mode_name FROM jobs"+where+
                ' ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?',(*values,limit,offset)).fetchall()
            modes = connection.execute("SELECT DISTINCT json_extract(config_json,'$.mode.id') AS id,"
                "json_extract(config_json,'$.mode.name') AS name FROM jobs"+
                (" WHERE COALESCE(json_extract(config_json,'$.workspace'),'forensics')=?" if workspace else '')+
                ' ORDER BY name,id', (workspace,) if workspace else ()).fetchall()
        return {'jobs':[dict(row) for row in rows], 'total':total, 'limit':limit, 'offset':offset,
                'modes':[dict(row) for row in modes if row['id']]}

    def plan(self, ident):
        self.get(ident)
        with closing(sqlite3.connect(self.storage.database)) as c:
            return json.loads(c.execute('SELECT config_json FROM jobs WHERE id=?',(ident,)).fetchone()[0])

    def paths(self, ident):
        try:
            return job_paths(self.storage,self.plan(ident),ident)
        except (ValueError,OSError) as exc:
            raise HTTPException(409,'Arbeitsziel ist nicht sicher erreichbar: '+str(exc)) from exc

    def get(self, ident: str) -> dict:
        try:
            if str(UUID(ident)) != ident:
                raise ValueError()
        except ValueError as exc:
            raise HTTPException(404, "Aufbereitung nicht gefunden.") from exc
        with closing(sqlite3.connect(self.storage.database)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (ident,)).fetchone()
        if row is None:
            raise HTTPException(404, "Aufbereitung nicht gefunden.")
        result = dict(row)
        config = json.loads(result.pop("config_json"))
        effective = json.loads(result.pop("effective_json") or "null") or config
        commands = effective.get("commands") or [effective]
        current = commands[min(result["current_step"], len(commands)-1)]
        result["error_detail"] = json.loads(result["error_detail"] or "null")
        if result["status"] == "failed" and not result["error_detail"]:
            exc = PermissionError("KAPE meldet fehlende Administratorrechte, auch bei Exitcode 0.") if "administrator privileges not found" in result["log_tail"].casefold() else ValueError(result["error"] or "Vorgang ohne gespeicherte Fehlerdetails fehlgeschlagen.")
            result["error_detail"] = describe_error(exc, result["phase"])
        result.update(command=current["command"], requested_command=config["command"], mode_name=config["mode"]["name"], total=len(commands),
                      filename=config.get("filename", "Evidence.zip"), tool=current["tool"])
        result["current_name"] = current.get("name", "KAPE")
        result["current_kind"] = current.get("kind", "kape")
        result["source_kind"] = config.get("source_kind", "upload")
        result['workspace'] = config.get('workspace','forensics')
        result["local_path"] = config.get("local_input", {}).get("path")
        result["source_resolution"] = effective.get("source_resolution")
        result['storage_error'] = None
        result['output_available'] = False
        try:
            root,_work,archive = job_paths(self.storage,config,ident)
            result['data_root'] = str(root)
            result['result_available'] = result['status'] == 'succeeded' and archive.is_file()
            result['report_available'] = (root/'results'/ident/'Abschlussbericht.html').is_file()
            output = _work/Path(*PureWindowsPath(config['mode'].get('output_folder','PostMortem')).parts)
            if output.is_dir() and output.resolve().is_relative_to(_work.resolve()):
                no_links(output)
                result['output_available'] = result['status'] == 'succeeded'
        except (ValueError,OSError) as exc:
            result['data_root'] = config.get('data_root',str(self.storage.root))
            result['storage_error'] = str(exc)
            result['result_available'] = result['report_available'] = False
        result['create_zip'] = config.get('create_zip',True)
        with closing(sqlite3.connect(self.storage.database)) as c:
            item = c.execute('SELECT status,error FROM archive_requests WHERE job_id=?',(ident,)).fetchone()
        result['archive_status'] = item[0] if item else None
        result['archive_error'] = item[1] if item else None
        return result

    def update(self, ident: str, **values):
        allowed = {"status", "phase", "completed", "input_size", "input_sha256", "result_sha256", "error", "exit_code", "error_detail", "effective_json", "current_step", "input_sha1", "result_sha1"}
        assert values.keys() <= allowed
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("UPDATE jobs SET "+",".join(key+"=?" for key in values)+
                               ",updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                               (*values.values(), ident))
            connection.execute("INSERT INTO job_events(job_id,kind,payload) VALUES (?,'status',?)",
                               (ident, json.dumps(values, ensure_ascii=False)))

    def fail(self, ident: str, exc: BaseException):
        detail = describe_error(exc, self.get(ident)["phase"])
        self.update(ident, status="failed", phase="Fehlgeschlagen", error=detail["message"],
                    error_detail=json.dumps(detail, ensure_ascii=False))
        self.log(ident, "\nFEHLER ["+detail["phase"]+"]: "+detail["message"]+"\nHinweis: "+detail["recommendation"]+"\n")

    def log(self, ident: str, text: str):
        text = text[-8192:]
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("UPDATE jobs SET log_tail=substr(log_tail || ?, -65536) WHERE id=?", (text, ident))
            connection.execute("INSERT INTO job_events(job_id,kind,payload) VALUES (?,'log',?)",
                               (ident, json.dumps({"text": text}, ensure_ascii=False)))

    def events(self, ident: str, after: int):
        with closing(sqlite3.connect(self.storage.database)) as connection:
            return [{"id": row[0], "kind": row[1], "data": json.loads(row[2])} for row in connection.execute(
                "SELECT id,kind,payload FROM job_events WHERE job_id=? AND id>? ORDER BY id LIMIT 100", (ident, after))]

    def cancel(self, ident: str):
        self.get(ident)
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute("UPDATE archive_requests SET cancel_requested=1 WHERE job_id=? AND status IN ('queued','running')",(ident,))
            if connection.execute('SELECT status FROM jobs WHERE id=?',(ident,)).fetchone()[0] == 'queued':
                connection.execute("UPDATE jobs SET status='cancelled',phase='Abgebrochen',cancel_requested=1,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",(ident,))
                connection.execute("INSERT INTO job_events(job_id,kind,payload) VALUES (?,'status',?)",
                                   (ident,json.dumps({'status':'cancelled','phase':'Abgebrochen'})))
                return
            connection.execute("UPDATE jobs SET cancel_requested=1 WHERE id=? AND status NOT IN (?,?,?,?)", (ident, *TERMINAL))


class JobService:
    def __init__(self, storage: Storage, *, test_no_admin: bool = False):
        self.storage = storage
        self.store = JobStore(storage)
        self.process = None
        self.stop_event = None
        self.download_tickets = {}
        self.ticket_lock = threading.Lock()
        self.test_no_admin = test_no_admin
        self.limits = ProcessingSettings(storage)

    def start(self):
        from forensic_app.worker import worker_main
        self.store.recover()
        context = multiprocessing.get_context("spawn")
        self.stop_event = context.Event()
        self.process = context.Process(target=worker_main, args=(str(self.storage.root), self.stop_event), daemon=True)
        self.process.start()

    def stop(self):
        if self.process:
            self.stop_event.set()
            self.process.join(timeout=6)
            if self.process.is_alive():
                self.process.terminate()
                self.process.join(timeout=3)

    def available(self):
        return self.process is not None and self.process.is_alive()

    def catalog(self,workspace='forensics'):
        state = ConfigurationTransfer(self.storage).current()
        modes = state['modes'] if workspace=='forensics' else MalwareModes(self.storage).list()
        result = []
        for mode in modes:
            try:
                compile_plan(mode, state["tools"]) if workspace=='forensics' else compile_static(mode)
                if sum((item['evidence_format'],item["effort"]) == (mode['evidence_format'],mode["effort"]) for item in modes) != 1:
                    raise ValueError("Aufwandsstufe ist mehrfach belegt.")
                reason = ""
            except (ValueError, OSError) as exc:
                reason = str(exc)
            result.append({"id": mode["id"], "ready": not reason, "reason": reason})
        limits = self.limits.get()
        return {"worker": self.available(), "administrator": is_admin(), "test_no_admin": self.test_no_admin,
                "modes": result, "max_upload_bytes": limits["max_upload_bytes"], "limits": limits}

    def begin(self, mode_id: str, filename: str, *, local_input: dict | None = None, allow_high_compression: bool = False, create_zip: bool = True, workspace='forensics'):
        if not self.available():
            raise HTTPException(503, "Ausführungsprozess ist nicht verfügbar. Server neu starten.")
        if not is_admin() and not self.test_no_admin:
            raise HTTPException(403, "Administratorrechte fehlen. App neu starten und Windows-UAC bestätigen.")
        state = ConfigurationTransfer(self.storage).current()
        modes = state['modes'] if workspace=='forensics' else MalwareModes(self.storage).list()
        mode = next((mode for mode in modes if mode["id"] == mode_id), None)
        if mode is None:
            raise HTTPException(404, "Modus nicht gefunden.")
        if sum((item['evidence_format'],item["effort"]) == (mode['evidence_format'],mode["effort"]) for item in modes) != 1:
            raise HTTPException(409, "Aufwandsstufe ist mehrfach belegt.")
        try:
            if workspace=='malware':
                validate_name(filename,mode['evidence_format'])
                plan = compile_static(mode,capture=True)
            else:
                plan = compile_plan(mode, state["tools"], capture=True)
            destination = Workspaces(self.storage).get()['path']
            ensure_space(Path(destination))
        except (ValueError, OSError) as exc:
            raise HTTPException(422, str(exc)) from exc
        plan["data_root"] = destination
        plan['workspace'] = workspace
        plan["create_zip"] = create_zip
        plan["filename"] = Path(filename.replace("\\", "/")).name[:240]
        plan["source_kind"] = "local" if local_input else "upload"
        plan["allow_high_compression"] = allow_high_compression
        plan["test_no_admin"] = self.test_no_admin
        plan["limits"] = state["limits"]
        if workspace=='malware':
            plan['limits'] = {**state['limits'],'max_upload_bytes':min(state['limits']['max_upload_bytes'],MAX_SAMPLE_BYTES)}
        if local_input:
            plan["local_input"] = local_input
        ident = str(uuid4())
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            accepting(connection)
            active = connection.execute("SELECT count(*) FROM jobs WHERE status NOT IN (?,?,?,?)", TERMINAL).fetchone()[0]
            if connection.execute('SELECT active FROM cleanup_state WHERE id=1').fetchone()[0]:
                raise HTTPException(409,'Eine Bereinigung läuft. Neue Aufträge danach starten.')
            if active >= 4:
                raise HTTPException(409, "Maximal vier offene Aufbereitungen. Erst laufende Aufträge abschließen.")
            connection.execute("INSERT INTO jobs(id,status,phase,config_json) VALUES (?,'uploading','Upload',?)",
                               (ident, json.dumps(plan, ensure_ascii=False)))
        return ident

    def local(self, value: LocalJob):
        try:
            path = Path(validate_local_path(value.path)).resolve(strict=True)
            validate_local_path(str(path))
            if not path.is_file() or (value.workspace=='forensics' and path.suffix.casefold() != ".zip"):
                raise ValueError("Bitte eine vorhandene ZIP-Datei auf dem Server auswählen.")
            with locked_input(path) as source:
                identity = input_identity(source)
                if not identity["size"]:
                    raise ValueError("Lokale ZIP-Datei ist leer.")
                if value.workspace=='malware' and identity['size']>MAX_SAMPLE_BYTES:
                    raise ValueError('Malware-Erstversion: maximal 256 MiB pro Einzeldatei.')
            ident = self.begin(value.mode_id, path.name, local_input={"path": str(path), **identity},
                               allow_high_compression=value.allow_high_compression,create_zip=value.create_zip,workspace=value.workspace)
            self.store.update(ident, status="queued", phase="Lokale ZIP wartet", input_size=identity["size"])
            return {"id": ident}
        except (ValueError, OSError) as exc:
            raise HTTPException(422, str(exc)) from exc


def jobs_router(service: JobService, authorize):
    router = APIRouter(prefix="/api/jobs", dependencies=[Depends(authorize)])
    explorer = ResultExplorer(service.storage, service.store)

    @router.get("/{ident}/explorer")
    def explorer_available(ident: str, request: Request):
        return explorer.availability(ident, request.client.host if request.client else None)

    @router.post("/{ident}/explorer")
    def show_in_explorer(ident: str, request: Request):
        return explorer.open(ident, request.client.host if request.client else None)

    @router.get("/catalog")
    def catalog(workspace:Literal['forensics','malware']='forensics'):
        return service.catalog(workspace)

    @router.get("")
    def list_jobs(q: str = Query(default='',max_length=200),
                  status: Literal['uploading','validating','queued','running','succeeded','failed','cancelled','interrupted'] | None = None,
                  mode_id: str | None = Query(default=None,max_length=80), date_from: date | None = None,
                  date_to: date | None = None, limit: int = Query(default=50,ge=1,le=100), offset: int = Query(default=0,ge=0),workspace:Literal['forensics','malware']|None=None):
        return service.store.search(q=q,status=status,mode_id=mode_id,date_from=date_from,date_to=date_to,limit=limit,offset=offset,workspace=workspace)

    @router.post("/local")
    def local_job(value: LocalJob):
        return service.local(value)

    @router.post("/browse")
    def browse_local(value: BrowseRequest,workspace:Literal['forensics','malware']='forensics'):
        result = browse(value)
        suffixes = {'.zip'} if workspace=='forensics' else set.union(*EXTENSIONS.values())
        result["entries"] = [entry for entry in result["entries"] if entry["kind"] == "directory" or Path(entry['name']).suffix.casefold() in suffixes]
        return result

    @router.post("")
    async def upload(request: Request, mode_id: str, filename: str = "Evidence.zip", allow_high_compression: bool = False, create_zip: bool = True,workspace:Literal['forensics','malware']='forensics'):
        if workspace=='forensics' and not filename.lower().endswith(".zip"):
            raise HTTPException(422, "Nur ZIP (KAPE-Target) wird unterstützt.")
        if request.headers.get("content-type", "").split(";")[0] != ('application/zip' if workspace=='forensics' else 'application/octet-stream'):
            raise HTTPException(415, "ZIP als application/zip hochladen.")
        declared = request.headers.get("content-length")
        max_upload = service.limits.get()["max_upload_bytes"]
        if workspace=='malware':
            max_upload = min(max_upload,MAX_SAMPLE_BYTES)
        if declared and (not declared.isdecimal() or int(declared) > max_upload):
            raise HTTPException(413, f"Uploadlimit überschritten: maximal {max_upload:,} Bytes. Unter Einstellungen → Verarbeitung änderbar.")
        ident = await run_in_threadpool(service.begin, mode_id, filename, allow_high_compression=allow_high_compression,create_zip=create_zip,workspace=workspace)
        with closing(sqlite3.connect(service.storage.database)) as connection:
            plan = json.loads(connection.execute("SELECT config_json FROM jobs WHERE id=?", (ident,)).fetchone()[0])
        max_upload = plan["limits"]["max_upload_bytes"]
        folder = job_paths(service.storage,plan,ident)[0] / "evidence" / ident
        size, checksum, sha1 = 0, hashlib.sha256(), hashlib.sha1()
        try:
            folder.mkdir()
            with (folder / "upload.part").open("xb") as output:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > max_upload:
                        raise ValueError(f"Uploadlimit überschritten: {size:,} Bytes empfangen, maximal {max_upload:,} Bytes.")
                    if await run_in_threadpool(lambda: service.store.get(ident)["cancel_requested"]):
                        raise ValueError("Upload abgebrochen.")
                    await run_in_threadpool(ensure_space, folder, len(chunk))
                    await run_in_threadpool(output.write, chunk)
                    checksum.update(chunk)
                    sha1.update(chunk)
            if size == 0 or declared and int(declared) != size:
                raise ValueError("ZIP-Upload ist leer oder unvollständig.")
            (folder / "upload.part").replace(folder / ('Evidence.zip' if workspace=='forensics' else 'Evidence.bin'))
            await run_in_threadpool(service.store.update, ident, status="queued", phase="Warteschlange",
                                    input_size=size, input_sha256=checksum.hexdigest(),input_sha1=sha1.hexdigest())
        except BaseException as exc:
            await run_in_threadpool(service.store.update, ident, input_size=size)
            await run_in_threadpool(service.store.fail, ident, exc)
            (folder / "upload.part").unlink(missing_ok=True)
            if isinstance(exc, (ValueError, OSError)):
                raise HTTPException(422, {"message": str(exc), "job_id": ident,
                                          "error_detail": service.store.get(ident)["error_detail"]}) from exc
            raise
        return {"id": ident}

    @router.get("/{ident}")
    def status(ident: str):
        return service.store.get(ident)

    @router.get("/{ident}/diagnostics")
    def diagnostics(ident: str):
        state = service.store.get(ident)
        return PlainTextResponse(json.dumps(state, ensure_ascii=False, indent=2), headers={
            "Content-Disposition": f'attachment; filename="Diagnose-{ident}.txt"'})

    @router.get("/{ident}/log")
    def job_log(ident: str):
        state = service.store.get(ident)
        path = service.store.paths(ident)[1] / "command.log"
        if path.is_file():
            return FileResponse(path, media_type="text/plain", filename=f"KAPE-{ident}.log")
        return PlainTextResponse(state["log_tail"] or "Keine Toolausgabe; siehe Fehlerdetails.")

    @router.post('/{ident}/archive')
    def archive_result(ident: str):
        from forensic_app.artifacts import ArchiveQueue
        if not service.available():
            raise HTTPException(503,'Worker ist nicht verfügbar.')
        return ArchiveQueue(service.store).request(ident)

    @router.get('/{ident}/report')
    def report(ident: str, format: Literal['html','json'] = 'html'):
        root = service.store.paths(ident)[0]
        path = root/'results'/ident/('Abschlussbericht.'+format)
        from forensic_app.workspaces import no_links
        try:
            no_links(path)
        except (ValueError,OSError) as exc:
            raise HTTPException(404,'Abschlussbericht fehlt oder ist nicht sicher zugänglich.') from exc
        if format == 'html':
            from fastapi.responses import Response

            from forensic_app.artifacts import render_report
            source = path.with_suffix('.json')
            no_links(source)
            if source.is_file():
                return Response(render_report(json.loads(source.read_text(encoding='utf-8'))),media_type='text/html',
                                headers={'Content-Disposition':'attachment; filename="Abschlussbericht-'+ident+'.html"',
                                         'Content-Security-Policy':"sandbox; default-src 'none'; style-src 'unsafe-inline'"})
        return FileResponse(path,media_type='text/html' if format == 'html' else 'application/json',
                            filename='Abschlussbericht-'+ident+'.'+format,
                            headers={'Content-Security-Policy':"sandbox; default-src 'none'; style-src 'unsafe-inline'"})

    @router.post("/{ident}/cancel")
    def cancel(ident: str):
        service.store.cancel(ident)
        return {"cancel_requested": True}

    @router.get("/{ident}/events")
    async def events(ident: str, request: Request, after: int = 0):
        await run_in_threadpool(service.store.get, ident)

        async def generate():
            cursor = max(0, after)
            while not await request.is_disconnected():
                batch = await run_in_threadpool(service.store.events, ident, cursor)
                for event in batch:
                    cursor = event["id"]
                    yield f"id: {cursor}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
                status = await run_in_threadpool(service.store.get, ident)
                if status["status"] in TERMINAL and status["archive_status"] not in ("queued","running") and not batch:
                    return
                if not batch:
                    yield ": heartbeat\n\n"
                    await asyncio.sleep(0.75)
        return StreamingResponse(generate(), media_type="text/event-stream")

    @router.get("/{ident}/download")
    def download(ident: str):
        status = service.store.get(ident)
        if status["status"] != "succeeded":
            raise HTTPException(409, "Ergebnis ist noch nicht erfolgreich abgeschlossen.")
        path = service.store.paths(ident)[2]
        if not path.is_file():
            raise HTTPException(404, "Ergebnisdatei fehlt.")
        return FileResponse(path, media_type="application/zip", filename=f"PostMortem-{ident}.zip")

    @router.post("/{ident}/download-ticket")
    def download_ticket(ident: str):
        download(ident)  # Same authorization, completion and existence checks.
        with service.ticket_lock:
            now = time.monotonic()
            service.download_tickets = {key: value for key, value in service.download_tickets.items() if value[1] > now}
            if len(service.download_tickets) >= 64:
                raise HTTPException(429, "Zu viele offene Downloads. Bitte kurz warten.")
            ticket = secrets.token_urlsafe(32)
            service.download_tickets[ticket] = (ident, now+120)
        return {"url": "/api/results/"+ticket}

    return router


def results_router(service: JobService):
    router = APIRouter(prefix="/api/results")

    @router.get("/{ticket}")
    def result(ticket: str):
        # One-use capability minted only by the bearer-authenticated endpoint above.
        # Native browser download streams large ZIPs without building a JS Blob in memory.
        with service.ticket_lock:
            entry = service.download_tickets.pop(ticket, None)
        if entry is None or entry[1] <= time.monotonic():
            raise HTTPException(410, "Downloadlink abgelaufen. Download Evidences erneut anklicken.")
        ident = entry[0]
        if not service.store.get(ident)["result_available"]:
            raise HTTPException(409, "Ergebnis nicht verfügbar.")
        return FileResponse(service.store.paths(ident)[2],
                            media_type="application/zip", filename=f"PostMortem-{ident}.zip")
    return router
