"""Versioned configuration exchange, with immutable preview tickets and atomic application."""

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from starlette.concurrency import run_in_threadpool

from forensic_app import __version__
from forensic_app.app_errors import AppValueError, ErrorText, request_locale
from forensic_app.malware_modes import MalwareMode, MalwareModes
from forensic_app.modes import EFFORTS, ModeDraft
from forensic_app.processing_settings import ProcessingLimits, read_limits, write_limits
from forensic_app.storage import Storage
from forensic_app.tool_settings import ToolLocation, inspect_path

MAX_IMPORT_BYTES = 4 * 1024 * 1024
TICKET_TTL = 600


class ExportTool(ToolLocation):
    id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")


class ExportMode(ModeDraft):
    id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")


class ExportMalwareMode(MalwareMode):
    id: str = Field(min_length=1,max_length=80,pattern=r'^[A-Za-z0-9_-]+$')


class ConfigurationFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["post-processing-magic.configuration"]
    schema_version: Literal[1, 2, 3]
    app_version: str = Field(min_length=1, max_length=40)
    exported_at: datetime
    tools: list[ExportTool] = Field(max_length=1000)
    modes: list[ExportMode] = Field(max_length=100)
    malware_modes: list[ExportMalwareMode] = Field(default_factory=list,max_length=100)
    limits: ProcessingLimits | None = None

    @model_validator(mode='after')
    def complete_unified_document(self):
        if self.schema_version==3 and 'malware_modes' not in self.model_fields_set:
            raise AppValueError('error.ec9b73ddee1a')
        return self


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    strategy: Literal["merge", "replace"] = "merge"
    document: ConfigurationFile


class ApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ticket: str = Field(min_length=1, max_length=100)
    confirm_replace: bool = False


def dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def snapshot(connection) -> dict:
    tools = [{"id": row[0], "name": row[1], "path": row[2]} for row in connection.execute(
        "SELECT id, name, path FROM tool_locations ORDER BY id"
    )]
    modes = [{"id": row[0], **json.loads(row[1])} for row in connection.execute(
        "SELECT id, body_json FROM mode_drafts ORDER BY id"
    )]
    malware = []
    if connection.execute("SELECT 1 FROM sqlite_master WHERE name='malware_modes'").fetchone():
        malware = [{'id':r[0],**json.loads(r[1])} for r in connection.execute('SELECT id,body_json FROM malware_modes ORDER BY id')]
    return {"tools": tools, "modes": modes, 'malware_modes':malware, "limits": read_limits(connection)}


def document(state: dict) -> dict:
    state = dict(state)
    state.setdefault('malware_modes',[])
    return {"format": "post-processing-magic.configuration", "schema_version": 3,
            "app_version": __version__, "exported_at": datetime.now(UTC).isoformat(), **state}


def fingerprint(state: dict) -> str:
    return hashlib.sha256(dump(state).encode("utf-8")).hexdigest()


def validate_state(state: dict) -> list[str]:
    errors = []
    for kind in ("tools", "modes", "malware_modes"):
        ids, names = set(), set()
        for item in state.get(kind,[]):
            if item["id"] in ids:
                errors.append(ErrorText('config.duplicate_id', kind=kind, ident=item['id']))
            if item["name"].casefold() in names:
                errors.append(ErrorText('config.duplicate_name', kind=kind, name=item['name']))
            ids.add(item["id"])
            names.add(item["name"].casefold())
    tools = {tool["id"] for tool in state["tools"]}
    slots = set()
    for mode in [*state['modes'],*state.get('malware_modes',[])]:
        effort = mode["effort"]
        if effort not in EFFORTS:
            errors.append(ErrorText('config.unknown_effort', name=mode['name'], effort=effort))
        slot = (mode["evidence_format"], effort)
        if slot in slots:
            errors.append(ErrorText('config.slot_conflict', format=mode['evidence_format'], effort=effort))
        slots.add(slot)
        for step in mode.get("steps", []):
            if step.get("tool_id") is not None and step["tool_id"] not in tools:
                errors.append(ErrorText('config.missing_tool', name=mode['name'], step=step['name']))
    return list(dict.fromkeys(errors))


def changes(before: list[dict], after: list[dict]) -> dict:
    old, new = {item["id"]: item for item in before}, {item["id"]: item for item in after}
    return {
        "added": [new[key]["name"] for key in new.keys() - old.keys()],
        "updated": [new[key]["name"] for key in new.keys() & old.keys() if dump(new[key]) != dump(old[key])],
        "removed": [old[key]["name"] for key in old.keys() - new.keys()],
        "unchanged": sum(dump(new[key]) == dump(old[key]) for key in new.keys() & old.keys()),
    }


class ConfigurationTransfer:
    def __init__(self, storage: Storage):
        self.storage = storage
        self.lock = threading.Lock()
        self.tickets = {}

    def initialize(self):
        MalwareModes(self.storage).initialize()
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS configuration_import_events (
                    id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, strategy TEXT NOT NULL,
                    before_json TEXT NOT NULL, after_json TEXT NOT NULL, backup_file TEXT NOT NULL
                )
            """)

    def current(self) -> dict:
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("BEGIN")
            return snapshot(connection)

    def export(self) -> dict:
        return document(self.current())

    def preview(self, request: PreviewRequest) -> dict:
        before = self.current()
        incoming = {"tools": [tool.model_dump() for tool in request.document.tools],
                    "modes": [mode.model_dump() for mode in request.document.modes],
                    "malware_modes":[mode.model_dump() for mode in request.document.malware_modes]}
        if request.document.schema_version<3:
            incoming["malware_modes"] = before["malware_modes"]
        errors = validate_state(incoming)
        after = {}
        for kind in ("tools", "modes", "malware_modes"):
            combined = {item["id"]: item for item in before[kind]} if request.strategy == "merge" else {}
            combined.update({item["id"]: item for item in incoming[kind]})
            after[kind] = sorted(combined.values(), key=lambda item: item["id"])
        after["limits"] = request.document.limits.model_dump() if request.document.limits else before["limits"]
        errors.extend(validate_state(after))
        errors = list(dict.fromkeys(errors))
        summary = {kind: changes(before[kind], after[kind]) for kind in ("tools", "modes", "malware_modes")}
        warnings = []
        for tool in after["tools"]:
            status = inspect_path(tool["path"])
            if status["kind"] in ("missing", "unavailable"):
                warnings.append(ErrorText('config.missing_path', name=tool['name'], status=status['message']))
        for mode in after["modes"]:
            if not mode.get("steps") or any((not step.get("script") if step.get("type") == "powershell" else step.get("tool_id") is None)
                                          for step in mode.get("steps", [])):
                warnings.append(ErrorText('config.incomplete', name=mode['name']))
        result = {"valid": not errors, "errors": errors, "warnings": warnings,
                  "strategy": request.strategy, "changes": summary,
                  "total_tools": len(after["tools"]), "total_modes": len(after["modes"]),"total_malware_modes":len(after["malware_modes"])}
        result["limits"] = {"before": before["limits"], "after": after["limits"], "changed": before["limits"] != after["limits"]}
        if not errors:
            with self.lock:
                now = time.monotonic()
                self.tickets = {key: value for key, value in self.tickets.items() if value["expires"] > now}
                if len(self.tickets) >= 32:
                    raise HTTPException(429, ErrorText('error.9834eab14186'))
                ticket = secrets.token_urlsafe(24)
                self.tickets[ticket] = {"expires": now + TICKET_TTL, "before": fingerprint(before),
                                        "after": after, "strategy": request.strategy, "summary": summary}
                result["ticket"] = ticket
        return result

    def apply(self, request: ApplyRequest) -> dict:
        with self.lock:
            preview = self.tickets.get(request.ticket)
            if preview is None or preview["expires"] <= time.monotonic():
                self.tickets.pop(request.ticket, None)
                raise HTTPException(409, ErrorText('error.658836555ad3'))
            if preview["strategy"] == "replace" and not request.confirm_replace:
                raise HTTPException(422, ErrorText('error.e82b2ef2795d'))
            with closing(sqlite3.connect(self.storage.database)) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                before = snapshot(connection)
                if fingerprint(before) != preview["before"]:
                    del self.tickets[request.ticket]
                    raise HTTPException(409, ErrorText('error.89bad8961c91'))
                backup_dir = self.storage.root / "config" / "backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_path = backup_dir / f"before-import-{uuid4()}.json"
                # Backup only configuration, with no access tokens, certificates or evidence.
                with backup_path.open("x", encoding="utf-8") as output:
                    json.dump(document(before), output, ensure_ascii=False, indent=2)
                after = preview["after"]
                write_limits(connection, after["limits"])
                connection.execute("DELETE FROM malware_modes")
                connection.executemany("INSERT INTO malware_modes(id,name,body_json) VALUES (?,?,?)",
                    [(item["id"],item["name"],dump({k:v for k,v in item.items() if k!="id"})) for item in after["malware_modes"]])
                connection.execute("DELETE FROM mode_drafts")
                connection.execute("DELETE FROM tool_locations")
                connection.executemany("INSERT INTO tool_locations(id,name,path) VALUES (?,?,?)",
                                       [(item["id"], item["name"], item["path"]) for item in after["tools"]])
                connection.executemany("INSERT INTO mode_drafts(id,name,body_json) VALUES (?,?,?)",
                                       [(item["id"], item["name"], dump({key: value for key, value in item.items() if key != "id"}))
                                        for item in after["modes"]])
                connection.execute(
                    "INSERT INTO configuration_import_events "
                    "(occurred_at,strategy,before_json,after_json,backup_file) "
                    "VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'),?,?,?,?)",
                    (preview["strategy"], dump(before), dump(after), backup_path.name),
                )
            del self.tickets[request.ticket]
            return {"imported": True, "backup_file": str(backup_path), "changes": preview["summary"],
                    "total_tools": len(after["tools"]), "total_modes": len(after["modes"]),"total_malware_modes":len(after["malware_modes"])}


async def read_payload(request: Request, model):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_IMPORT_BYTES:
            raise HTTPException(413, ErrorText('error.63138b3742eb'))
    try:
        return model.model_validate_json(body)
    except ValidationError as exc:
        errors = [".".join(str(part) for part in error["loc"])+": "+
                  (error['ctx']['error'].text.localized(request_locale.get())
                   if isinstance(error.get('ctx',{}).get('error'),AppValueError) else error['msg'])
                  for error in exc.errors(include_input=False)[:20]]
        raise HTTPException(422, ErrorText('error.18f52c0145c2', p0='; '.join(errors))) from exc


def configuration_router(service: ConfigurationTransfer, authorize) -> APIRouter:
    router = APIRouter(prefix="/api/settings/configuration", dependencies=[Depends(authorize)])

    @router.get("/export")
    def export_configuration():
        return JSONResponse(service.export(), headers={
            "Content-Disposition": 'attachment; filename="PostProcessingMagic-config.json"'
        })

    @router.post("/preview")
    async def preview_import(request: Request):
        payload = await read_payload(request, PreviewRequest)
        return await run_in_threadpool(service.preview, payload)

    @router.post("/apply")
    async def apply_import(request: Request):
        payload = await read_payload(request, ApplyRequest)
        try:
            return await run_in_threadpool(service.apply, payload)
        except OSError as exc:
            raise HTTPException(500, ErrorText('error.ae5f493ed498')) from exc
        except sqlite3.Error as exc:
            raise HTTPException(500, ErrorText('error.032c3f018b44')) from exc

    return router
