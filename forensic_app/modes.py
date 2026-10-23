"""Persisted mode drafts and a user-requested KAPE reference; deliberately no runner."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path, PureWindowsPath
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from forensic_app.storage import Storage

EFFORTS = ("schnell", "Medium", "langsam")
DEFAULT_COMMAND_TIMEOUT_SECONDS = 24 * 60 * 60
MAX_COMMAND_TIMEOUT_SECONDS = 7 * 24 * 60 * 60


def canonical_effort(value: str) -> str:
    return next((effort for effort in EFFORTS if effort.casefold() == value.casefold()), value)


class SlotConflict(ValueError):
    pass


KAPE_MODULES = (
    "CCMRUAFinder_RecentlyUsedApps,Chainsaw,hayabusa_OfflineEventLogs,DHParser,"
    "ObsidianForensics_Hindsight,SRUMDump,NirSoft_BrowsingHistoryView,"
    "NirSoft_FullEventLogView_PowerShell-Operational,NirSoft_FullEventLogView_ScheduledTasks,"
    "NirSoft_FullEventLogView_Security,NirSoft_FullEventLogView_System,!EZParser,LogParser,"
    "LogParser_RDPUsageEvents,NTFSLogTracker,RegRipper,PowerShell_Move-KAPEConsoleHost_history,"
    "PowerShell_MFTECmd_J-MFTParsing,PowerShell_Get-DoSvc4n6,EvtxHussar,"
    "NirSoft_TurnedOnTimesView,OneDriveExplorer"
)
KAPE_COMMAND = (
    "kape.exe --msource .\\Targets\\C --mdest .\\PostMortem --module " + KAPE_MODULES + " --gui"
)


class CommandStep(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=80)
    name: str = Field(default="Tool-Aufruf", min_length=1, max_length=120)
    tool_id: str | None = Field(default=None, max_length=80)
    tool_hint: str = Field(default="", max_length=100)
    parameters: str = Field(default="", max_length=16000)
    type: Literal["tool", "powershell"] = "tool"
    script: str = Field(default="", max_length=8000)
    working_directory: str = Field(default=".", max_length=240)
    timeout_seconds: int = Field(default=DEFAULT_COMMAND_TIMEOUT_SECONDS, strict=True,
                                 ge=1, le=MAX_COMMAND_TIMEOUT_SECONDS)

    @field_validator("script")
    @classmethod
    def script_text(cls, value):
        if any(ord(char) < 32 and char not in "\n\r\t" for char in value) or "\x7f" in value:
            raise ValueError("Unzulässige Steuerzeichen im PowerShell-Block.")
        return value

    @field_validator("working_directory")
    @classmethod
    def relative_working_directory(cls, value):
        return "." if value == "." else ModeDraft.job_relative_folder(value)

    @model_validator(mode="after")
    def powershell_without_tool(self):
        if self.type == "powershell" and self.tool_id is not None:
            raise ValueError("PowerShell-Blöcke benötigen keine Toolreferenz.")
        return self

    @field_validator("id", "name", "tool_id", "tool_hint", "parameters")
    @classmethod
    def no_control_characters(cls, value):
        if value is not None and any(ord(char) < 32 and char not in "\t" for char in value):
            raise ValueError("Ein Befehlsblock darf keine Zeilenumbrüche oder Steuerzeichen enthalten.")
        return value


class ModeDraft(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=4000)
    evidence_format: Literal["ZIP", "E01", "VMDK"] = "ZIP"
    effort: str = Field(min_length=1, max_length=80)
    source_folder: str = Field(default="Targets\\C", min_length=1, max_length=240)
    extract_folder: str = Field(default="Targets", min_length=1, max_length=240)
    output_folder: str = Field(default="PostMortem", min_length=1, max_length=240)
    command_reference: str = Field(default="", max_length=16000)
    steps: list[CommandStep] = Field(default_factory=list, max_length=50)

    @field_validator("effort")
    @classmethod
    def normalize_effort(cls, value: str) -> str:
        return canonical_effort(value)

    @field_validator("name", "effort")
    @classmethod
    def plain_label(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Name und Aufwand dürfen keine Steuerzeichen enthalten.")
        return value

    @field_validator("description", "command_reference")
    @classmethod
    def readable_text(cls, value: str) -> str:
        if any(ord(char) < 32 and char not in "\n\r\t" for char in value):
            raise ValueError("Unzulässige Steuerzeichen im Text.")
        return value

    @field_validator("source_folder", "extract_folder", "output_folder")
    @classmethod
    def job_relative_folder(cls, value: str) -> str:
        path = PureWindowsPath(value)
        if path.drive or path.root or not path.parts or ".." in path.parts:
            raise ValueError("Nur relative Unterordner innerhalb der Aufbereitung verwenden.")
        for part in path.parts:
            if any(ord(char) < 32 or char in '<>:"|?*' for char in part):
                raise ValueError("Ungültiger Ordnername.")
            if part.endswith((".", " ")) or PureWindowsPath(part).is_reserved():
                raise ValueError("Dieser Ordnername ist unter Windows nicht verwendbar.")
        return str(path)

    @model_validator(mode="after")
    def separate_input_output(self):
        if self.evidence_format != "ZIP":
            raise ValueError("Version 1 unterstützt nur ZIP (KAPE-Target). E01 und VMDK sind in Planung.")
        source = PureWindowsPath(self.source_folder)
        output = PureWindowsPath(self.output_folder)
        extraction = PureWindowsPath(self.extract_folder)
        if (source.is_relative_to(output) or output.is_relative_to(source)
                or extraction.is_relative_to(output) or output.is_relative_to(extraction)):
            raise ValueError("Eingabe- und Ergebnisordner müssen getrennt sein.")
        if len({step.id for step in self.steps}) != len(self.steps):
            raise ValueError("Befehlsblöcke müssen unterschiedliche IDs haben.")
        return self


KAPE_TEMPLATE = ModeDraft(
    name="KAPE-Target / Medium / ohne Timeline",
    description=(
        "ZIP mit KAPE-Target in Targets\\C entpacken. KAPE mit der angegebenen Modulliste "
        "ausführen. Nach Ende und Ergebnisprüfung den Ordner PostMortem zippen und als "
        "Download bereitstellen. Keine zusätzlichen Timeline-Schritte."
    ),
    evidence_format="ZIP", effort="Medium", command_reference=KAPE_COMMAND,
    steps=[CommandStep(name="KAPE-Module ausführen", tool_hint="KAPE",
                       parameters=KAPE_COMMAND.removeprefix("kape.exe "))],
)


class ModeStore:
    def __init__(self, storage: Storage):
        self.storage = storage

    def initialize(self) -> None:
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS mode_drafts (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    body_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mode_configuration_events (
                    id INTEGER PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    mode_id TEXT NOT NULL,
                    before_json TEXT,
                    after_json TEXT
                );
                CREATE TABLE IF NOT EXISTS applied_templates (
                    key TEXT PRIMARY KEY
                );
            """)
            # A removed or edited template is never restored or overwritten on restart.
            connection.execute("BEGIN IMMEDIATE")
            # Materialize newly introduced defaults without changing workflow behavior.
            for ident, body in connection.execute("SELECT id,body_json FROM mode_drafts").fetchall():
                normalized = ModeDraft.model_validate_json(body).model_dump_json()
                if json.loads(normalized) != json.loads(body):
                    connection.execute("UPDATE mode_drafts SET body_json=? WHERE id=?", (normalized, ident))
                    self._audit(connection, "schema-upgrade", ident, body, normalized)
            if not connection.execute(
                "SELECT 1 FROM applied_templates WHERE key = 'kape-medium-v1'"
            ).fetchone():
                mode_id = str(uuid4())
                body = KAPE_TEMPLATE.model_dump_json()
                connection.execute(
                    "INSERT INTO mode_drafts(id, name, body_json) VALUES (?, ?, ?)",
                    (mode_id, KAPE_TEMPLATE.name, body),
                )
                self._audit(connection, "template", mode_id, None, body)
                connection.execute("INSERT INTO applied_templates VALUES ('kape-medium-v1')")

    @staticmethod
    def _audit(connection, action, mode_id, before, after):
        connection.execute(
            "INSERT INTO mode_configuration_events "
            "(occurred_at, action, mode_id, before_json, after_json) "
            "VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, ?, ?, ?)",
            (action, mode_id, before, after),
        )

    def list_modes(self) -> list[dict]:
        with closing(sqlite3.connect(self.storage.database)) as connection:
            modes = [{"id": row[0], **ModeDraft.model_validate_json(row[1]).model_dump(),
                      "status": "draft", "executable": False}
                     for row in connection.execute(
                         "SELECT id, body_json FROM mode_drafts ORDER BY name COLLATE NOCASE"
                     )]
        counts = {}
        for mode in modes:
            slot = (mode["evidence_format"], mode["effort"])
            counts[slot] = counts.get(slot, 0) + 1
        for mode in modes:
            mode["slot_conflict"] = counts[(mode["evidence_format"], mode["effort"])] > 1
        return modes

    def configuration(self) -> dict:
        # Presence checks are configuration diagnostics, not a claim that the runner exists.
        modes = self.list_modes()
        tools = {tool["id"]: tool for tool in self.storage.list_tools()}
        availability = []
        for effort in EFFORTS:
            entries = [mode for mode in modes if mode["evidence_format"] == "ZIP"
                       and mode["effort"] == effort]
            if not entries:
                state = "missing"
            elif len(entries) > 1:
                state = "conflict"
            else:
                steps = entries[0]["steps"]
                complete = bool(steps)
                for step in steps:
                    if step.get("type") == "powershell":
                        complete = complete and bool(step.get("script", "").strip())
                        continue
                    tool = tools.get(step["tool_id"])
                    try:
                        complete = complete and bool(tool) and Path(tool["path"]).is_file()
                    except OSError:
                        complete = False
                state = "configured" if complete else "incomplete"
            availability.append({"evidence_format": "ZIP", "effort": effort, "state": state,
                                 "mode_ids": [mode["id"] for mode in entries],
                                 "available_for_run": False})
        return {"modes": modes, "availability": availability,
                "workspace_pattern": str(self.storage.root / "work" / "{Aufbereitungs-ID}")}

    def save(self, mode_id: str, draft: ModeDraft, *, create: bool) -> dict:
        body = draft.model_dump_json()
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            old = connection.execute(
                "SELECT body_json FROM mode_drafts WHERE id = ?", (mode_id,)
            ).fetchone()
            if not create and old is None:
                raise KeyError(mode_id)
            previous = json.loads(old[0]) if old else None
            keep_own_slot = (previous is not None
                             and previous.get("evidence_format", "ZIP") == draft.evidence_format
                             and canonical_effort(previous["effort"]) == draft.effort)
            if draft.effort not in EFFORTS and not keep_own_slot:
                raise ValueError("Bitte schnell, Medium oder langsam als Aufwand wählen.")
            # BEGIN IMMEDIATE serializes the slot check and write, including concurrent requests.
            for existing_id, existing_body in connection.execute("SELECT id, body_json FROM mode_drafts"):
                if existing_id == mode_id:
                    continue
                existing = json.loads(existing_body)
                if (existing.get("evidence_format", "ZIP") == draft.evidence_format
                        and canonical_effort(existing["effort"]) == draft.effort
                        and not keep_own_slot):
                    raise SlotConflict(f"{draft.effort} ist für {draft.evidence_format} bereits belegt.")
            tool_ids = {row[0] for row in connection.execute("SELECT id FROM tool_locations")}
            for step in draft.steps:
                if step.tool_id is not None and step.tool_id not in tool_ids:
                    raise ValueError(f"Tool für Schritt '{step.name}' wurde nicht gefunden.")
            if create:
                connection.execute(
                    "INSERT INTO mode_drafts(id, name, body_json) VALUES (?, ?, ?)",
                    (mode_id, draft.name, body),
                )
            else:
                connection.execute(
                    "UPDATE mode_drafts SET name = ?, body_json = ? WHERE id = ?",
                    (draft.name, body, mode_id),
                )
            self._audit(connection, "create" if create else "update", mode_id,
                        old[0] if old else None, body)
        return {"id": mode_id, **draft.model_dump(), "status": "draft", "executable": False}

    def delete(self, mode_id: str) -> None:
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            old = connection.execute(
                "SELECT body_json FROM mode_drafts WHERE id = ?", (mode_id,)
            ).fetchone()
            if old is None:
                raise KeyError(mode_id)
            connection.execute("DELETE FROM mode_drafts WHERE id = ?", (mode_id,))
            self._audit(connection, "delete", mode_id, old[0], None)


def modes_router(store: ModeStore, authorize) -> APIRouter:
    router = APIRouter(prefix="/api/settings/modes", dependencies=[Depends(authorize)])

    @router.get("")
    def list_modes():
        return store.configuration()

    def save(mode_id, draft, create):
        try:
            return store.save(mode_id, draft, create=create)
        except KeyError as exc:
            raise HTTPException(404, "Modus nicht gefunden.") from exc
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "Dieser Modusname ist bereits vergeben.") from exc
        except SlotConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.post("", status_code=201)
    def create_mode(draft: ModeDraft):
        return save(str(uuid4()), draft, True)

    @router.put("/{mode_id}")
    def update_mode(mode_id: str, draft: ModeDraft):
        return save(mode_id, draft, False)

    @router.delete("/{mode_id}", status_code=204)
    def delete_mode(mode_id: str):
        try:
            store.delete(mode_id)
        except KeyError as exc:
            raise HTTPException(404, "Modus nicht gefunden.") from exc
        return Response(status_code=204)

    return router
