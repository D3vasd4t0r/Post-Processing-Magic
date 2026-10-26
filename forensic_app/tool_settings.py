"""Configuration only. Saving or checking a path never executes a tool."""

import sqlite3
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from forensic_app.app_errors import AppValueError, ErrorText, error_detail
from forensic_app.file_browser import BrowseRequest, browse
from forensic_app.local_paths import validate_local_path
from forensic_app.storage import Storage


class ToolLocation(BaseModel):
    """Validate a display name and absolute local server path without probing or executing it."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    path: str = Field(min_length=1, max_length=4096)

    @field_validator("name", "path")
    @classmethod
    def no_control_characters(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise AppValueError('error.92ba731cf2d1')
        return value

    @field_validator("path")
    @classmethod
    def absolute_local_path(cls, value: str) -> str:
        return validate_local_path(value)


def inspect_path(value: str) -> dict:
    """Classify filesystem presence as file, directory, missing or inaccessible.

    This metadata probe does not verify tool format, version or execution readiness.
    """
    try:
        path = Path(value)
        if path.is_file():
            return {"kind": "file", "message": "Programmdatei gefunden"}
        if path.is_dir():
            return {"kind": "directory", "message": "Verzeichnis gefunden"}
        return {"kind": "missing", "message": "Pfad auf dem Server nicht gefunden"}
    except OSError:
        return {"kind": "unavailable", "message": "Pfad ist nicht zugänglich"}


def settings_router(storage: Storage, authorize) -> APIRouter:
    """Build authenticated tool CRUD, path-check and server filesystem-picker endpoints.

    Saving or browsing a path does not execute a program. Storage enforces references
    and audits writes; route handlers translate expected storage failures.
    """
    router = APIRouter(prefix="/api/settings/tools", dependencies=[Depends(authorize)])

    @router.get("")
    def list_tools():
        return {"tools": [dict(tool, used_by=storage.tool_usage(tool["id"]), **inspect_path(tool["path"]))
                          for tool in storage.list_tools()]}

    @router.post("/check")
    def check_tool(tool: ToolLocation):
        return inspect_path(tool.path)

    @router.post("/browse")
    def browse_tools(request: BrowseRequest):
        return browse(request)

    def save(tool_id: str, tool: ToolLocation, *, create: bool) -> dict:
        try:
            storage.save_tool(tool_id, tool.name, tool.path, create=create)
        except KeyError as exc:
            raise HTTPException(404, ErrorText('error.e5eda5fc7128')) from exc
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, ErrorText('error.6372f02edf1b')) from exc
        return {"id": tool_id, **tool.model_dump(), **inspect_path(tool.path)}

    @router.post("", status_code=201)
    def create_tool(tool: ToolLocation):
        return save(str(uuid4()), tool, create=True)

    @router.put("/{tool_id}")
    def update_tool(tool_id: str, tool: ToolLocation):
        return save(tool_id, tool, create=False)

    @router.delete("/{tool_id}", status_code=204)
    def delete_tool(tool_id: str):
        try:
            storage.delete_tool(tool_id)
        except KeyError as exc:
            raise HTTPException(404, ErrorText('error.e5eda5fc7128')) from exc
        except ValueError as exc:
            raise HTTPException(409, error_detail(exc)) from exc
        return Response(status_code=204)

    return router
