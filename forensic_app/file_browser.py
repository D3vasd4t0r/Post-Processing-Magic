"""Authenticated metadata browser for server-local tool selection; no file reads or execution."""

import os
from pathlib import Path

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from forensic_app.local_paths import validate_local_path

MAX_SCAN = 10_000
MAX_ENTRIES = 500


class BrowseRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str | None = Field(default=None, max_length=4096)
    query: str = Field(default="", max_length=100)

    @field_validator("path")
    @classmethod
    def local_path(cls, value):
        return validate_local_path(value) if value else None


def roots() -> list[str]:
    if os.name == "nt":
        return sorted(os.listdrives())
    return [str(Path.home().anchor)]


def browse(request: BrowseRequest) -> dict:
    try:
        path = Path(request.path) if request.path else Path.home()
        path = path.resolve(strict=True)
        validate_local_path(str(path))
        selected = str(path) if path.is_file() else None
        if selected:
            path = path.parent
        if not path.is_dir():
            raise HTTPException(400, "Dieser Pfad ist kein Ordner und keine reguläre Datei.")
        entries = []
        scanned = 0
        limited = False
        query = request.query.casefold()
        with os.scandir(path) as iterator:
            for entry in iterator:
                scanned += 1
                if scanned > MAX_SCAN:
                    limited = True
                    break
                if query and query not in entry.name.casefold():
                    continue
                try:
                    item = Path(entry.path)
                    # Never follow links while enumerating. The explicit address field resolves
                    # paths and revalidates their destination before listing it.
                    if entry.is_symlink() or item.is_junction():
                        continue
                    kind = "directory" if entry.is_dir(follow_symlinks=False) else "file"
                    if kind == "file" and not entry.is_file(follow_symlinks=False):
                        continue
                    entries.append({"name": entry.name, "path": str(item), "kind": kind})
                except OSError:
                    continue
        entries.sort(key=lambda item: (item["kind"] != "directory", item["name"].casefold()))
        limited = limited or len(entries) > MAX_ENTRIES
        return {
            "path": str(path),
            "parent": str(path.parent) if path.parent != path else None,
            "roots": roots(),
            "entries": entries[:MAX_ENTRIES],
            "selected_file": selected,
            "limited": limited,
        }
    except FileNotFoundError as exc:
        raise HTTPException(404, "Der Pfad wurde auf dem Server nicht gefunden.") from exc
    except PermissionError as exc:
        raise HTTPException(403, "Keine Berechtigung für diesen Ordner.") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(400, "Der Pfad kann auf dem Server nicht geöffnet werden.") from exc
