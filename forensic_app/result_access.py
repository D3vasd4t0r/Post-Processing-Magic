"""Authorize and resolve recorded result files while excluding cleanup admission."""

import json
import sqlite3
import stat
from contextlib import closing, contextmanager
from pathlib import Path, PureWindowsPath

from fastapi import HTTPException

from forensic_app.app_errors import AppValueError, ErrorText, error_detail
from forensic_app.workspaces import job_paths, no_links


@contextmanager
def result_file(store, ident, relative=None, extensions=(".csv", ".xlsx")):
    with closing(sqlite3.connect(store.storage.database)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT active FROM cleanup_state WHERE id=1").fetchone()[0]:
            raise HTTPException(409, ErrorText('error.ebb4ee00e1c1'))
        if connection.execute("SELECT 1 FROM archive_requests WHERE job_id=? AND status IN ('queued','running')", (ident,)).fetchone():
            raise HTTPException(409, ErrorText('error.fd846e92ec09'))
        if store.get(ident)["status"] != "succeeded":
            raise HTTPException(409, ErrorText('error.6b46c79dde21'))
        try:
            plan = store.plan(ident)
            root, work, _ = job_paths(store.storage, plan, ident)
            manifest = root / "results" / ident / "Abschlussbericht.json"
            no_links(manifest)
            if not stat.S_ISREG(manifest.lstat().st_mode) or manifest.stat().st_nlink != 1:
                raise AppValueError('error.36a0f3d8cde5')
            with manifest.open("rb") as source:
                payload = source.read(16 * 1024**2 + 1)
            if len(payload) > 16 * 1024**2:
                raise AppValueError('error.074a110df8e9')
            files = [item["path"] for item in json.loads(payload).get("files", [])
                     if isinstance(item, dict) and isinstance(item.get("path"), str)
                     and item["path"].lower().endswith(extensions)]
            if relative is None:
                yield files, None
                return
            windows = PureWindowsPath(relative)
            if (windows.drive or windows.root or any(part in ("", ".", "..") for part in relative.replace("\\", "/").split("/"))
                    or any(char in relative for char in ":\x00")):
                raise AppValueError('error.ef55365dab25')
            if relative not in files:
                raise HTTPException(404, ErrorText('error.6d76089a8684'))
            output = work / Path(*PureWindowsPath(plan["mode"]["output_folder"]).parts)
            candidate = output / Path(*windows.parts)
            no_links(output)
            if not output.resolve().is_relative_to(work.resolve()):
                raise AppValueError('error.89045519c588')
            no_links(candidate)
            if not candidate.resolve().is_relative_to(output.resolve()):
                raise AppValueError('error.5c90ef7eb9d2')
            info = candidate.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise AppValueError('error.e6788b21f5f3')
            yield files, candidate
        except (ValueError, OSError, KeyError, TypeError) as exc:
            raise HTTPException(422, ErrorText('error.8609b7e8e421', p0=error_detail(exc))) from exc
