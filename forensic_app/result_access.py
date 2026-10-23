"""Authorize and resolve recorded result files while excluding cleanup admission."""
import json
import sqlite3
import stat
from contextlib import closing, contextmanager
from pathlib import Path, PureWindowsPath

from fastapi import HTTPException

from forensic_app.workspaces import job_paths, no_links


@contextmanager
def result_file(store, ident, relative=None, extensions=(".csv", ".xlsx")):
    with closing(sqlite3.connect(store.storage.database)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT active FROM cleanup_state WHERE id=1").fetchone()[0]:
            raise HTTPException(409, "Eine Bereinigung läuft. Danach erneut versuchen.")
        if connection.execute("SELECT 1 FROM archive_requests WHERE job_id=? AND status IN ('queued','running')", (ident,)).fetchone():
            raise HTTPException(409, "Archivierung läuft. Danach erneut versuchen.")
        if store.get(ident)["status"] != "succeeded":
            raise HTTPException(409, "Ergebnisansicht nur für erfolgreiche abgeschlossene Aufträge.")
        try:
            plan = store.plan(ident)
            root, work, _ = job_paths(store.storage, plan, ident)
            manifest = root / "results" / ident / "Abschlussbericht.json"
            no_links(manifest)
            if not stat.S_ISREG(manifest.lstat().st_mode) or manifest.stat().st_nlink != 1:
                raise ValueError("Ergebnisliste ist keine reguläre unverknüpfte Datei.")
            with manifest.open("rb") as source:
                payload = source.read(16 * 1024**2 + 1)
            if len(payload) > 16 * 1024**2:
                raise ValueError("Ergebnisdateiliste überschreitet 16 MiB.")
            files = [item["path"] for item in json.loads(payload).get("files", [])
                     if isinstance(item, dict) and isinstance(item.get("path"), str)
                     and item["path"].lower().endswith(extensions)]
            if relative is None:
                yield files, None
                return
            windows = PureWindowsPath(relative)
            if (windows.drive or windows.root or any(part in ("", ".", "..") for part in relative.replace("\\", "/").split("/"))
                    or any(char in relative for char in ":\x00")):
                raise ValueError("Ungültiger relativer Ergebnisdateipfad.")
            if relative not in files:
                raise HTTPException(404, "Datei fehlt in der gespeicherten Ergebnisliste dieses Auftrags.")
            output = work / Path(*PureWindowsPath(plan["mode"]["output_folder"]).parts)
            candidate = output / Path(*windows.parts)
            no_links(output)
            if not output.resolve().is_relative_to(work.resolve()):
                raise ValueError("Ergebnisordner liegt außerhalb des Auftrags.")
            no_links(candidate)
            if not candidate.resolve().is_relative_to(output.resolve()):
                raise ValueError("Datei liegt außerhalb des Ergebnisordners.")
            info = candidate.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Ergebnisdatei ist keine reguläre unverknüpfte Datei.")
            yield files, candidate
        except (ValueError, OSError, KeyError, TypeError) as exc:
            raise HTTPException(422, "Ergebnisansicht nicht verfügbar: " + str(exc)) from exc
