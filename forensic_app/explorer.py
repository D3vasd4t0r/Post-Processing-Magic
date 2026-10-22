"""Open only completed job output folders, from an authenticated local request."""

import ipaddress
import json
import sqlite3
import stat
from contextlib import closing
from pathlib import PureWindowsPath

from fastapi import HTTPException

from forensic_app.modes import ModeDraft
from forensic_app.windows_access import interactive_desktop, open_explorer
from forensic_app.workspaces import job_root


def local_client(host: str | None) -> bool:
    try:
        address = ipaddress.ip_address(host or "")
        return address.is_loopback or bool(getattr(address, "ipv4_mapped", None) and address.ipv4_mapped.is_loopback)
    except ValueError:
        return False


class ResultExplorer:
    def __init__(self, storage, store):
        self.storage = storage
        self.store = store

    def folder(self, ident):
        if self.store.get(ident)["status"] != "succeeded":
            raise HTTPException(409, "Der Ergebnisordner ist erst nach erfolgreicher Aufbereitung verfügbar.")
        with closing(sqlite3.connect(self.storage.database)) as connection:
            plan = json.loads(connection.execute("SELECT config_json FROM jobs WHERE id=?", (ident,)).fetchone()[0])
        try:
            relative = PureWindowsPath(ModeDraft.job_relative_folder(plan["mode"]["output_folder"]))
            root = (job_root(self.storage,plan) / "work").resolve(strict=True)
            current = root / ident
            for part in (None, *relative.parts):
                if part is not None:
                    current /= part
                info = current.lstat()
                if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError("Verknüpfungen und umgeleitete Ergebnisordner werden nicht geöffnet.")
                if not current.is_dir():
                    raise FileNotFoundError("Ergebnisordner fehlt.")
            resolved = current.resolve(strict=True)
            if not resolved.is_relative_to(root / ident):
                raise ValueError("Ergebnisordner liegt außerhalb des Auftrags.")
            return resolved
        except FileNotFoundError as exc:
            raise HTTPException(404, "Der Ergebnisordner ist nicht mehr vorhanden. Möglicherweise wurde er verschoben oder bereinigt.") from exc
        except (ValueError, KeyError) as exc:
            raise HTTPException(409, "Der gespeicherte Ergebnisordner kann nicht sicher geöffnet werden: "+str(exc)) from exc
        except OSError as exc:
            raise HTTPException(409, "Auf den Ergebnisordner kann nicht zugegriffen werden: "+str(exc)) from exc

    def checked_folder(self, ident, host):
        if not local_client(host):
            raise HTTPException(403, "Show in Explorer ist nur direkt auf dem Server verfügbar. Bitte den Ergebnisdownload verwenden.")
        folder = self.folder(ident)
        if not interactive_desktop():
            raise HTTPException(409, "Keine interaktive Windows-Sitzung mit Explorer verfügbar. Bitte direkt am Server anmelden oder den Ergebnisdownload verwenden.")
        return folder

    def availability(self, ident, host):
        try:
            self.checked_folder(ident, host)
            return {"local": True, "available": True, "reason": "Zeigt den markierten Ergebnisordner im übergeordneten Windows-Explorer-Verzeichnis, ohne Download."}
        except HTTPException as exc:
            return {"local": local_client(host), "available": False, "reason": exc.detail}

    def open(self, ident, host):
        folder = self.checked_folder(ident, host)
        try:
            open_explorer(folder)
        except OSError as exc:
            raise HTTPException(409, "Windows Explorer konnte nicht geöffnet werden: "+str(exc)) from exc
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("INSERT INTO job_events(job_id,kind,payload) VALUES (?,'explorer',?)",
                               (ident, json.dumps({"action": "open-result-folder", "path": str(folder), "actor": "authenticated-local"})))
        return {"requested": True, "path": str(folder), "message": "Windows Explorer zeigt den übergeordneten Ordner mit markiertem Ergebnisordner. Prüfe auch ein bereits offenes Explorer-Fenster."}
