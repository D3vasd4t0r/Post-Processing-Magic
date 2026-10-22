"""Bounded, on-demand metadata scan; never reads evidence file contents."""

import os
import shutil
import stat
import threading
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException

from forensic_app.workspaces import all_roots, registered_root

MAX_ENTRIES = 500_000
MAX_SECONDS = 10
AREAS = (("evidence", "Eingänge"), ("work", "Arbeitsordner"), ("results", "Ergebnisarchive"))


class StorageOverview:
    def __init__(self, storage):
        self.storage = storage
        self.lock = threading.Lock()
        self.last_scan = None

    def get(self):
        try:
            usage = shutil.disk_usage(self.storage.root)
            volume = {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free}
        except OSError as exc:
            raise HTTPException(409, "Freier Speicherplatz konnte nicht ermittelt werden: "+str(exc)) from exc
        locations = []
        for candidate in all_roots(self.storage):
            try:
                current = registered_root(self.storage,candidate)
                disk = shutil.disk_usage(current)
                locations.append({'path':str(current),'free_bytes':disk.free,'error':None})
            except (ValueError,OSError) as exc:
                locations.append({'path':str(candidate),'free_bytes':None,'error':str(exc)})
        return {"locations":locations,"path": str(self.storage.root.resolve()), "volume": volume, "scan": self.last_scan}

    def scan(self):
        if not self.lock.acquire(blocking=False):
            raise HTTPException(409, "Eine Speichermessung läuft bereits. Bitte kurz warten.")
        try:
            start = time.monotonic()
            visited = 0
            areas = []
            for name, label in AREAS:
                result = {"id": name, "label": label, "bytes": 0, "files": 0,
                          "directories": 0, "skipped_links": 0, "errors": 0, "complete": True}
                areas.append(result)
                pending = []
                for candidate in all_roots(self.storage):
                    try:
                        pending.append(registered_root(self.storage,candidate)/name)
                    except (ValueError,OSError):
                        result['errors'] += 1
                        result['complete'] = False
                while pending:
                    if visited >= MAX_ENTRIES or time.monotonic()-start >= MAX_SECONDS:
                        result["complete"] = False
                        break
                    folder = pending.pop()
                    try:
                        info = folder.lstat()
                        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                            result["skipped_links"] += 1
                            continue
                        with os.scandir(folder) as entries:
                            for entry in entries:
                                if visited >= MAX_ENTRIES or time.monotonic()-start >= MAX_SECONDS:
                                    result["complete"] = False
                                    break
                                visited += 1
                                try:
                                    info = entry.stat(follow_symlinks=False)
                                    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                                        result["skipped_links"] += 1
                                    elif stat.S_ISDIR(info.st_mode):
                                        result["directories"] += 1
                                        pending.append(type(folder)(entry.path))
                                    elif stat.S_ISREG(info.st_mode):
                                        result["files"] += 1
                                        result["bytes"] += info.st_size
                                except OSError:
                                    result["errors"] += 1
                                    result["complete"] = False
                    except OSError:
                        result["errors"] += 1
                        result["complete"] = False
            self.last_scan = {"measured_at": datetime.now(UTC).isoformat(), "areas": areas,
                              "bytes": sum(area["bytes"] for area in areas),
                              "complete": all(area["complete"] for area in areas),
                              "skipped_links": sum(area["skipped_links"] for area in areas),
                              "errors": sum(area["errors"] for area in areas)}
            return self.get()
        finally:
            self.lock.release()


def storage_overview_router(overview, authorize):
    router = APIRouter(prefix="/api/settings/storage", dependencies=[Depends(authorize)])

    @router.get("")
    def get_overview():
        return overview.get()

    @router.post("/scan")
    def measure():
        return overview.scan()
    return router
