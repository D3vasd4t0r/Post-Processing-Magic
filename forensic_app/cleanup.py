"""Previewed removal of app-owned job files. Never follow filesystem links."""

import hashlib
import json
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import closing
from pathlib import Path, PureWindowsPath
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StrictBool, field_validator

from forensic_app.app_errors import AppValueError, ErrorText, error_detail
from forensic_app.modes import ModeDraft
from forensic_app.workspaces import job_root, registered_root

KINDS = {'cache':'Cache leeren','evidence':'Evidences leeren','results':'Results leeren'}
TERMINAL = ('succeeded','failed','cancelled','interrupted')


class Preview(BaseModel):
    """Choose one cleanup category and optionally restrict it to a single job."""
    model_config = ConfigDict(extra='forbid')
    category: Literal['cache','evidence','results']
    job_id: str | None = None


class Apply(BaseModel):
    """Require a preview ticket and an explicit true confirmation before deletion."""
    model_config = ConfigDict(extra='forbid')
    ticket: str
    confirmed: StrictBool

    @field_validator('confirmed')
    @classmethod
    def must_confirm(cls, value):
        if not value:
            raise AppValueError('error.2648260ca025')
        return value


class Cleanup:
    """Preview and remove selected app-owned data using expiring manifest-bound tickets.

    Job history/configuration remain. Local original references and category-specific
    protected outputs are excluded; deletion is not a reversible database transaction.
    """
    def __init__(self, storage, overview):
        self.storage, self.overview = storage, overview
        self.lock = threading.Lock()
        self.tickets = {}

    def initialize(self):
        """Mark prior running cleanup events interrupted and clear the admission flag on startup."""
        with closing(sqlite3.connect(self.storage.database)) as c, c:
            c.execute("UPDATE cleanup_events SET status='interrupted' WHERE status='running'")
            c.execute('UPDATE cleanup_state SET active=0 WHERE id=1')

    def idle(self, c):
        """Check drain, download leases, cleanup, pending archives and active forensic jobs.

        Callers choose transaction scope; apply repeats these gates while acquiring the
        persistent cleanup flag before filesystem deletion.
        """
        from forensic_app.server_control import accepting
        accepting(c)
        if c.execute("SELECT 1 FROM source_streams WHERE expires>? LIMIT 1", (time.time(),)).fetchone():
            raise HTTPException(409, 'An original source is being downloaded. Retry after it finishes.')
        if c.execute('SELECT active FROM cleanup_state WHERE id=1').fetchone()[0]:
            raise HTTPException(409,ErrorText('error.90c97e3b2151'))
        if c.execute("SELECT count(*) FROM archive_requests WHERE status IN ('queued','running') AND job_id IN (SELECT id FROM jobs WHERE COALESCE(json_extract(config_json,'$.workspace'),'forensics')='forensics')").fetchone()[0]:
            raise HTTPException(409,ErrorText('error.5b20cd9b1495'))
        if c.execute("SELECT count(*) FROM jobs WHERE status NOT IN (?,?,?,?) AND COALESCE(json_extract(config_json,'$.workspace'),'forensics')='forensics'",TERMINAL).fetchone()[0]:
            raise HTTPException(409,ErrorText('error.da5a487eb1b1'))

    def checked(self, path, root=None):
        """Check an absolute descendant path and reject linked components before returning metadata."""
        root = Path(root) if root is not None else self.storage.root.resolve()
        if not path.is_absolute() or not path.is_relative_to(root):
            raise AppValueError('error.601b0357277b')
        current = root
        for part in path.relative_to(root).parts:
            current /= part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise AppValueError('error.b60dcf1e9220')
        if not path.resolve().is_relative_to(root):
            raise AppValueError('error.df83041a66f3')
        return path.lstat()

    def manifest(self, category, job_id=None):
        """Build a bounded postorder deletion manifest and its metadata fingerprint.

        Protect all recorded local originals, skip non-forensic job targets, links and
        special files, and retain result directories during cache cleanup. File contents
        are not read; limits abort the preview rather than approving an incomplete list.
        """
        root = self.storage.root.resolve()
        with closing(sqlite3.connect(self.storage.database)) as c:
            rows = c.execute('SELECT id,config_json FROM jobs').fetchall()
        protected, targets = [], []
        for ident, body in rows:
            if str(UUID(ident)) != ident:
                raise HTTPException(409,ErrorText('error.dc6d54feda5e'))
            plan = json.loads(body)
            if plan.get('source_kind') == 'local':
                protected.append(Path(plan['local_input']['path']).resolve())
            if plan.get('workspace', 'forensics') != 'forensics':
                continue
            if job_id and ident != job_id:
                continue
            relative = PureWindowsPath(ModeDraft.job_relative_folder(plan['mode'].get('output_folder','PostMortem')))
            root = job_root(self.storage,plan)
            work = root/'work'/ident
            output = work.joinpath(*relative.parts)
            if category == 'cache':
                protected.append(output)
                targets.append((work,root))
            elif category == 'evidence':
                targets.append((root/'evidence'/ident,root))
            else:
                targets.extend((p,root) for p in (output,root/'results'/(ident+'.zip'),root/'results'/(ident+'.part'),root/'results'/ident))
        records, skipped = [], 0
        start = time.monotonic()

        def walk(path, root, parent_checked=False):
            nonlocal skipped
            if len(records) >= 200_000 or time.monotonic()-start > 60:
                raise HTTPException(422,ErrorText('error.842626c1a964'))
            if any(path == p or path.is_relative_to(p) for p in protected):
                return
            try:
                # Descendants inherit a checked parent; reparse points themselves
                # are always skipped. Application rechecks every complete path.
                info = path.lstat() if parent_checked else self.checked(path,root)
                if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise AppValueError('error.35c0509a1f0d')
            except FileNotFoundError:
                return
            except ValueError:
                skipped += 1
                return
            except OSError as exc:
                raise HTTPException(409,ErrorText('error.f91a33ed8191', p0=error_detail(exc))) from exc
            directory = stat.S_ISDIR(info.st_mode)
            if directory:
                for child in sorted(path.iterdir()):
                    walk(child, root, True)
                if any(p.is_relative_to(path) for p in protected):
                    return
            elif not stat.S_ISREG(info.st_mode):
                skipped += 1
                return
            records.append({'root':str(root),'path':str(path.relative_to(root)), 'directory':directory,
                            'size':0 if directory else info.st_size,'mtime':info.st_mtime_ns,'inode':info.st_ino})

        for path,root in targets:
            walk(path,root)
        digest = hashlib.sha256(json.dumps(records,sort_keys=True).encode()).hexdigest()
        return records, digest, skipped

    def preview(self, category, job_id=None):
        """Check idle state and issue a ten-minute ticket for the current manifest fingerprint.

        Return counts and category scope without deleting anything. Apply must regenerate
        the manifest and reject changes before acting.
        """
        if job_id:
            from forensic_app.jobs import JobStore
            JobStore(self.storage).get(job_id)
        with closing(sqlite3.connect(self.storage.database)) as c:
            self.idle(c)
        records, digest, skipped = self.manifest(category,job_id)
        ticket = secrets.token_urlsafe(24)
        with self.lock:
            now = time.monotonic()
            self.tickets = {key:value for key,value in self.tickets.items() if value[0] > now}
            if len(self.tickets) >= 16:
                raise HTTPException(429,ErrorText('error.575d65995bcc'))
            self.tickets[ticket] = (now+600,category,digest,job_id)
        return {'ticket':ticket,'category':category,'label':KINDS[category],
                'files':sum(not r['directory'] for r in records),'bytes':sum(r['size'] for r in records),
                'skipped_links':skipped,'root':'Registrierte App-Datenordner (nur dieser Auftrag)' if job_id else 'Alle registrierten App-Datenordner',
                'note': 'Dauerhaft löschen. Historie, Einstellungen und lokal referenzierte Originale bleiben erhalten. '+
                    ('Ergebnisordner bleiben erhalten; entpackte Eingänge, Arbeitsreste und vollständige Command-Logs werden entfernt.' if category == 'cache' else
                     'Nur hochgeladene Eingangskopien werden entfernt.' if category == 'evidence' else
                     'Ergebnisordner, Ergebnis-ZIPs UND Abschlussberichte werden entfernt; Explorer/Download stehen danach dafür nicht mehr bereit.')}

    def apply(self, ticket):
        """Consume the ticket, close admission, recheck its manifest, and remove listed entries.

        Revalidate roots, paths and file metadata before each removal; collect up to twenty
        errors and audit partial results. Always release the cleanup flag. Earlier
        filesystem deletions cannot be rolled back if later entries fail.
        """
        with self.lock:
            value = self.tickets.pop(ticket,None)
        if not value or value[0] < time.monotonic():
            raise HTTPException(409,ErrorText('error.d12ac4be3406'))
        _, category, digest, job_id = value
        with closing(sqlite3.connect(self.storage.database)) as c, c:
            c.execute('BEGIN IMMEDIATE')
            self.idle(c)
            c.execute('UPDATE cleanup_state SET active=1 WHERE id=1')
        event = None
        try:
            records, current, _ = self.manifest(category,job_id)
            if current != digest:
                raise HTTPException(409,ErrorText('error.6693e8496441'))
            with closing(sqlite3.connect(self.storage.database)) as c, c:
                event = c.execute("INSERT INTO cleanup_events(category,status,detail) VALUES (?,'running',?)",(category,json.dumps({"actor":"authenticated-user"}))).lastrowid
            deleted, removed_bytes, errors = 0, 0, []
            for item in records:
                root = registered_root(self.storage,item['root'])
                path = root/item['path']
                try:
                    info = self.checked(path,root)
                    if not item['directory'] and (info.st_size,info.st_mtime_ns,info.st_ino) != (item['size'],item['mtime'],item['inode']):
                        raise AppValueError('error.3a22d34b6b0b')
                    if item['directory']:
                        path.rmdir()
                    else:
                        path.unlink()
                        deleted += 1
                        removed_bytes += item['size']
                except (OSError,ValueError) as exc:
                    if len(errors) < 20:
                        errors.append(item['path']+': '+str(exc))
            result = {'deleted_files':deleted,'bytes':removed_bytes,'errors':errors,'category':category,'actor':'authenticated-user'}
            with closing(sqlite3.connect(self.storage.database)) as c, c:
                c.execute('UPDATE cleanup_events SET status=?,detail=? WHERE id=?',
                          ('partial' if errors else 'done',json.dumps(result,ensure_ascii=False),event))
            self.overview.last_scan = None
            return result
        finally:
            with closing(sqlite3.connect(self.storage.database)) as c, c:
                c.execute("UPDATE cleanup_events SET status='interrupted' WHERE id=? AND status='running'",(event,))
                c.execute('UPDATE cleanup_state SET active=0 WHERE id=1')


def cleanup_router(cleaner, authorize):
    """Expose authenticated preview and explicitly confirmed cleanup application endpoints."""
    router = APIRouter(prefix='/api/settings/cleanup',dependencies=[Depends(authorize)])

    @router.post('/preview')
    def preview(value: Preview):
        return cleaner.preview(value.category,value.job_id)

    @router.post('/apply')
    def apply(value: Apply):
        return cleaner.apply(value.ticket)
    return router
