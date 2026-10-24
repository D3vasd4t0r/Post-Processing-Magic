"""Server-local work destinations, registered and frozen per job. No migration."""

import json
import os
import shutil
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from forensic_app.app_errors import AppValueError, error_detail
from forensic_app.local_paths import validate_local_path


def no_links(path):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise AppValueError('error.b3e9165381f6')


def registered_root(storage, value=None):
    root = Path(value) if value else storage.root
    default = storage.root.resolve()
    if root == default or root == storage.root:
        return default
    if not root.is_absolute():
        raise AppValueError('error.890b53b794b4')
    with closing(sqlite3.connect(storage.database)) as c:
        owner = c.execute('SELECT owner FROM workspace_roots WHERE path=?',(str(root),)).fetchone()
    if not owner:
        raise AppValueError('error.caf6f13ab3b6')
    no_links(root)
    if json.loads((root/'.ppm-owner.json').read_text(encoding='utf-8')) != {'owner':owner[0]}:
        raise AppValueError('error.09b15b5aa17e')
    return root


def job_root(storage, plan):
    return registered_root(storage, plan.get('data_root'))


def job_paths(storage, plan, ident):
    if str(UUID(ident)) != ident:
        raise AppValueError('error.2f50ad74f414')
    root = job_root(storage,plan)
    for area in ['work','results','evidence']:
        no_links(root/area)
    return root,root/'work'/ident,root/'results'/(ident+'.zip')


def all_roots(storage):
    with closing(sqlite3.connect(storage.database)) as c:
        return [storage.root.resolve(),*[Path(row[0]) for row in c.execute('SELECT path FROM workspace_roots')]]


class Destination(BaseModel):
    model_config = ConfigDict(extra='forbid')
    folder: str | None = None


class Workspaces:
    def __init__(self, storage):
        self.storage = storage

    def get(self):
        with closing(sqlite3.connect(self.storage.database)) as c:
            value = c.execute('SELECT path FROM workspace_settings WHERE id=1').fetchone()[0]
        root = registered_root(self.storage,value)
        return {'path':str(root),'custom':bool(value),'folder':str(root.parent) if value else '',
                'default_path':str(self.storage.root.resolve()),'free_bytes':shutil.disk_usage(root).free,
                'note':'Gilt nur für neue Aufträge. Vorhandene Daten werden nicht verschoben. Serverlokale Einstellung, nicht im Konfigurationsexport.'}

    def save(self, folder):
        selected = None
        if folder is not None:
            base = Path(validate_local_path(folder))
            no_links(base)
            base = base.resolve(strict=True)
            for known in all_roots(self.storage):
                if any(base.is_relative_to(known/area) for area in ['work','results','evidence']):
                    raise AppValueError('error.61110f7d4fc3')
            if not base.is_dir():
                raise AppValueError('error.754d4388d6a9')
            if os.name == 'nt':
                import ctypes
                if ctypes.windll.kernel32.GetDriveTypeW(str(base.anchor)) == 4:
                    raise AppValueError('error.cb444807dea3')
            with closing(sqlite3.connect(self.storage.database)) as c:
                owner = c.execute('SELECT owner FROM workspace_settings WHERE id=1').fetchone()[0]
            selected = base/('PostProcessingMagic-Jobs-'+owner[:8])
            if selected.exists():
                no_links(selected)
                if not (selected/'.ppm-owner.json').is_file() or json.loads((selected/'.ppm-owner.json').read_text(encoding='utf-8')) != {'owner':owner}:
                    raise AppValueError('error.1f0244e8fd33')
            else:
                selected.mkdir()
                (selected/'.ppm-owner.json').write_text(json.dumps({'owner':owner}),encoding='utf-8')
            for name in ['work','results','evidence']:
                path = selected/name
                path.mkdir(exist_ok=True)
                no_links(path)
            probe = selected/('.write-test-'+uuid4().hex)
            with probe.open('xb') as f:
                f.write(b'ppm')
            probe.unlink()
        with closing(sqlite3.connect(self.storage.database)) as c,c:
            if selected:
                c.execute('INSERT OR IGNORE INTO workspace_roots(path,owner) SELECT ?,owner FROM workspace_settings WHERE id=1',(str(selected),))
            c.execute('UPDATE workspace_settings SET path=? WHERE id=1',(str(selected) if selected else None,))
            c.execute("INSERT INTO configuration_events(occurred_at,action,tool_id,after_json) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'),'workspace','server',?)",(json.dumps({'path':str(selected) if selected else None,'actor':'authenticated-user'}),))
        return self.get()


def workspace_router(workspaces, authorize):
    router = APIRouter(prefix='/api/settings/workspace',dependencies=[Depends(authorize)])
    @router.get('')
    def get():
        try:
            return workspaces.get()
        except (ValueError,OSError) as exc:
            raise HTTPException(409,error_detail(exc)) from exc
    @router.put('')
    def save(value: Destination):
        try:
            return workspaces.save(value.folder)
        except (ValueError,OSError) as exc:
            raise HTTPException(422,error_detail(exc)) from exc
    return router
