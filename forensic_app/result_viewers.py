"""Explicit local GUI starts for two synthetically verified viewer builds.

Configured paths are ordinary shared tool records and travel with configuration
export. Fingerprints identify tested invocation contracts, not a sandbox or proof
of safety of the viewer, its dependencies, or the displayed result.
"""

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
from contextlib import closing
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from forensic_app.app_errors import AppValueError, ErrorText, error_detail
from forensic_app.explorer import local_client
from forensic_app.result_access import result_file
from forensic_app.windows_access import interactive_desktop
from forensic_app.workspaces import no_links

VIEWERS = {
    'timeline': ('Timeline Explorer', 'TimelineExplorer', '.csv',
                 '21ae15f2f7fea1bc27792520ea04364eb8521461415de0b19fa76e65fab83cd9',
                 '68607d1cac01546376fb8ddd4b7ab10a2bc48e2b64e51a12831f47fa9ce1be6d'),
    'ezviewer': ('EZViewer', 'EZViewer', '.xlsx',
                 '8df39382fd7ff6d09a4baca752f41851da4bc6af4daf6b1d4fffd9d594b3372f',
                 '4318a7c6867c05e7da0ca70cf26c2a9c759a93711da34d5274d3f5d2e49299c7'),
}


def configured(storage, kind):
    name, stem, _, exe_hash, dll_hash = VIEWERS[kind]
    tool = next((item for item in storage.list_tools() if item['name'].casefold() == name.casefold()), None)
    proposal = f'C:\\DFIR\\Zimmerman\\net9\\{stem}\\{stem}.exe'
    return tool, proposal, exe_hash, dll_hash


def checked_program(storage, kind):
    tool, _, exe_hash, dll_hash = configured(storage, kind)
    if tool is None:
        raise AppValueError('error.d5bc8a09963c')
    path = Path(tool['path'])
    if not path.is_absolute() or path.name.casefold() != (VIEWERS[kind][1]+'.exe').casefold():
        raise AppValueError('error.cd41f0eff355')
    for candidate, expected in ((path, exe_hash), (path.with_suffix('.dll'), dll_hash)):
        no_links(candidate)
        info = candidate.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 128*1024**2:
            raise AppValueError('error.b3c64a9d7c1c')
        with candidate.open('rb') as source:
            actual = hashlib.file_digest(source, 'sha256').hexdigest()
        if actual != expected:
            raise AppValueError('error.25db03b6af49')
    return path


class ViewerOpen(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['timeline', 'ezviewer']
    path: str = Field(min_length=1, max_length=240)


def viewer_router(service, authorize):
    router = APIRouter(dependencies=[Depends(authorize)])

    @router.get('/api/settings/viewers')
    def settings():
        return {'viewers': [{'kind': kind, 'name': spec[0], 'proposal': configured(service.storage, kind)[1],
                                 'tool': configured(service.storage, kind)[0]} for kind, spec in VIEWERS.items()]}

    def check(ident, path, kind, host):
        if not local_client(host):
            raise HTTPException(403, ErrorText('error.6c21c6a29f60'))
        if os.name != 'nt' or not interactive_desktop():
            raise HTTPException(409, ErrorText('error.9a263312f43e'))
        return result_file(service.store, ident, path, (VIEWERS[kind][2],))

    def program(kind):
        try:
            return checked_program(service.storage,kind)
        except (ValueError,OSError) as exc:
            raise HTTPException(409,error_detail(exc)) from exc

    @router.get('/api/jobs/{ident}/viewer')
    def availability(ident: str, request: Request, path: str = Query(max_length=240),
                     kind: Literal['timeline','ezviewer'] = 'timeline'):
        try:
            with check(ident,path,kind,request.client.host if request.client else ''):
                program(kind)
            return {'available':True,'reason':'Getesteter Datei-Aufruf für Version 2026.5.0. Start nur auf eigenen Klick, außerhalb der internen Vorschau; keine Sandbox.'}
        except (HTTPException, ValueError, OSError) as exc:
            return {'available':False,'reason':str(exc.detail) if isinstance(exc,HTTPException) else str(exc)}

    @router.post('/api/jobs/{ident}/viewer')
    def open_viewer(ident: str, body: ViewerOpen, request: Request):
        try:
            with check(ident,body.path,body.kind,request.client.host if request.client else '') as (_, result):
                executable = program(body.kind)
                process = subprocess.Popen([str(executable),str(result)],shell=False,cwd=str(executable.parent),
                                           stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                           close_fds=True)
        except (ValueError,OSError) as exc:
            raise HTTPException(409,ErrorText('error.9ef1fb91cdf8', p0=error_detail(exc))) from exc
        with closing(sqlite3.connect(service.storage.database)) as connection, connection:
            connection.execute("INSERT INTO job_events(job_id,kind,payload) VALUES (?,'viewer',?)",
                               (ident,json.dumps({'action':'open-result-viewer','viewer':body.kind,'result':body.path,
                                                  'actor':'authenticated-local','pid':process.pid})))
        return {'requested':True,'message':'Viewerstart auf dem Server angefordert. Bitte das Viewerfenster prüfen.'}

    return router
