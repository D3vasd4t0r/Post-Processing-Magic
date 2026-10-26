"""Metadata-only source references and bounded, leased upload-original streams."""

import os
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from forensic_app.windows_access import input_identity, locked_input
from forensic_app.workspaces import no_links

LEASE_SECONDS = 300
CHUNK_BYTES = 1024 * 1024


def initialize_sources(connection):
    connection.execute("CREATE TABLE IF NOT EXISTS source_streams (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, expires REAL NOT NULL)")


def check_cleanup(connection):
    if connection.execute('SELECT active FROM cleanup_state WHERE id=1').fetchone()[0]:
        raise HTTPException(409, 'Data cleanup is in progress. Retry afterwards.')


def checked_file(path):
    no_links(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Source is not an independent regular file.')
    return info


class SourceAccess:
    def __init__(self, store):
        self.store = store
        self.tickets = {}
        self.lock = threading.Lock()

    def _path(self, ident):
        plan = self.store.plan(ident)
        if plan.get('source_kind', 'upload') == 'local':
            return plan, Path(plan['local_input']['path'])
        return plan, self.store.paths(ident)[0]/'evidence'/ident/'Evidence.zip'

    def metadata(self, ident):
        plan, path = self._path(ident)
        local = plan.get('source_kind') == 'local'
        result = {'kind': 'local' if local else 'upload', 'filename': plan.get('filename', 'Evidence.zip'),
                  'available': False, 'size': None, 'reason': None}
        if local:
            result['path'] = str(path)
        with closing(sqlite3.connect(self.store.storage.database)) as connection:
            connection.execute('BEGIN IMMEDIATE')
            check_cleanup(connection)
            try:
                info = checked_file(path)
                if local:
                    identity = plan['local_input']
                    if (info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino) != tuple(identity[key] for key in ('size', 'mtime_ns', 'device', 'inode')):
                        raise ValueError('The referenced original has changed.')
                else:
                    expected = connection.execute('SELECT input_size FROM jobs WHERE id=?', (ident,)).fetchone()[0]
                    if info.st_size != expected:
                        raise ValueError('The uploaded original size has changed.')
                result.update(available=True, size=info.st_size)
            except (OSError, ValueError) as exc:
                result['reason'] = str(exc)
        return result

    def ticket(self, ident):
        meta = self.metadata(ident)
        if meta['kind'] != 'upload':
            raise HTTPException(409, 'Local sources are references and cannot be downloaded.')
        if not meta['available']:
            raise HTTPException(404, 'Uploaded original is no longer available.')
        try:
            _, path = self._path(ident)
            info = checked_file(path)
            identity = (info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino)
        except (OSError, ValueError) as exc:
            raise HTTPException(404, 'Uploaded original is missing or unsafe.') from exc
        with self.lock:
            now = time.monotonic()
            self.tickets = {key: value for key, value in self.tickets.items() if value[1] > now}
            if len(self.tickets) >= 64:
                raise HTTPException(429, 'Too many pending source downloads.')
            token = secrets.token_urlsafe(32)
            self.tickets[token] = (ident, now + 120, identity)
        return {'url': '/api/sources/' + token}

    def stream(self, ticket):
        with self.lock:
            entry = self.tickets.pop(ticket, None)
        if entry is None or entry[1] <= time.monotonic():
            raise HTTPException(410, 'Download ticket expired or already used.')
        ident = entry[0]
        plan, path = self._path(ident)
        if plan.get('source_kind') == 'local':
            raise HTTPException(409, 'Local sources cannot be downloaded.')
        lease = secrets.token_hex(24)
        # Serialize admission with cleanup. No transaction is held while streaming.
        with closing(sqlite3.connect(self.store.storage.database)) as connection, connection:
            connection.execute('BEGIN IMMEDIATE')
            check_cleanup(connection)
            connection.execute('INSERT INTO source_streams VALUES (?,?,?)', (lease, ident, time.time()+LEASE_SECONDS))
        handle_context, source = None, None
        release_lock = threading.Lock()
        heartbeat_stop = threading.Event()
        released = False

        def release():
            nonlocal released
            with release_lock:
                if released:
                    return
                released = True
                heartbeat_stop.set()
                try:
                    if handle_context is not None and source is not None:
                        handle_context.__exit__(None, None, None)
                finally:
                    with closing(sqlite3.connect(self.store.storage.database)) as connection, connection:
                        connection.execute('DELETE FROM source_streams WHERE id=?', (lease,))

        try:
            checked_file(path)
            handle_context = locked_input(path)
            source = handle_context.__enter__()
            info = checked_file(path)
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or opened.st_nlink != 1:
                raise ValueError('Source identity changed while opening.')
            identity = input_identity(source)
            if tuple(identity[key] for key in ('size', 'mtime_ns', 'device', 'inode')) != entry[2]:
                raise ValueError('Source changed after download authorization.')
            if plan.get('source_kind', 'upload') != 'upload':
                raise ValueError('Source is not an upload.')
        except (OSError, ValueError) as exc:
            release()
            raise HTTPException(404, 'Uploaded original is missing or unsafe.') from exc

        def renew():
            # Slow clients may suspend the body iterator for minutes. Keep cleanup
            # admission closed until disconnect/completion, independent of demand.
            while not heartbeat_stop.wait(30):
                with release_lock:
                    if released:
                        return
                    with closing(sqlite3.connect(self.store.storage.database)) as connection, connection:
                        connection.execute('UPDATE source_streams SET expires=? WHERE id=?', (time.time()+LEASE_SECONDS, lease))

        threading.Thread(target=renew, daemon=True, name='source-download-lease').start()

        def chunks():
            try:
                while True:
                    with closing(sqlite3.connect(self.store.storage.database)) as connection, connection:
                        connection.execute('BEGIN IMMEDIATE')
                        check_cleanup(connection)
                        connection.execute('UPDATE source_streams SET expires=? WHERE id=?', (time.time()+LEASE_SECONDS, lease))
                    info = checked_file(path)
                    if input_identity(source) != identity or (info.st_dev, info.st_ino) != (identity['device'], identity['inode']):
                        raise OSError('Source changed during download.')
                    chunk = source.read(CHUNK_BYTES)
                    if not chunk:
                        return
                    yield chunk
            finally:
                release()

        filename = quote(plan.get('filename', 'Evidence.zip'), safe='')
        return StreamingResponse(chunks(), media_type='application/zip', background=BackgroundTask(release),
                                 headers={'Content-Disposition': "attachment; filename*=UTF-8''"+filename,
                                          'Content-Length': str(identity['size']), 'Cache-Control': 'no-store'})


def source_router(access, authorize):
    router = APIRouter(prefix='/api/jobs', dependencies=[Depends(authorize)])

    @router.get('/{ident}/source')
    def metadata(ident: str):
        return access.metadata(ident)

    @router.post('/{ident}/source/download-ticket')
    def ticket(ident: str):
        return access.ticket(ident)

    return router


def source_download_router(access):
    # One-use capability minted exclusively by the authenticated route above.
    router = APIRouter(prefix='/api/sources')

    @router.get('/{ticket}')
    def download(ticket: str):
        return access.stream(ticket)

    return router
