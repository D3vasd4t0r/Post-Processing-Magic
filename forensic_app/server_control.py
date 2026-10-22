"""Drain admission and worker claims in the same SQLite transaction domain."""
import logging
import sqlite3
import threading
from contextlib import closing

from fastapi import HTTPException

logger = logging.getLogger(__name__)


def accepting(connection):
    if connection.execute('SELECT stopping FROM server_control WHERE id=1').fetchone()[0]:
        raise HTTPException(409,'Server wird gestoppt. Neue Aufträge nach erneutem Start möglich.')


def draining(connection):
    return bool(connection.execute('SELECT stopping FROM server_control WHERE id=1').fetchone()[0])


class ServerControl:
    def __init__(self,storage,jobs,on_shutdown):
        self.storage,self.jobs,self.on_shutdown = storage,jobs,on_shutdown
        self.closed = threading.Event()
        self.thread = None
        self.lock = threading.Lock()

    def reset(self):
        with closing(sqlite3.connect(self.storage.database)) as c,c:
            c.execute('UPDATE server_control SET stopping=0 WHERE id=1')

    def status(self):
        with closing(sqlite3.connect(self.storage.database)) as c:
            c.execute('BEGIN')
            return {'stopping':draining(c),
                    'active_jobs':c.execute("SELECT count(*) FROM jobs WHERE status IN ('running','uploading','validating')").fetchone()[0],
                    'active_archives':c.execute("SELECT count(*) FROM archive_requests WHERE status='running'").fetchone()[0],
                    'cleanup':bool(c.execute('SELECT active FROM cleanup_state WHERE id=1').fetchone()[0])}

    def request(self):
        if self.on_shutdown is None:
            raise HTTPException(409,'Serversteuerung in diesem Testmodus nicht verfügbar.')
        with self.lock:
            with closing(sqlite3.connect(self.storage.database)) as c,c:
                c.execute('BEGIN IMMEDIATE')
                c.execute('UPDATE server_control SET stopping=1 WHERE id=1')
            if self.thread is None:
                logger.info('Geordnetes Stoppen angefordert. Neue Aufträge gesperrt, wartende zurückgehalten.')
                self.thread = threading.Thread(target=self._wait,daemon=True)
                self.thread.start()
        return {'stopping':True}

    def _wait(self):
        while not self.closed.wait(.2):
            try:
                state = self.status()
                if not state['active_jobs'] and not state['active_archives'] and not state['cleanup']:
                    logger.info('Laufende Arbeiten abgeschlossen. Server wird gestoppt.')
                    self.on_shutdown()
                    return
            except Exception:
                logger.exception('Stopstatus konnte nicht geprüft werden; erneuter Versuch folgt.')

    def close(self):
        self.closed.set()
        if self.thread:
            self.thread.join(timeout=2)
