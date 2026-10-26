"""Drain admission and worker claims in the same SQLite transaction domain."""

import logging
import sqlite3
import threading
from contextlib import closing

from fastapi import HTTPException

from forensic_app.app_errors import ErrorText

logger = logging.getLogger(__name__)


def accepting(connection):
    """Raise HTTP 409 when drain has closed admission, using the caller transaction."""
    if connection.execute('SELECT stopping FROM server_control WHERE id=1').fetchone()[0]:
        raise HTTPException(409,ErrorText('error.80584b31b1b6'))


def draining(connection):
    """Read the persistent drain flag through the supplied SQLite connection."""
    return bool(connection.execute('SELECT stopping FROM server_control WHERE id=1').fetchone()[0])


class ServerControl:
    """Coordinate graceful shutdown after active forensic work and cleanup complete.

    The drain flag blocks new admission and claims. Waiting jobs remain queued; this
    controller does not force-stop tools or replay interrupted work.
    """
    def __init__(self,storage,jobs,on_shutdown):
        self.storage,self.jobs,self.on_shutdown = storage,jobs,on_shutdown
        self.closed = threading.Event()
        self.thread = None
        self.lock = threading.Lock()

    def reset(self):
        """Clear a previous drain flag when the owning server starts."""
        with closing(sqlite3.connect(self.storage.database)) as c,c:
            c.execute('UPDATE server_control SET stopping=0 WHERE id=1')

    def status(self):
        """Read drain state, active forensic jobs/archives and cleanup status consistently."""
        with closing(sqlite3.connect(self.storage.database)) as c:
            c.execute('BEGIN')
            return {'stopping':draining(c),
                    'active_jobs':c.execute("SELECT count(*) FROM jobs WHERE status IN ('running','uploading','validating') AND COALESCE(json_extract(config_json,'$.workspace'),'forensics')='forensics'").fetchone()[0],
                    'active_archives':c.execute("SELECT count(*) FROM archive_requests WHERE status='running' AND job_id IN (SELECT id FROM jobs WHERE COALESCE(json_extract(config_json,'$.workspace'),'forensics')='forensics')").fetchone()[0],
                    'cleanup':bool(c.execute('SELECT active FROM cleanup_state WHERE id=1').fetchone()[0])}

    def request(self):
        """Persist drain admission and start at most one shutdown-wait thread.

        A configured shutdown callback is required. Repeated requests return draining
        state rather than starting additional wait threads.
        """
        if self.on_shutdown is None:
            raise HTTPException(409,ErrorText('error.00ebc3025f62'))
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
        """Poll active work until idle, then invoke the shutdown callback; retry status failures."""
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
        """Signal the wait thread to exit and wait up to two seconds for it."""
        self.closed.set()
        if self.thread:
            self.thread.join(timeout=2)
