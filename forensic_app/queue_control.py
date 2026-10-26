"""Persistent admission pause, serialized with the worker's atomic claim."""

import json
import sqlite3
from contextlib import closing

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from forensic_app.server_control import draining


class QueueChange(BaseModel):
    """Require an explicit boolean admission-pause setting."""
    model_config = ConfigDict(extra='forbid')
    paused: bool = Field(strict=True)


class QueueControl:
    """Persist queue pause state and atomically claim the next forensic processing job.

    Pausing prevents future claims; it does not interrupt an already running command.
    """
    def __init__(self, storage):
        self.storage = storage

    def initialize(self):
        """Create queue-control/audit tables, preserving an existing pause setting."""
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.executescript('''
                CREATE TABLE IF NOT EXISTS queue_control(id INTEGER PRIMARY KEY CHECK(id=1),paused INTEGER NOT NULL CHECK(paused IN (0,1)));
                INSERT OR IGNORE INTO queue_control VALUES (1,0);
                CREATE TABLE IF NOT EXISTS queue_control_events(
                    id INTEGER PRIMARY KEY, paused INTEGER NOT NULL,
                    occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
            ''')

    def get(self):
        """Read pause, drain and forensic job/archive counters from one database snapshot."""
        with closing(sqlite3.connect(self.storage.database)) as connection:
            connection.execute('BEGIN')
            paused = bool(connection.execute('SELECT paused FROM queue_control WHERE id=1').fetchone()[0])
            archives = connection.execute("SELECT count(*) FROM archive_requests WHERE status='queued' AND job_id IN (SELECT id FROM jobs WHERE COALESCE(json_extract(config_json,'$.workspace'),'forensics')='forensics')").fetchone()[0]
            archiving = [row[0] for row in connection.execute("SELECT job_id FROM archive_requests WHERE status='running' AND job_id IN (SELECT id FROM jobs WHERE COALESCE(json_extract(config_json,'$.workspace'),'forensics')='forensics')")]
            waiting = connection.execute("SELECT count(*) FROM jobs WHERE status='queued' AND COALESCE(json_extract(config_json,'$.workspace'),'forensics')='forensics'").fetchone()[0]
            running = [row[0] for row in connection.execute("SELECT id FROM jobs WHERE status='running' AND COALESCE(json_extract(config_json,'$.workspace'),'forensics')='forensics'")]
            stopping = draining(connection)
        return {'paused':paused,'waiting':waiting,'running':running,'archive_waiting':archives,'archiving':archiving,'stopping':stopping}

    def set(self, paused):
        """Serialize the pause change, audit actual changes, then read current queue status."""
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute('BEGIN IMMEDIATE')
            old = connection.execute('SELECT paused FROM queue_control WHERE id=1').fetchone()[0]
            connection.execute('UPDATE queue_control SET paused=? WHERE id=1',(int(paused),))
            if old != int(paused):
                connection.execute('INSERT INTO queue_control_events(paused) VALUES (?)',(int(paused),))
        return self.get()

    def claim(self):
        """Claim the oldest queued forensic job and emit its status event atomically.

        Drain, cleanup and pause gates are checked in the same BEGIN IMMEDIATE transaction.
        Return the ID/configuration row, or None when admission is closed or no job waits.
        """
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute('BEGIN IMMEDIATE')
            if draining(connection):
                return None
            if connection.execute('SELECT active FROM cleanup_state WHERE id=1').fetchone()[0]:
                return None
            if connection.execute('SELECT paused FROM queue_control WHERE id=1').fetchone()[0]:
                return None
            row = connection.execute("SELECT id,config_json FROM jobs WHERE status='queued' AND COALESCE(json_extract(config_json,'$.workspace'),'forensics')='forensics' ORDER BY created_at,id LIMIT 1").fetchone()
            if row:
                connection.execute("UPDATE jobs SET status='running',phase='Wird vorbereitet' WHERE id=?",(row[0],))
                connection.execute("INSERT INTO job_events(job_id,kind,payload) VALUES (?,'status',?)",
                                   (row[0],json.dumps({'status':'running','phase':'Wird vorbereitet'})))
            return row


def queue_router(control, authorize):
    """Expose authenticated queue-status and pause controls; execution remains in the worker."""
    router = APIRouter(prefix='/api/queue',dependencies=[Depends(authorize)])

    @router.get('')
    def status():
        return control.get()

    @router.put('')
    def change(value: QueueChange):
        return control.set(value.paused)
    return router
