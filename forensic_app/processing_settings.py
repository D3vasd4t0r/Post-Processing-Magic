"""Persisted byte limits, captured per job and included in configuration transfer."""

import json
import sqlite3
from contextlib import closing

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from forensic_app.storage import Storage


class ProcessingLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_upload_bytes: int = Field(default=50*1024**3, ge=1, le=2**50, strict=True)
    max_extract_bytes: int = Field(default=2_000_000_000_000, ge=1, le=2**50, strict=True)


def read_limits(connection) -> dict:
    row = connection.execute("SELECT body_json FROM processing_settings WHERE id=1").fetchone()
    return ProcessingLimits.model_validate_json(row[0]).model_dump() if row else ProcessingLimits().model_dump()


def write_limits(connection, limits: dict):
    before = read_limits(connection)
    normalized = ProcessingLimits.model_validate(limits).model_dump()
    connection.execute("INSERT OR REPLACE INTO processing_settings(id,body_json) VALUES (1,?)", (json.dumps(normalized),))
    if before != normalized:
        connection.execute("INSERT INTO processing_settings_events(before_json,after_json) VALUES (?,?)",
                           (json.dumps(before), json.dumps(normalized)))


class ProcessingSettings:
    def __init__(self, storage: Storage):
        self.storage = storage

    def initialize(self):
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS processing_settings(id INTEGER PRIMARY KEY CHECK(id=1),body_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS processing_settings_events(
                    id INTEGER PRIMARY KEY, before_json TEXT NOT NULL, after_json TEXT NOT NULL,
                    occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
            """)
            connection.execute("INSERT OR IGNORE INTO processing_settings VALUES (1,?)", (ProcessingLimits().model_dump_json(),))

    def get(self):
        with closing(sqlite3.connect(self.storage.database)) as connection:
            return read_limits(connection)

    def save(self, limits: ProcessingLimits):
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            write_limits(connection, limits.model_dump())
        return limits.model_dump()


def processing_settings_router(settings: ProcessingSettings, authorize):
    router = APIRouter(prefix="/api/settings/processing", dependencies=[Depends(authorize)])

    @router.get("")
    def get_limits():
        return settings.get()

    @router.put("")
    def save_limits(value: ProcessingLimits):
        return settings.save(value)
    return router
