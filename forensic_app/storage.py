import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4


def default_data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
    return base / "PostProcessingMagic"


@dataclass(frozen=True)
class Storage:
    root: Path

    @property
    def database(self) -> Path:
        return self.root / "state.sqlite3"

    def initialize(self) -> None:
        for name in ("config", "evidence", "work", "results", "logs"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY CHECK(version = 1)
                );
                INSERT OR IGNORE INTO schema_version VALUES (1);
                CREATE TABLE IF NOT EXISTS startup_events (
                    id INTEGER PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    version TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tool_locations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    path TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS configuration_events (
                    id INTEGER PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    before_json TEXT,
                    after_json TEXT
                );
                CREATE TABLE IF NOT EXISTS workspace_settings(id INTEGER PRIMARY KEY CHECK(id=1),path TEXT,owner TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workspace_roots(path TEXT PRIMARY KEY,owner TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS archive_requests(job_id TEXT PRIMARY KEY,status TEXT NOT NULL,error TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
                CREATE TABLE IF NOT EXISTS cleanup_state(id INTEGER PRIMARY KEY CHECK(id=1),active INTEGER NOT NULL DEFAULT 0);
                INSERT OR IGNORE INTO cleanup_state VALUES (1,0);
                CREATE TABLE IF NOT EXISTS server_control(id INTEGER PRIMARY KEY CHECK(id=1),stopping INTEGER NOT NULL DEFAULT 0);
                INSERT OR IGNORE INTO server_control VALUES (1,0);
                CREATE TABLE IF NOT EXISTS server_preferences(id INTEGER PRIMARY KEY CHECK(id=1),body_json TEXT NOT NULL,revision INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS feedback(id TEXT PRIMARY KEY,category TEXT NOT NULL,title TEXT NOT NULL,text TEXT NOT NULL,app_version TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
                CREATE TABLE IF NOT EXISTS cleanup_events(id INTEGER PRIMARY KEY,category TEXT NOT NULL,status TEXT NOT NULL,detail TEXT NOT NULL,
                    occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
            """)

            connection.execute('INSERT OR IGNORE INTO workspace_settings(id,path,owner) VALUES (1,NULL,?)',(str(uuid4()),))

    def record_start(self, version: str) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO startup_events(occurred_at, version) "
                "VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?)",
                (version,),
            )

    def list_tools(self) -> list[dict]:
        with closing(sqlite3.connect(self.database)) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(
                "SELECT id, name, path FROM tool_locations ORDER BY name COLLATE NOCASE"
            )]

    def save_tool(self, tool_id: str, name: str, path: str, *, create: bool) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            old = connection.execute(
                "SELECT id, name, path FROM tool_locations WHERE id = ?", (tool_id,)
            ).fetchone()
            if not create and old is None:
                raise KeyError(tool_id)
            if create:
                connection.execute(
                    "INSERT INTO tool_locations(id, name, path) VALUES (?, ?, ?)",
                    (tool_id, name, path),
                )
            else:
                connection.execute(
                    "UPDATE tool_locations SET name = ?, path = ? WHERE id = ?",
                    (name, path, tool_id),
                )
            connection.execute(
                "INSERT INTO configuration_events "
                "(occurred_at, action, tool_id, before_json, after_json) "
                "VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, ?, ?, ?)",
                ("create" if create else "update", tool_id,
                 json.dumps(dict(old)) if old else None,
                 json.dumps({"id": tool_id, "name": name, "path": path})),
            )

    def tool_usage(self, tool_id: str) -> list[dict]:
        with closing(sqlite3.connect(self.database)) as connection:
            result = []
            for table in ('mode_drafts','malware_modes'):
                if connection.execute('SELECT 1 FROM sqlite_master WHERE name=?',(table,)).fetchone():
                    result.extend({'id':row[0],'name':row[1]} for row in connection.execute('SELECT id,name,body_json FROM '+table)
                                  if any(step.get('tool_id') == tool_id for step in json.loads(row[2]).get('steps',[])))
            return result


    def delete_tool(self, tool_id: str) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            old = connection.execute(
                "SELECT id, name, path FROM tool_locations WHERE id = ?", (tool_id,)
            ).fetchone()
            if old is None:
                raise KeyError(tool_id)
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='mode_drafts'"
            ).fetchone():
                used_by = [mode_name for mode_name, mode_body in connection.execute("SELECT name,body_json FROM mode_drafts")
                           if any(step.get("tool_id") == tool_id for step in json.loads(mode_body).get("steps", []))]
                if used_by:
                    raise ValueError("Tool ist in folgenden Modi eingebunden: "+", ".join(used_by)+
                                     ". Löschen gesperrt; Verknüpfungen bleiben erhalten.")
            if connection.execute("SELECT 1 FROM sqlite_master WHERE name='malware_modes'").fetchone():
                names = [name for name,body in connection.execute('SELECT name,body_json FROM malware_modes')
                         if any(step.get('tool_id') == tool_id for step in json.loads(body).get('steps',[]))]
                if names:
                    raise ValueError('Tool ist in Malware-Modulen eingebunden: '+', '.join(names)+'. Verknüpfungen bleiben erhalten.')
            connection.execute("DELETE FROM tool_locations WHERE id = ?", (tool_id,))
            connection.execute(
                "INSERT INTO configuration_events "
                "(occurred_at, action, tool_id, before_json) "
                "VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), 'delete', ?, ?)",
                (tool_id, json.dumps(dict(old))),
            )


class InstanceLock:
    """OS-owned lock; released even after a crash. A stale filename is harmless."""

    def __init__(self, root: Path):
        self.path = root / ".instance.lock"
        self.stream: BinaryIO | None = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        stream = self.path.open("a+b")
        try:
            stream.seek(0, 2)
            if stream.tell() == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            stream.close()
            raise RuntimeError("In diesem Datenverzeichnis läuft bereits eine Instanz.") from exc
        self.stream = stream
        return self

    def __exit__(self, *_):
        if self.stream is not None:
            self.stream.close()
            self.stream = None

