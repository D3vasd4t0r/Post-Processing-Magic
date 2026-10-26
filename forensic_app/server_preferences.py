"""Server-local settings, deliberately excluded from portable workflow transfer."""
import json
import logging
import sqlite3
import stat
from contextlib import closing

from pydantic import BaseModel, ConfigDict, Field

from forensic_app.workspaces import no_links


class ServerPreferences(BaseModel):
    """Validate server port, LAN access and technical-log rotation limits.

    These server-local preferences are excluded from portable workflow configuration.
    """
    model_config = ConfigDict(extra='forbid')
    port: int = Field(default=8765,ge=1,le=65535,strict=True)
    lan: bool = Field(default=False,strict=True)
    log_max_bytes: int = Field(default=2_000_000,ge=100_000,le=100_000_000,strict=True)
    log_backups: int = Field(default=3,ge=1,le=20,strict=True)


class PreferenceStore:
    """Persist validated server preferences with an increasing revision and change record."""
    def __init__(self,storage):
        self.storage = storage

    def get(self):
        """Read preferences/revision or return defaults/revision zero without creating storage."""
        if not self.storage.database.exists():
            return ServerPreferences(),0
        with closing(sqlite3.connect(self.storage.database)) as c:
            if not c.execute("SELECT 1 FROM sqlite_master WHERE name='server_preferences'").fetchone():
                return ServerPreferences(),0
            row = c.execute('SELECT body_json,revision FROM server_preferences WHERE id=1').fetchone()
        return (ServerPreferences.model_validate_json(row[0]),row[1]) if row else (ServerPreferences(),0)

    def save(self,value):
        """Initialize storage and serialize the preference write, revision bump and audit.

        Saving returns validated preferences; it does not restart a running server or
        apply firewall changes.
        """
        value = ServerPreferences.model_validate(value)
        self.storage.initialize()
        with closing(sqlite3.connect(self.storage.database)) as c,c:
            c.execute('BEGIN IMMEDIATE')
            c.execute('INSERT INTO server_preferences(id,body_json,revision) VALUES (1,?,1) '
                      'ON CONFLICT(id) DO UPDATE SET body_json=excluded.body_json,revision=revision+1',(value.model_dump_json(),))
            c.execute("INSERT INTO configuration_events(occurred_at,action,tool_id,after_json) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'),'server_preferences','server',?)",(json.dumps(value.model_dump()),))
        return value


def prune_server_logs(storage,count):
    """Remove excess numbered technical log rotations while the instance lock is held.

    Only regular single-link server.log.N files above the retained count, up to 20,
    are removed. Skip linked/invalid entries and leave job logs and current logs alone.
    """
    folder = storage.root/'logs'
    no_links(folder)
    for number in range(count+1,21):
        path = folder/('server.log.'+str(number))
        if not path.exists():
            continue
        try:
            no_links(path)
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                path.unlink()
        except (OSError,ValueError):
            logging.getLogger(__name__).warning('Technische Logrotation konnte nicht bereinigt werden; Eintrag übersprungen.')
