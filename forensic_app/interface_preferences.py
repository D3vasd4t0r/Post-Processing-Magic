"""Server-local interface preferences, separate from portable analysis configuration."""
import json
import sqlite3
from contextlib import closing
from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictBool


class InterfaceState(BaseModel):
    """Validate the server-local interface language and onboarding-dismissal preference."""
    model_config = ConfigDict(extra='forbid')
    locale: Literal['de','en'] = 'de'
    onboarding_dismissed: StrictBool = False


class InterfacePatch(BaseModel):
    """Validate optional preference changes; None leaves the corresponding value unchanged."""
    model_config = ConfigDict(extra='forbid')
    locale: Literal['de','en'] | None = None
    onboarding_dismissed: StrictBool | None = None


class InterfacePreferences:
    """Persist interface preferences independently of portable processing configuration."""
    def __init__(self, storage):
        self.storage = storage

    def initialize(self):
        """Create the preference table without inserting or replacing a saved state."""
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute('CREATE TABLE IF NOT EXISTS interface_preferences '
                               '(id INTEGER PRIMARY KEY CHECK(id=1),body_json TEXT NOT NULL)')

    def get(self):
        """Return validated preferences or defaults without creating missing storage."""
        if not self.storage.database.exists():
            return InterfaceState().model_dump()
        with closing(sqlite3.connect(self.storage.database)) as connection:
            if not connection.execute("SELECT 1 FROM sqlite_master WHERE name='interface_preferences'").fetchone():
                return InterfaceState().model_dump()
            row=connection.execute('SELECT body_json FROM interface_preferences WHERE id=1').fetchone()
        return InterfaceState.model_validate_json(row[0]).model_dump() if row else InterfaceState().model_dump()

    def update(self, *, locale=None, onboarding_dismissed=None):
        """Merge non-None fields into current preferences in one serialized write.

        Initialize storage if needed and preserve values omitted from the patch; this
        does not modify workflows, job snapshots or browser-local UI state.
        """
        patch=InterfacePatch(locale=locale,onboarding_dismissed=onboarding_dismissed)
        self.storage.initialize()
        self.initialize()
        with closing(sqlite3.connect(self.storage.database)) as connection, connection:
            connection.execute('BEGIN IMMEDIATE')
            row=connection.execute('SELECT body_json FROM interface_preferences WHERE id=1').fetchone()
            before=InterfaceState.model_validate_json(row[0]).model_dump() if row else InterfaceState().model_dump()
            after=InterfaceState.model_validate({**before,**patch.model_dump(exclude_none=True)}).model_dump()
            connection.execute('INSERT OR REPLACE INTO interface_preferences(id,body_json) VALUES (1,?)',
                               (json.dumps(after),))
        return after
