"""Local feedback, explicit export only. Never attached to technical diagnostics."""

import json
import sqlite3
from contextlib import closing
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from forensic_app import __version__
from forensic_app.app_errors import AppValueError, ErrorText


class FeedbackDraft(BaseModel):
    """Validate a bounded local bug, wish or general-feedback entry."""
    model_config = ConfigDict(extra='forbid',str_strip_whitespace=True)
    category: Literal['bug','wish','feedback']
    title: str = Field(min_length=1,max_length=160)
    text: str = Field(min_length=1,max_length=8000)

    @field_validator('title','text')
    @classmethod
    def valid_text(cls,value):
        if any(ord(ch)<32 and ch not in '\n\r\t' for ch in value):
            raise AppValueError('error.0e9b27f8ca9d')
        return value


class FeedbackStore:
    """Persist user feedback locally, separate from technical diagnostics and workflow exports."""
    def __init__(self,storage):
        self.storage = storage

    def list(self,limit=100):
        """Read the newest feedback entries up to the supplied SQL limit."""
        with closing(sqlite3.connect(self.storage.database)) as c:
            c.row_factory = sqlite3.Row
            return [dict(row) for row in c.execute('SELECT * FROM feedback ORDER BY created_at DESC,id DESC LIMIT ?',(limit,))]

    def create(self,draft):
        """Check the 1,000-entry cap and insert the versioned feedback atomically.

        The record receives a new UUID and database UTC timestamp; no external message
        is sent and no diagnostic files are attached.
        """
        ident = str(uuid4())
        with closing(sqlite3.connect(self.storage.database)) as c,c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT count(*) FROM feedback').fetchone()[0] >= 1000:
                raise HTTPException(409,ErrorText('error.6b267cfc5a31'))
            c.execute('INSERT INTO feedback(id,category,title,text,app_version) VALUES (?,?,?,?,?)',
                      (ident,draft.category,draft.title,draft.text,__version__))
        return {'saved':True,'id':ident}


def feedback_router(store,authorize):
    """Expose authenticated list, bounded-create and explicit JSON-export endpoints.

    The export contains entered feedback text; it is not a technical diagnostic package.
    """
    router = APIRouter(prefix='/api/feedback',dependencies=[Depends(authorize)])
    @router.get('')
    def items():
        return {'items':store.list()}
    @router.post('')
    async def create(request:Request):
        data = bytearray()
        async for chunk in request.stream():
            if len(data)+len(chunk)>65536:
                raise HTTPException(413,ErrorText('error.3fa32ca426c4'))
            data.extend(chunk)
        try:
            value = FeedbackDraft.model_validate_json(data)
        except ValidationError as exc:
            raise HTTPException(422,exc.errors(include_input=False,include_context=False)) from exc
        return store.create(value)
    @router.get('/export')
    def export():
        body = json.dumps({'schema_version':1,'feedback':store.list(1000)},ensure_ascii=False,indent=2)
        return Response(body,media_type='application/json',headers={'Content-Disposition':'attachment; filename="Feedback.json"'})
    return router
