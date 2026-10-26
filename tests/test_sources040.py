"""Only own synthetic ZIPs; source references must never become file readers."""

import os
import sqlite3
import time

import pytest
from fastapi import HTTPException
from test_processing import archive_bytes, plan_for, upload
from test_processing import setup as setup  # noqa: PLC0414

from forensic_app.jobs import JobStore
from forensic_app.source_access import SourceAccess


def access_for(storage):
    return SourceAccess(JobStore(storage))


def test_uploaded_original_auth_metadata_and_one_use_native_stream(setup):
    client, storage, mode, _ = setup
    content = archive_bytes()
    ident = upload(client, mode, content).json()['id']
    endpoint = f'/api/jobs/{ident}/source'
    assert client.get(endpoint, headers={'Authorization': ''}).status_code == 401
    metadata = client.get(endpoint).json()
    assert metadata == {'kind': 'upload', 'filename': 'synthetic.zip', 'available': True, 'size': len(content), 'reason': None}
    assert client.post(endpoint+'/download-ticket', headers={'Authorization': ''}).status_code == 401
    url = client.post(endpoint+'/download-ticket').json()['url']
    response = client.get(url, headers={'Authorization': ''})
    assert response.status_code == 200 and response.content == content
    assert response.headers['content-length'] == str(len(content))
    assert client.get(url).status_code == 410
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute('SELECT count(*) FROM source_streams').fetchone()[0] == 0


def test_local_original_is_metadata_reference_never_download(setup, tmp_path):
    client, storage, mode, _ = setup
    path = tmp_path/'own-local.zip'
    path.write_bytes(archive_bytes())
    ident = client.post('/api/jobs/local', json={'mode_id': mode, 'path': str(path)}).json()['id']
    metadata = client.get(f'/api/jobs/{ident}/source').json()
    assert metadata['kind'] == 'local' and metadata['available']
    assert metadata['path'] == str(path)
    assert client.post(f'/api/jobs/{ident}/source/download-ticket').status_code == 409
    assert not (storage.root/'evidence'/ident).exists()
    path.unlink()
    assert not client.get(f'/api/jobs/{ident}/source').json()['available']
    assert plan_for(storage, ident)['local_input']['path'] == str(path)


def test_source_leases_exclude_cleanup_and_missing_source_is_explicit(setup):
    client, storage, mode, _ = setup
    ident = upload(client, mode).json()['id']
    access = access_for(storage)
    ticket = access.ticket(ident)['url'].rsplit('/', 1)[-1]
    response = access.stream(ticket)
    # The handle/lease is acquired before the streaming response is returned.
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute('SELECT job_id FROM source_streams').fetchone()[0] == ident
    assert client.post('/api/settings/cleanup/preview', json={'category': 'evidence'}).status_code == 409
    import asyncio
    asyncio.run(response.background())
    (storage.root/'evidence'/ident/'Evidence.zip').unlink()
    assert not access.metadata(ident)['available']
    with pytest.raises(HTTPException) as exc:
        access.ticket(ident)
    assert exc.value.status_code == 404


def test_cleanup_admission_rechecked_at_download_and_expiry(setup):
    _, storage, mode, _ = setup
    # Use the service client fixture to upload synthetic data.
    client = setup[0]
    ident = upload(client, mode).json()['id']
    access = access_for(storage)
    ticket = access.ticket(ident)['url'].rsplit('/', 1)[-1]
    with sqlite3.connect(storage.database) as connection:
        connection.execute('UPDATE cleanup_state SET active=1 WHERE id=1')
    with pytest.raises(HTTPException) as exc:
        access.stream(ticket)
    assert exc.value.status_code == 409
    with sqlite3.connect(storage.database) as connection:
        connection.execute('UPDATE cleanup_state SET active=0 WHERE id=1')
    expired = access.ticket(ident)['url'].rsplit('/', 1)[-1]
    access.tickets[expired] = (ident, time.monotonic()-1)
    with pytest.raises(HTTPException) as exc:
        access.stream(expired)
    assert exc.value.status_code == 410


def test_source_hardlinks_and_parent_links_rejected(setup, tmp_path):
    client, storage, mode, _ = setup
    ident = upload(client, mode).json()['id']
    path = storage.root/'evidence'/ident/'Evidence.zip'
    access = access_for(storage)
    ticket = access.ticket(ident)['url'].rsplit('/', 1)[-1]
    os.link(path, tmp_path/'hardlink.zip')
    assert not access.metadata(ident)['available']
    with pytest.raises(HTTPException):
        access.stream(ticket)
    assert client.get('/api/jobs/not-a-uuid/source').status_code == 404


def test_source_ticket_cannot_be_retargeted_by_unsafe_parent(setup, tmp_path):
    client, storage, mode, _ = setup
    ident = upload(client, mode).json()['id']
    access = access_for(storage)
    ticket = access.ticket(ident)['url'].rsplit('/', 1)[-1]
    folder = storage.root/'evidence'/ident
    (folder/'Evidence.zip').unlink()
    folder.rmdir()
    outside = tmp_path/'outside'
    outside.mkdir()
    (outside/'Evidence.zip').write_bytes(b'private synthetic bytes')
    try:
        folder.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('Symlink creation requires privileges on this Windows host.')
    assert not access.metadata(ident)['available']
    with pytest.raises(HTTPException):
        access.stream(ticket)


def test_source_ticket_rejects_regular_replacement_after_authorization(setup):
    client, storage, mode, _ = setup
    ident = upload(client, mode).json()['id']
    access = access_for(storage)
    ticket = access.ticket(ident)['url'].rsplit('/', 1)[-1]
    path = storage.root/'evidence'/ident/'Evidence.zip'
    path.unlink()
    path.write_bytes(b'unrelated replacement')
    with pytest.raises(HTTPException) as exc:
        access.stream(ticket)
    assert exc.value.status_code == 404


def test_link_created_during_stream_stops_reading_and_releases_lease(setup, tmp_path):
    import asyncio

    client, storage, mode, _ = setup
    payload = archive_bytes([('C/own.bin', os.urandom(2*1024**2))])
    ident = upload(client, mode, payload).json()['id']
    access = access_for(storage)
    ticket = access.ticket(ident)['url'].rsplit('/', 1)[-1]
    response = access.stream(ticket)

    async def consume():
        first = await anext(response.body_iterator)
        assert first == payload[:1024**2]
        os.link(storage.root/'evidence'/ident/'Evidence.zip', tmp_path/'late-hardlink.zip')
        with pytest.raises(ValueError):
            await anext(response.body_iterator)
        await response.background()

    asyncio.run(consume())
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute('SELECT count(*) FROM source_streams').fetchone()[0] == 0
