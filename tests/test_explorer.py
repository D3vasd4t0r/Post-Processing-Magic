import json
import sqlite3
import subprocess
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.storage import Storage

AUTH = {"Authorization": "Bearer explorer-test"}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    storage = Storage(tmp_path / "state")
    app = create_app(storage, "explorer-test", lan=True)
    opened = []
    monkeypatch.setattr("forensic_app.explorer.interactive_desktop", lambda: True)
    monkeypatch.setattr("forensic_app.explorer.open_explorer", opened.append)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 4321), headers=AUTH) as client:
        ident = str(uuid4())
        plan = {"mode": {"name": "Own metadata fixture", "output_folder": "Results\\Own output"},
                "command": "Own fixture; never execute", "tool": {}}
        with sqlite3.connect(storage.database) as connection:
            connection.execute("INSERT INTO jobs(id,status,phase,config_json) VALUES (?,'succeeded','Done',?)",
                               (ident, json.dumps(plan)))
        folder = storage.root / "work" / ident / "Results" / "Own output"
        folder.mkdir(parents=True)
        (folder / "own.txt").write_text("Only synthetic result")
        yield client, app, storage, ident, folder, opened


def test_local_open_uses_frozen_folder_and_audits_without_changing_job(setup):
    client, _, storage, ident, folder, opened = setup
    url = f"/api/jobs/{ident}/explorer"
    assert client.get(url).json()["available"]
    assert opened == []  # Availability never opens a window.
    before = client.get('/api/jobs/'+ident).json()
    # No submitted path is interpreted; endpoint resolves only the stored snapshot.
    response = client.post(url, json={"path": "C:\\Windows"})
    assert response.status_code == 200 and response.json()["requested"]
    assert opened == [folder.resolve()]
    assert client.get('/api/jobs/'+ident).json() == before
    assert (folder / "own.txt").read_text() == "Only synthetic result"
    with sqlite3.connect(storage.database) as connection:
        event = json.loads(connection.execute("SELECT payload FROM job_events WHERE kind='explorer'").fetchone()[0])
    assert event["path"] == str(folder.resolve()) and event["actor"] == "authenticated-local"


def test_authentication_required(setup):
    client, _, _, ident, _, opened = setup
    for method in (client.get, client.post):
        assert method(f'/api/jobs/{ident}/explorer', headers={"Authorization": ""}).status_code == 401
    assert not opened


def test_remote_cannot_open_even_with_forwarded_header(setup):
    _, app, _, ident, _, opened = setup
    with TestClient(app, base_url="http://192.0.2.1", client=("192.0.2.20", 4321), headers=AUTH) as remote:
        url = f'/api/jobs/{ident}/explorer'
        info = remote.get(url).json()
        assert not info["local"] and not info["available"]
        assert remote.post(url, headers={"X-Forwarded-For": "127.0.0.1"}).status_code == 403
    assert not opened


@pytest.mark.parametrize('status', ['queued', 'running', 'failed', 'cancelled', 'interrupted'])
def test_incomplete_or_failed_jobs_cannot_open(setup, status):
    client, _, storage, ident, _, opened = setup
    with sqlite3.connect(storage.database) as connection:
        connection.execute('UPDATE jobs SET status=? WHERE id=?', (status, ident))
    assert client.post(f'/api/jobs/{ident}/explorer').status_code == 409
    assert not opened


def test_missing_folder_and_no_desktop_are_explained(setup, monkeypatch):
    client, _, _, ident, folder, opened = setup
    url = f'/api/jobs/{ident}/explorer'
    monkeypatch.setattr("forensic_app.explorer.interactive_desktop", lambda: False)
    response = client.post(url)
    assert response.status_code == 409 and 'Windows-Sitzung' in response.json()['detail']
    (folder/'own.txt').unlink()
    folder.rmdir()
    assert not client.get(url).json()['available']
    assert client.post(url).status_code == 404
    assert not opened


@pytest.mark.parametrize('path', ['..\\outside', 'C:\\Windows', '\\\\server\\share', 'Results:stream'])
def test_invalid_snapshot_path_is_rejected(setup, path):
    client, _, storage, ident, _, opened = setup
    with sqlite3.connect(storage.database) as connection:
        plan = json.loads(connection.execute('SELECT config_json FROM jobs WHERE id=?', (ident,)).fetchone()[0])
        plan['mode']['output_folder'] = path
        connection.execute('UPDATE jobs SET config_json=? WHERE id=?', (json.dumps(plan), ident))
    assert client.post(f'/api/jobs/{ident}/explorer').status_code == 409
    assert not opened


def test_junction_cannot_redirect_explorer_outside_job(setup, tmp_path):
    client, _, _, ident, folder, opened = setup
    (folder/'own.txt').unlink()
    folder.rmdir()
    outside = tmp_path/'outside'
    outside.mkdir()
    result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(folder), str(outside)],
                            check=False, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr
    assert client.post(f'/api/jobs/{ident}/explorer').status_code == 409
    assert not opened


def test_shell_error_does_not_claim_success(setup, monkeypatch):
    client, _, _, ident, _, opened = setup

    def fail(folder):
        raise OSError('Own simulated Windows failure')

    monkeypatch.setattr('forensic_app.explorer.open_explorer', fail)
    response = client.post(f'/api/jobs/{ident}/explorer')
    assert response.status_code == 409 and 'Windows Explorer' in response.json()['detail']
    assert not opened
