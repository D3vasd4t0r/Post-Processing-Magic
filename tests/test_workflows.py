import io
import json
import threading
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.jobs import JobService, JobStore
from forensic_app.modes import ModeDraft, ModeStore
from forensic_app.storage import Storage

AUTH = {"Authorization": "Bearer workflow-test"}


def archive():
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as output:
        output.writestr("C/example.txt", "Own synthetic input")
    return stream.getvalue()


def make_client(tmp_path, monkeypatch):
    storage = Storage(tmp_path/"state")
    monkeypatch.setattr(JobService, "available", lambda self: True)
    client = TestClient(create_app(storage, "workflow-test", test_no_admin=True),
                        base_url="http://127.0.0.1", headers=AUTH)
    return client, storage


def job(client, mode):
    response = client.post("/api/jobs", params={"mode_id": mode, "filename": "own.zip"},
                           content=archive(), headers={"Content-Type": "application/zip"})
    assert response.status_code == 200, response.text
    return response.json()["id"]


def config(storage, ident):
    import sqlite3
    with sqlite3.connect(storage.database) as connection:
        return json.loads(connection.execute("SELECT config_json FROM jobs WHERE id=?", (ident,)).fetchone()[0])


def test_limits_default_validation_auth_and_persistence(tmp_path, monkeypatch):
    client, storage = make_client(tmp_path, monkeypatch)
    with client:
        defaults = client.get("/api/settings/processing").json()
        assert defaults == {"max_upload_bytes": 50*1024**3, "max_extract_bytes": 2_000_000_000_000}
        assert client.get("/api/settings/processing", headers={"Authorization": "Bearer wrong"}).status_code == 401
        for value in (0, -1, True, "many", 2**51):
            assert client.put("/api/settings/processing", json={**defaults, "max_upload_bytes": value}).status_code == 422
        changed = {"max_upload_bytes": 12345, "max_extract_bytes": 54321}
        assert client.put("/api/settings/processing", json=changed).status_code == 200
    with TestClient(create_app(storage, "workflow-test"), base_url="http://127.0.0.1", headers=AUTH) as restarted:
        assert restarted.get("/api/settings/processing").json() == changed


def test_limit_snapshot_new_limits_do_not_change_queued_job(tmp_path, monkeypatch):
    from forensic_app.worker import process_job
    client, storage = make_client(tmp_path, monkeypatch)
    with client:
        mode = ModeStore(storage).list_modes()[0]
        draft = ModeDraft(name="Own PS", effort="Medium", steps=[{
            "type": "powershell", "script": "New-Item -ItemType Directory PostMortem | Out-Null; Set-Content PostMortem/result.txt 'Example'"}])
        ModeStore(storage).save(mode["id"], draft, create=False)
        first = job(client, mode["id"])
        client.put("/api/settings/processing", json={"max_upload_bytes": 50*1024**3, "max_extract_bytes": 1})
        second = job(client, mode["id"])
        assert config(storage, first)["limits"]["max_extract_bytes"] == 2_000_000_000_000
        process_job(JobStore(storage), first, config(storage, first), threading.Event())
        process_job(JobStore(storage), second, config(storage, second), threading.Event())
        assert client.get('/api/jobs/'+first).json()["status"] == "succeeded"
        state = client.get('/api/jobs/'+second).json()
        assert state["status"] == "failed" and "Entpacklimit" in state["error"]


def test_real_powershell_blocks_order_cd_and_explicit_working_directory(tmp_path, monkeypatch):
    from forensic_app.worker import process_job
    client, storage = make_client(tmp_path, monkeypatch)
    with client:
        mode_id = ModeStore(storage).list_modes()[0]["id"]
        draft = ModeDraft(name="PS workflow", effort="Medium", steps=[
            {"type":"powershell", "name":"Create and cd", "script":
             "New-Item -ItemType Directory PostMortem | Out-Null\ncd PostMortem\nSet-Content first.txt 'first'\nWrite-Output 'Grüße'"},
            {"type":"powershell", "name":"Root again", "script":"(Get-Location).Path | Set-Content PostMortem/second.txt"},
            {"type":"powershell", "name":"Explicit cwd", "working_directory":"PostMortem",
             "script":"Set-Content third.txt 'third'\n1..100 | ForEach-Object { Write-Output ('Line '+$_) }"},
        ])
        assert client.put('/api/settings/modes/'+mode_id,json=draft.model_dump()).status_code == 200
        assert client.get('/api/jobs/catalog').json()["modes"][0]["ready"]
        ident = job(client, mode_id)
        process_job(JobStore(storage), ident, config(storage, ident), threading.Event())
        state = client.get('/api/jobs/'+ident).json()
        assert state["status"] == "succeeded", state
        assert state["completed"] == state["total"] == 3
        assert "Grüße" in state["log_tail"] and "Line 100" in state["log_tail"]
        assert "#< CLIXML" not in state["log_tail"]
        work = storage.root/"work"/ident
        assert (work/"PostMortem"/"second.txt").read_text().strip() == str(work)
        assert (work/"PostMortem"/"first.txt").read_text().strip() == "first"
        assert (work/"PostMortem"/"third.txt").read_text().strip() == "third"
        payload = client.get('/api/settings/configuration/export').json()
        assert payload["schema_version"] == 3 and payload["modes"][0]["steps"] == draft.model_dump()["steps"]
        assert payload['malware_modes']==[]
        preview = client.post('/api/settings/configuration/preview',json={"document":payload}).json()
        assert preview["valid"] and not preview["warnings"]


def test_powershell_failure_stops_following_block(tmp_path, monkeypatch):
    from forensic_app.worker import process_job
    client, storage = make_client(tmp_path, monkeypatch)
    with client:
        mode_id = ModeStore(storage).list_modes()[0]["id"]
        draft = ModeDraft(name="Failure stops", effort="Medium", steps=[
            {"type":"powershell", "script":"throw 'Own synthetic failure'"},
            {"type":"powershell", "script":"Set-Content must-not-exist.txt 'unexpected'"}])
        ModeStore(storage).save(mode_id, draft, create=False)
        ident = job(client, mode_id)
        process_job(JobStore(storage), ident, config(storage, ident), threading.Event())
        state = client.get('/api/jobs/'+ident).json()
        assert state["status"] == "failed" and state["completed"] == 0
        assert "Own synthetic failure" in state["log_tail"]
        assert not (storage.root/"work"/ident/"must-not-exist.txt").exists()


def test_config_v2_limits_and_v1_backward_compatibility(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    with client:
        original = client.get('/api/settings/configuration/export').json()
        original['limits'] = {"max_upload_bytes": 1234, "max_extract_bytes": 5678}
        preview = client.post('/api/settings/configuration/preview',json={"document":original}).json()
        assert preview['limits']['changed']
        assert client.post('/api/settings/configuration/apply',json={"ticket":preview['ticket']}).status_code == 200
        assert client.get('/api/settings/processing').json() == original['limits']
        legacy = dict(original, schema_version=1)
        del legacy['limits']
        for mode in legacy['modes']:
            for step in mode['steps']:
                for key in ('type','script','working_directory'):
                    step.pop(key, None)
        preview = client.post('/api/settings/configuration/preview',json={"document":legacy}).json()
        assert preview['valid'] and not preview['limits']['changed']
        assert client.post('/api/settings/configuration/apply',json={"ticket":preview['ticket']}).status_code == 200
        assert client.get('/api/settings/processing').json() == original['limits']
