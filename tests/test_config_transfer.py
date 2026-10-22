import copy
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.config_transfer import MAX_IMPORT_BYTES
from forensic_app.storage import Storage

BASE = "/api/settings/configuration"
AUTH = {"Authorization": "Bearer transfer-secret"}


@pytest.fixture
def setup(tmp_path):
    storage = Storage(tmp_path / "state")
    with TestClient(create_app(storage, "transfer-secret"), base_url="http://127.0.0.1",
                    headers=AUTH) as client:
        yield client, storage


def exported(client):
    response = client.get(BASE + "/export")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    return response.json()


def preview(client, document, strategy="merge"):
    response = client.post(BASE + "/preview", json={"strategy": strategy, "document": document})
    assert response.status_code == 200, response.text
    return response.json()


def test_authenticated_roundtrip_preserves_steps_references_and_backups(setup, tmp_path):
    client, storage = setup
    path = tmp_path / "only-a-synthetic-tool.exe"
    path.write_text("Never execute")
    tool = client.post("/api/settings/tools", json={"name": "Example", "path": str(path)}).json()
    original = exported(client)
    mode = original["modes"][0]
    mode["steps"] = [
        {**mode["steps"][0], "id": "second-first", "tool_id": tool["id"], "parameters": '--output "PostMortem/a"'},
        {**mode["steps"][0], "id": "first-second", "tool_id": tool["id"], "parameters": "--read Targets\\C"},
    ]
    original["modes"][0] = mode
    before = exported(client)
    result = preview(client, original)
    assert result["valid"] and result["changes"]["modes"]["updated"] == [mode["name"]]
    assert exported(client)["modes"] == before["modes"]
    assert not (storage.root / "config" / "backups").exists()
    response = client.post(BASE + "/apply", json={"ticket": result["ticket"]})
    assert response.status_code == 200, response.text
    after = exported(client)
    assert after["tools"] == original["tools"]
    assert after["modes"] == original["modes"]
    backup = json.loads(Path(response.json()["backup_file"]).read_text(encoding="utf-8"))
    assert backup["modes"] == before["modes"]
    assert "transfer-secret" not in json.dumps(after)
    assert set(after) == {"format", "schema_version", "app_version", "exported_at", "tools", "modes", "limits"}
    assert client.post(BASE + "/apply", json={"ticket": result["ticket"]}).status_code == 409
    same = preview(client, after)
    assert same["valid"] and same["changes"]["modes"]["unchanged"] == 1
    assert same["changes"]["tools"]["unchanged"] == 1
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute("SELECT count(*) FROM configuration_import_events").fetchone()[0] == 1
    assert path.read_text() == "Never execute"


def test_preview_auth_schema_size_and_invalid_json(setup):
    client, _ = setup
    doc = exported(client)
    for method, route in [("GET", "/export"), ("POST", "/preview"), ("POST", "/apply")]:
        assert client.request(method, BASE + route, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post(BASE + "/preview", content=b"not json").status_code == 422
    for updates in [{"schema_version": 99}, {"secret": "never-export"}]:
        response = client.post(BASE + "/preview", json={"document": {**doc, **updates}})
        assert response.status_code == 422
    assert client.post(BASE + "/preview", content=b" " * (MAX_IMPORT_BYTES+1)).status_code == 413
    assert client.post(BASE + "/apply", json={"ticket": "no-preview"}).status_code == 409


@pytest.mark.parametrize("conflict", ["slot", "name", "reference", "id"])
def test_conflicts_block_import_without_changes(setup, conflict):
    client, _ = setup
    original = exported(client)
    doc = copy.deepcopy(original)
    if conflict == "reference":
        doc["modes"][0]["steps"][0]["tool_id"] = "missing-tool"
    else:
        new = copy.deepcopy(doc["modes"][0])
        new["id"] = "different-id" if conflict != "id" else new["id"]
        if conflict != "name":
            new["name"] = "New mode"
        if conflict != "slot":
            new["effort"] = "schnell"
        doc["modes"].append(new)
    result = preview(client, doc)
    assert not result["valid"] and result["errors"] and "ticket" not in result
    assert exported(client)["modes"] == original["modes"]


def test_replace_requires_confirmation_and_empty_configuration_survives_restart(setup):
    client, storage = setup
    doc = exported(client)
    doc["modes"] = []
    result = preview(client, doc, "replace")
    assert result["valid"] and len(result["changes"]["modes"]["removed"]) == 1
    assert client.post(BASE + "/apply", json={"ticket": result["ticket"]}).status_code == 422
    assert client.post(BASE + "/apply", json={"ticket": result["ticket"], "confirm_replace": True}).status_code == 200
    with TestClient(create_app(storage, "transfer-secret"), base_url="http://127.0.0.1", headers=AUTH) as restarted:
        assert exported(restarted)["modes"] == []


def test_preview_is_invalidated_by_intervening_settings_edit(setup, tmp_path):
    client, _ = setup
    result = preview(client, exported(client))
    tool = {"name": "Changed during preview", "path": str(tmp_path)}
    assert client.post("/api/settings/tools", json=tool).status_code == 201
    response = client.post(BASE + "/apply", json={"ticket": result["ticket"]})
    assert response.status_code == 409
    assert exported(client)["tools"][0]["name"] == tool["name"]


def test_database_failure_rolls_back_entire_import(setup):
    client, storage = setup
    before = exported(client)
    doc = copy.deepcopy(before)
    doc["modes"][0]["description"] = "Attempted change"
    result = preview(client, doc)
    with sqlite3.connect(storage.database) as connection:
        connection.execute("CREATE TRIGGER reject_import BEFORE INSERT ON mode_drafts "
                           "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
    assert client.post(BASE + "/apply", json={"ticket": result["ticket"]}).status_code == 500
    assert exported(client)["modes"] == before["modes"]
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute("SELECT count(*) FROM configuration_import_events").fetchone()[0] == 0
