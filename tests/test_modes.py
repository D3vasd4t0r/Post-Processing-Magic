import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.storage import Storage

ENDPOINT = "/api/settings/modes"
AUTH = {"Authorization": "Bearer mode-token"}


def test_kape_reference_matches_user_command_and_is_seeded_only_once(tmp_path):
    storage = Storage(tmp_path / "state")
    reference = Path(__file__).resolve().parents[1] / "docs" / "KAPE_ZIP_MEDIUM.md"
    expected_command = next(line for line in reference.read_text(encoding="utf-8").splitlines()
                            if line.startswith("kape.exe "))
    with TestClient(create_app(storage, "mode-token"), base_url="http://127.0.0.1",
                    headers=AUTH) as client:
        response = client.get(ENDPOINT).json()
        assert "{Aufbereitungs-ID}" in response["workspace_pattern"]
        template = response["modes"][0]
        assert len(response["modes"]) == 1
        assert template["command_reference"] == expected_command
        assert template["source_folder"] == "Targets\\C"
        assert template["output_folder"] == "PostMortem"
        assert template["evidence_format"] == "ZIP"
        assert template["effort"] == "Medium"
        assert template["extract_folder"] == "Targets"
        assert template["steps"][0]["tool_id"] is None
        assert template["steps"][0]["tool_hint"] == "KAPE"
        assert template["steps"][0]["parameters"] == expected_command.removeprefix("kape.exe ")
        assert template["executable"] is False
        assert template["status"] == "draft"
        assert not list((storage.root / "work").iterdir())
        assert not list((storage.root / "results").iterdir())
        assert client.post("/api/jobs", json={"mode_id": template["id"]}).status_code == 422
        assert client.delete(f"{ENDPOINT}/{template['id']}").status_code == 204
    with TestClient(create_app(storage, "mode-token"), base_url="http://127.0.0.1",
                    headers=AUTH) as client:
        assert client.get(ENDPOINT).json()["modes"] == []


def test_mode_crud_persistence_and_audit_with_existing_tool_database(tmp_path):
    storage = Storage(tmp_path / "state")
    storage.initialize()
    storage.save_tool("existing-tool", "Existing Tool", str(tmp_path / "tool.exe"), create=True)
    draft = {"name": "Eigener Testmodus", "description": "Nur Beschreibung",
             "effort": "schnell", "source_folder": "Targets/C", "output_folder": "Outputs",
             "command_reference": "kape.exe --gui"}
    with TestClient(create_app(storage, "mode-token"), base_url="http://127.0.0.1",
                    headers=AUTH) as client:
        response = client.post(ENDPOINT, json=draft)
        assert response.status_code == 201
        mode_id = response.json()["id"]
        assert response.json()["source_folder"] == "Targets\\C"
        assert response.json()["executable"] is False
        assert client.post(ENDPOINT, json={**draft, "name": "eigener testmodus"}).status_code == 409
        updated = {**draft, "description": "Geändert", "effort": "langsam"}
        assert client.put(f"{ENDPOINT}/{mode_id}", json=updated).status_code == 200
        assert client.put(f"{ENDPOINT}/missing", json=updated).status_code == 404
        assert client.get("/api/settings/tools").json()["tools"][0]["id"] == "existing-tool"
    with TestClient(create_app(storage, "mode-token"), base_url="http://127.0.0.1",
                    headers=AUTH) as client:
        saved = next(mode for mode in client.get(ENDPOINT).json()["modes"] if mode["id"] == mode_id)
        assert saved["description"] == "Geändert"
        assert saved["effort"] == "langsam"
        assert len(client.get(ENDPOINT).json()["modes"]) == 2
        assert client.delete(f"{ENDPOINT}/{mode_id}").status_code == 204
        assert client.delete(f"{ENDPOINT}/{mode_id}").status_code == 404
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute(
            "SELECT action FROM mode_configuration_events WHERE mode_id = ? ORDER BY id", (mode_id,)
        ).fetchall() == [("create",), ("update",), ("delete",)]


def test_modes_require_token_and_cannot_be_marked_executable(tmp_path):
    with TestClient(create_app(Storage(tmp_path), "mode-token"),
                    base_url="http://127.0.0.1") as client:
        draft = {"name": "Test", "effort": "Medium"}
        for method, suffix in [("GET", ""), ("POST", ""), ("PUT", "/missing"), ("DELETE", "/missing")]:
            assert client.request(method, ENDPOINT + suffix, json=draft).status_code == 401
        assert client.post(ENDPOINT, headers=AUTH, json={**draft, "executable": True}).status_code == 422
        assert client.post(ENDPOINT, headers=AUTH, json={**draft, "name": " "}).status_code == 422
        assert client.post(ENDPOINT, headers=AUTH, json={**draft, "evidence_format": "EXE"}).status_code == 422
        for planned in ["E01", "VMDK"]:
            assert client.post(ENDPOINT, headers=AUTH, json={**draft, "evidence_format": planned}).status_code == 422


@pytest.mark.parametrize("folder", ["..\\escape", "C:\\outside", "\\absolute", ".", "NUL", "bad:ads", "bad."])
def test_mode_folders_stay_within_individual_job(tmp_path, folder):
    with TestClient(create_app(Storage(tmp_path), "mode-token"),
                    base_url="http://127.0.0.1", headers=AUTH) as client:
        assert client.post(ENDPOINT, json={"name": "Bad", "effort": "Test",
                                          "source_folder": folder}).status_code == 422


def test_input_and_output_folders_cannot_overlap(tmp_path):
    with TestClient(create_app(Storage(tmp_path), "mode-token"),
                    base_url="http://127.0.0.1", headers=AUTH) as client:
        draft = {"name": "Overlap", "effort": "Test", "source_folder": "Targets\\C"}
        for output in ["Targets", "targets\\c", "Targets\\C\\Outputs"]:
            assert client.post(ENDPOINT, json={**draft, "output_folder": output}).status_code == 422


def test_ordered_commands_keep_tool_references_parameters_and_protect_used_tools(tmp_path):
    storage = Storage(tmp_path)
    with TestClient(create_app(storage, "mode-token"), base_url="http://127.0.0.1",
                    headers=AUTH) as client:
        tool = client.post("/api/settings/tools", json={"name": "KAPE", "path": str(tmp_path / "kape.exe")}).json()
        parameters = '--msource .\\Targets\\C --mdest .\\PostMortem --module !EZParser --gui'
        first = {"id": "first", "name": "KAPE", "tool_id": tool["id"], "parameters": parameters}
        second = {"id": "second", "name": "Danach", "tool_id": None, "parameters": "--example"}
        draft = {"name": "Steps", "effort": "schnell", "extract_folder": "Targets", "steps": [first, second]}
        response = client.post(ENDPOINT, json=draft)
        assert response.status_code == 201
        mode_id = response.json()["id"]
        assert response.json()["steps"][0]["parameters"] == parameters
        assert client.delete(f"/api/settings/tools/{tool['id']}").status_code == 409
        reordered = client.put(f"{ENDPOINT}/{mode_id}", json={**draft, "steps": [second, first]})
        assert [step["id"] for step in reordered.json()["steps"]] == ["second", "first"]
        assert client.post(ENDPOINT, json={**draft, "name": "Duplicate IDs", "steps": [first, first]}).status_code == 422
        assert client.post(ENDPOINT, json={**draft, "name": "Unknown tool", "effort": "langsam", "steps": [{**first, "tool_id": "missing"}]}).status_code == 422
        assert client.post(ENDPOINT, json={**draft, "name": "Control", "steps": [{**first, "parameters": "line1\nline2"}]}).status_code == 422
        assert not list((storage.root / "work").iterdir())
        assert client.delete(f"{ENDPOINT}/{mode_id}").status_code == 204
        assert client.delete(f"/api/settings/tools/{tool['id']}").status_code == 204
    with TestClient(create_app(storage, "mode-token"), base_url="http://127.0.0.1",
                    headers=AUTH) as client:
        assert all(mode["id"] != mode_id for mode in client.get(ENDPOINT).json()["modes"])
