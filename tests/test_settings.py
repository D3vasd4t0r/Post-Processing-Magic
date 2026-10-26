import sqlite3

from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.storage import Storage


def test_tool_configuration_persists_and_records_changes_without_execution(tmp_path):
    storage = Storage(tmp_path / "state")
    executable = tmp_path / "tool.exe"
    # Deliberately invalid executable content. Checking must only inspect metadata.
    executable.write_text("not an executable", encoding="utf-8")
    app = create_app(storage, "settings-token")
    headers = {"Authorization": "Bearer settings-token"}
    with TestClient(app, base_url="http://127.0.0.1", headers=headers) as client:
        tool = {"name": "Testtool", "path": str(executable)}
        check = client.post("/api/settings/tools/check", json=tool)
        assert check.status_code == 200
        assert check.json()["kind"] == "file"
        created = client.post("/api/settings/tools", json=tool)
        assert created.status_code == 201
        tool_id = created.json()["id"]
        assert client.post("/api/settings/tools", json=tool).status_code == 409
        changed = {"name": "Testtool", "path": str(tmp_path / "not-installed.exe")}
        updated = client.put(f"/api/settings/tools/{tool_id}", json=changed)
        assert updated.status_code == 200
        assert updated.json()["kind"] == "missing"
        assert client.put("/api/settings/tools/unknown", json=tool).status_code == 404
        assert client.get("/api/settings/tools").json()["tools"][0]["path"] == changed["path"]
    with TestClient(create_app(storage, "new-token"), base_url="http://127.0.0.1") as client:
        auth = {"Authorization": "Bearer new-token"}
        assert len(client.get("/api/settings/tools", headers=auth).json()["tools"]) == 1
        assert client.delete(f"/api/settings/tools/{tool_id}", headers=auth).status_code == 204
        assert client.delete(f"/api/settings/tools/{tool_id}", headers=auth).status_code == 404
        assert client.get("/api/settings/tools", headers=auth).json()["tools"] == []
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute(
            "SELECT action FROM configuration_events ORDER BY id"
        ).fetchall() == [("create",), ("update",), ("delete",)]
    assert executable.read_text() == "not an executable"


def test_settings_require_auth_and_reject_invalid_paths(tmp_path):
    storage = Storage(tmp_path / "state")
    with TestClient(create_app(storage, "secret"), base_url="http://127.0.0.1") as client:
        value = {"name": "Tool", "path": str(tmp_path)}
        for method, path in [("GET", ""), ("POST", ""), ("POST", "/check"),
                             ("PUT", "/unknown"), ("DELETE", "/unknown")]:
            assert client.request(method, "/api/settings/tools" + path, json=value).status_code == 401
        client.headers["Authorization"] = "Bearer secret"
        for path in ["relative/tool.exe", "\\\\server\\share\\tool.exe", "C:\\tool\n.exe"]:
            response = client.post("/api/settings/tools", json={"name": "Tool", "path": path})
            assert response.status_code == 422
        directory = client.post("/api/settings/tools/check", json=value)
        assert directory.json()["kind"] == "directory"
        assert client.post("/api/settings/tools", json={**value, "name": "  "}).status_code == 422
        assert client.post("/api/settings/tools", json={**value, "command": "anything"}).status_code == 422
        assert client.get("/api/settings/tools").json()["tools"] == []


def test_legacy_only_tool_links_are_not_loaded_or_used_to_block_tools(tmp_path):
    storage = Storage(tmp_path / 'legacy')
    storage.initialize()
    storage.save_tool('legacy-tool', 'Kept generic tool', str(tmp_path / 'program.exe'), create=True)
    with sqlite3.connect(storage.database) as connection:
        connection.execute('CREATE TABLE malware_modes(id TEXT PRIMARY KEY, name TEXT, body_json TEXT)')
        connection.execute("INSERT INTO malware_modes VALUES ('passive', 'Legacy', 'malformed inactive payload')")
    assert storage.list_tools()[0]['id'] == 'legacy-tool'
    assert storage.tool_usage('legacy-tool') == []
    storage.delete_tool('legacy-tool')
    with sqlite3.connect(storage.database) as connection:
        assert connection.execute('SELECT body_json FROM malware_modes').fetchone()[0] == 'malformed inactive payload'
