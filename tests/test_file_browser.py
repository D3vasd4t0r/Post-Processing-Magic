from pathlib import Path

from fastapi.testclient import TestClient

from forensic_app import file_browser
from forensic_app.api import create_app
from forensic_app.storage import Storage


def test_picker_requires_token_and_browses_files_and_folders_without_execution(tmp_path):
    folder = tmp_path / "Tools & Tests"
    folder.mkdir()
    child = folder / "Tool-Verzeichnis"
    child.mkdir()
    executable = folder / "Analyse Tool.exe"
    executable.write_bytes(b"deliberately not executable")
    with TestClient(
        create_app(Storage(tmp_path / "state"), "picker-token"), base_url="http://127.0.0.1"
    ) as client:
        endpoint = "/api/settings/tools/browse"
        assert client.post(endpoint, json={"path": str(folder)}).status_code == 401
        client.headers["Authorization"] = "Bearer picker-token"
        data = client.post(endpoint, json={"path": str(folder)}).json()
        assert data["path"] == str(folder.resolve())
        assert data["parent"] == str(tmp_path.resolve())
        assert [(item["name"], item["kind"]) for item in data["entries"]] == [
            (child.name, "directory"), (executable.name, "file")
        ]
        selected = client.post(endpoint, json={"path": str(executable)}).json()
        assert selected["selected_file"] == str(executable.resolve())
        assert selected["path"] == str(folder.resolve())
        filtered = client.post(endpoint, json={"path": str(folder), "query": "ANALYSE"}).json()
        assert len(filtered["entries"]) == 1
        assert filtered["entries"][0]["name"] == executable.name
        assert "content" not in filtered["entries"][0]
        assert client.get("/api/settings/tools").json()["tools"] == []
    assert executable.read_bytes() == b"deliberately not executable"


def test_picker_rejects_invalid_paths_and_reports_access_errors(tmp_path, monkeypatch):
    with TestClient(
        create_app(Storage(tmp_path / "state"), "picker-token"),
        base_url="http://127.0.0.1", headers={"Authorization": "Bearer picker-token"},
    ) as client:
        endpoint = "/api/settings/tools/browse"
        for value in ["relative", "\\\\server\\share", "C:\\bad\npath"]:
            assert client.post(endpoint, json={"path": value}).status_code == 422
        assert client.post(endpoint, json={"path": str(tmp_path / "missing")}).status_code == 404
        assert client.post(endpoint, json={"path": str(tmp_path), "extra": 1}).status_code == 422
        assert client.post(endpoint, json={"path": str(tmp_path), "query": "x" * 101}).status_code == 422

        def denied(path):
            raise PermissionError("test-only access denial")

        monkeypatch.setattr(file_browser.os, "scandir", denied)
        assert client.post(endpoint, json={"path": str(tmp_path)}).status_code == 403


def test_picker_bounds_results_and_root_parent(tmp_path, monkeypatch):
    for name in ["a.exe", "b.exe", "c.exe", "d.exe"]:
        (tmp_path / name).touch()
    monkeypatch.setattr(file_browser, "MAX_ENTRIES", 2)
    result = file_browser.browse(file_browser.BrowseRequest(path=str(tmp_path)))
    assert len(result["entries"]) == 2
    assert result["limited"]
    monkeypatch.setattr(file_browser, "MAX_SCAN", 1)
    assert file_browser.browse(file_browser.BrowseRequest(path=str(tmp_path)))["limited"]
    monkeypatch.setattr(file_browser, "MAX_SCAN", 10_000)
    root = Path(tmp_path.anchor)
    result = file_browser.browse(file_browser.BrowseRequest(path=str(root)))
    assert result["parent"] is None
