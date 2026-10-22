import argparse
import sqlite3

import pytest
from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.launcher import validate
from forensic_app.storage import InstanceLock, Storage


def test_startup_creates_persistent_storage_and_protects_api(tmp_path):
    storage = Storage(tmp_path / "data")
    app = create_app(storage, "test-token")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/system").status_code == 401
        assert client.get("/api/system", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get(
            "/api/system", headers={b"Authorization": b"Bearer \xc3\xa4"}
        ).status_code == 401
        response = client.get("/api/system", headers={"Authorization": "Bearer test-token"})
        assert response.status_code == 200
        assert response.json()["profiles"] == []
        assert not any(response.json()["capabilities"].values())
        assert "Startgerüst" in client.get("/").text
        assert client.get("/", headers={"host": "hostile.example"}).status_code == 400
        assert client.get("/config/access-token.txt").status_code == 404
        assert client.get("/state.sqlite3").status_code == 404
        assert client.get("/api/system").headers["cache-control"] == "no-store"
    for name in ("config", "evidence", "work", "results", "logs"):
        assert (storage.root / name).is_dir()
    with TestClient(app, base_url="http://127.0.0.1"):
        pass
    connection = sqlite3.connect(storage.database)
    try:
        assert connection.execute("SELECT count(*) FROM startup_events").fetchone()[0] == 2
    finally:
        connection.close()


def test_lock_rejects_duplicate_and_releases(tmp_path):
    with (
        InstanceLock(tmp_path),
        pytest.raises(RuntimeError, match="bereits"),
        InstanceLock(tmp_path),
    ):
        pass
    with InstanceLock(tmp_path):
        pass


@pytest.mark.parametrize("port", [0, 65536])
def test_rejects_invalid_port(port):
    with pytest.raises(ValueError, match="Port"):
        validate(argparse.Namespace(port=port, lan=False, tls_cert=None, tls_key=None))


def test_lan_accepts_automatic_certificate_mode():
    validate(argparse.Namespace(port=8765, lan=True, tls_cert=None, tls_key=None))


def test_partial_tls_configuration_rejected(tmp_path):
    with pytest.raises(ValueError, match="zusammen"):
        validate(argparse.Namespace(port=8765, lan=False, tls_cert=tmp_path / "cert", tls_key=None))

