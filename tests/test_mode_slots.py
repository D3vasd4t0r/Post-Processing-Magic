import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.modes import KAPE_TEMPLATE, ModeDraft, ModeStore, SlotConflict
from forensic_app.storage import Storage

AUTH = {"Authorization": "Bearer slot-token"}
ENDPOINT = "/api/settings/modes"


def test_unique_efforts_and_configuration_availability(tmp_path):
    storage = Storage(tmp_path / "state")
    executable = tmp_path / "example.exe"
    executable.write_bytes(b"test-only; never execute")
    with TestClient(create_app(storage, "slot-token"), base_url="http://127.0.0.1",
                    headers=AUTH) as client:
        status = {slot["effort"]: slot for slot in client.get(ENDPOINT).json()["availability"]}
        assert status["Medium"]["state"] == "incomplete"
        assert status["schnell"]["state"] == "missing"
        assert status["langsam"]["state"] == "missing"
        tool = client.post("/api/settings/tools", json={"name": "Example", "path": str(executable)}).json()
        draft = {"name": "Fast", "effort": "schnell", "steps": [{"tool_id": tool["id"]}]}
        created = client.post(ENDPOINT, json=draft)
        assert created.status_code == 201
        fast_id = created.json()["id"]
        assert client.post(ENDPOINT, json={"name": "Duplicate", "effort": "mEDiUm"}).status_code == 409
        assert client.post(ENDPOINT, json={"name": "Duplicate Fast", "effort": "schnell"}).status_code == 409
        assert client.post(ENDPOINT, json={"name": "Unsupported", "effort": "Custom"}).status_code == 422
        assert client.put(f"{ENDPOINT}/{fast_id}", json={**draft, "name": "Renamed Fast"}).status_code == 200
        assert client.put(f"{ENDPOINT}/{fast_id}", json={**draft, "effort": "Medium"}).status_code == 409
        status = {slot["effort"]: slot for slot in client.get(ENDPOINT).json()["availability"]}
        assert status["schnell"]["state"] == "configured"
        assert all(not slot["available_for_run"] for slot in status.values())
        executable.unlink()
        status = {slot["effort"]: slot for slot in client.get(ENDPOINT).json()["availability"]}
        assert status["schnell"]["state"] == "incomplete"
        assert client.delete(f"{ENDPOINT}/{fast_id}").status_code == 204
        assert client.post(ENDPOINT, json=draft).status_code == 201


def test_existing_duplicate_modes_remain_visible_and_can_be_resolved(tmp_path):
    storage = Storage(tmp_path / "state")
    storage.initialize()
    ModeStore(storage).initialize()
    legacy = KAPE_TEMPLATE.model_dump()
    legacy["name"] = "Existing duplicate"
    with sqlite3.connect(storage.database) as connection:
        connection.execute("INSERT INTO mode_drafts VALUES (?, ?, ?)",
                           ("legacy-copy", legacy["name"], json.dumps(legacy)))
    with TestClient(create_app(storage, "slot-token"), base_url="http://127.0.0.1",
                    headers=AUTH) as client:
        data = client.get(ENDPOINT).json()
        assert len(data["modes"]) == 2
        assert all(mode["slot_conflict"] for mode in data["modes"])
        assert next(slot for slot in data["availability"] if slot["effort"] == "Medium")["state"] == "conflict"
        assert client.put(f"{ENDPOINT}/legacy-copy", json={**legacy, "description": "Preserved"}).status_code == 200
        assert client.post(ENDPOINT, json={"name": "Third Medium", "effort": "Medium"}).status_code == 409
        assert client.put(f"{ENDPOINT}/legacy-copy", json={**legacy, "effort": "schnell"}).status_code == 200
        data = client.get(ENDPOINT).json()
        assert len(data["modes"]) == 2
        assert not any(mode["slot_conflict"] for mode in data["modes"])


def test_simultaneous_creation_cannot_claim_the_same_slot(tmp_path):
    storage = Storage(tmp_path / "state")
    storage.initialize()
    store = ModeStore(storage)
    store.initialize()

    def create(number):
        try:
            store.save(f"concurrent-{number}", ModeDraft(name=f"Concurrent {number}", effort="schnell"),
                       create=True)
            return "created"
        except SlotConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, [1, 2]))
    assert sorted(results) == ["conflict", "created"]
    assert len([mode for mode in store.list_modes() if mode["effort"] == "schnell"]) == 1
