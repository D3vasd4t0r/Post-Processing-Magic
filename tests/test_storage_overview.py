import subprocess
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.storage import Storage
from forensic_app.storage_overview import StorageOverview


@pytest.fixture
def data(tmp_path):
    storage = Storage(tmp_path/'state')
    storage.initialize()
    (storage.root/'evidence'/'own.zip').write_bytes(b'x'*123)
    (storage.root/'work'/'job'/'Results').mkdir(parents=True)
    (storage.root/'work'/'job'/'Results'/'own.txt').write_bytes(b'y'*456)
    (storage.root/'results'/'own-result.zip').write_bytes(b'z'*789)
    (tmp_path/'external-local-evidence.zip').write_bytes(b'e'*999)
    return storage


def test_sizes_metadata_only_and_no_external_inputs(data, monkeypatch):
    overview = StorageOverview(data)
    assert overview.get()['scan'] is None

    def reject_read(*args, **kwargs):
        raise AssertionError('Evidence contents must never be opened')

    monkeypatch.setattr(Path, 'open', reject_read)
    result = overview.scan()
    scan = result['scan']
    assert scan['complete'] and scan['bytes'] == 123+456+789
    assert [area['bytes'] for area in scan['areas']] == [123,456,789]
    assert [area['files'] for area in scan['areas']] == [1,1,1]
    assert scan['areas'][1]['directories'] == 2
    assert result['volume']['free_bytes'] >= 0
    assert overview.get()['scan'] == scan


def test_api_authorized_and_get_does_not_measure(data):
    with TestClient(create_app(data,'storage-test'),base_url='http://127.0.0.1') as client:
        for method,path in ((client.get,'/api/settings/storage'),(client.post,'/api/settings/storage/scan')):
            assert method(path).status_code == 401
        client.headers['Authorization'] = 'Bearer storage-test'
        assert client.get('/api/settings/storage').json()['scan'] is None
        result = client.post('/api/settings/storage/scan').json()
        assert result['scan']['bytes'] == 1368
        assert client.get('/api/settings/storage').json()['scan'] == result['scan']


def test_budget_marks_partial_results(data, monkeypatch):
    monkeypatch.setattr('forensic_app.storage_overview.MAX_ENTRIES', 1)
    scan = StorageOverview(data).scan()['scan']
    assert not scan['complete']
    assert any(not area['complete'] for area in scan['areas'])


def test_time_budget_and_busy_scan(data, monkeypatch):
    overview = StorageOverview(data)
    monkeypatch.setattr('forensic_app.storage_overview.MAX_SECONDS', 0)
    assert not overview.scan()['scan']['complete']
    overview.lock.acquire()
    try:
        with pytest.raises(HTTPException) as error:
            overview.scan()
        assert error.value.status_code == 409
    finally:
        overview.lock.release()


def test_junctions_are_skipped_instead_of_counting_other_locations(data, tmp_path):
    outside = tmp_path/'outside'
    outside.mkdir()
    (outside/'do-not-count.txt').write_bytes(b'o'*10000)
    link = data.root/'work'/'redirect'
    result = subprocess.run(['cmd','/c','mklink','/J',str(link),str(outside)],
                            check=False,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr
    scan = StorageOverview(data).scan()['scan']
    assert scan['bytes'] == 1368 and scan['skipped_links'] == 1


def test_unreadable_directory_is_reported(data, monkeypatch):
    import os
    original = os.scandir

    def denied(path):
        if Path(path) == data.root/'work':
            raise PermissionError('Own simulated denial')
        return original(path)

    monkeypatch.setattr('forensic_app.storage_overview.os.scandir',denied)
    scan = StorageOverview(data).scan()['scan']
    assert not scan['complete'] and scan['errors'] == 1
    assert scan['bytes'] == 123+789
