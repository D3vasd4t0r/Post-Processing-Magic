"""Synthetic directory trees only; no user evidence or archive inspection."""

import os
import subprocess
from pathlib import Path

import pytest

from forensic_app.artifact_inventory import collect_inventory


def _file(root, relative, size=1):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    return path


def test_inventory_records_only_paths_sizes_and_counts_without_reading_contents(tmp_path, monkeypatch):
    root = tmp_path / "Targets"
    _file(root, "C/Windows/System.evtx", 11)
    _file(root, "C/$MFT", 12)
    _file(root, "C/Users/own.csv", 13)
    def reject_read(*args, **kwargs):
        raise AssertionError("Inventory must never open file contents")
    monkeypatch.setattr(Path, "open", reject_read)
    result = collect_inventory(root)
    assert result["complete"] and result["source"] == "extracted_zip_tree"
    assert result["schema_version"] == 2
    assert result["files"] == 3 and result["bytes"] == 36
    assert result["directories"] == 3
    assert "groups" not in result and "classifier_version" not in result
    assert sorted(result["files_metadata"],key=lambda item:item['path']) == [
        {"path":"C/$MFT","bytes":12}, {"path":"C/Users/own.csv","bytes":13}, {"path":"C/Windows/System.evtx","bytes":11}]
    assert set(result['directory_paths']) == {'C','C/Windows','C/Users'}


def test_entry_and_path_budgets_are_explicit(tmp_path, monkeypatch):
    root=tmp_path/'extracted';root.mkdir()
    for index in range(6):
        _file(root,f'sample-{index}.evtx')
    result=collect_inventory(root,max_entries=3,max_file_paths=2)
    assert result['entries_scanned']==3 and result['files']==3
    assert not result['complete'] and result['partial_reasons']==['entry_limit']
    assert result['paths_truncated'] and len(result['files_metadata'])==2
    monkeypatch.setattr('forensic_app.artifact_inventory.MAX_PATH_LENGTH',5)
    result=collect_inventory(root)
    assert result['complete'] and result['paths_truncated'] and result['files_metadata']==[]
    assert result['files']==6


def test_time_budget_and_cancellation_are_distinct(tmp_path, monkeypatch):
    root = tmp_path / "extracted"
    root.mkdir()
    _file(root, "one.evtx")
    ticks = iter((0.0, 1.0))
    with monkeypatch.context() as patch:
        patch.setattr("forensic_app.artifact_inventory.time.monotonic", lambda: next(ticks))
        result = collect_inventory(root, max_seconds=0.5)
    assert not result["complete"] and result["partial_reasons"] == ["time_limit"]

    def canceled():
        raise RuntimeError("job canceled")

    with pytest.raises(RuntimeError, match="job canceled"):
        collect_inventory(root, check=canceled)


def test_unreadable_directory_is_partial(tmp_path, monkeypatch):
    root = tmp_path / "extracted"
    _file(root, "Unreadable/one.evtx")
    original = os.scandir

    def denied(path):
        if Path(path) == root / "Unreadable":
            raise PermissionError("synthetic denial")
        return original(path)

    monkeypatch.setattr("forensic_app.artifact_inventory.os.scandir", denied)
    result = collect_inventory(root)
    assert not result["complete"]
    assert result["errors"] == 1
    assert result["partial_reasons"] == ["directory_error"]


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_junction_is_not_followed(tmp_path):
    root = tmp_path / "extracted"
    root.mkdir()
    outside = tmp_path / "outside"
    _file(outside, "secret.evtx", 999)
    link = root / "redirect"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
        check=False, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert created.returncode == 0, created.stderr
    result = collect_inventory(root)
    assert not result["complete"]
    assert result["skipped_links"] == 1 and result["files"] == 0
    assert result["partial_reasons"] == ["link_skipped"]


def test_root_must_be_real_directory(tmp_path):
    file = tmp_path / "plain.txt"
    file.write_bytes(b"synthetic")
    with pytest.raises(ValueError, match="regular directory"):
        collect_inventory(file)
