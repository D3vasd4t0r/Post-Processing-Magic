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


def test_inventory_classifies_extracted_tree_without_reading_contents(tmp_path, monkeypatch):
    root = tmp_path / "Targets"
    _file(root, "C/Windows/System32/winevt/Logs/System.evtx", 11)
    _file(root, "C/$MFT", 12)
    _file(root, "C/Windows/Prefetch/APP-123.PF", 13)
    _file(root, "C/Windows/System32/config/SYSTEM", 14)
    _file(root, "C/Users/Alice/NTUSER.DAT", 15)
    _file(root, "C/Users/Alice/AppData/Local/Microsoft/Windows/UsrClass.dat", 16)
    _file(root, "C/Windows/AppCompat/Programs/Amcache.hve", 17)
    _file(root, "C/Unrelated/SYSTEM", 18)
    _file(root, "C/Unrelated/not-$MFT", 19)
    original_zip = tmp_path / "original.zip"
    original_zip.write_bytes(b"this is not an archive")

    def reject_read(*args, **kwargs):
        raise AssertionError("Inventory must never open file contents")

    monkeypatch.setattr(Path, "open", reject_read)
    result = collect_inventory(root)
    assert result["complete"] and result["source"] == "extracted_zip_tree"
    assert result["files"] == 9 and result["bytes"] == sum(range(11, 20))
    groups = result["groups"]
    assert {key: group["files"] for key, group in groups.items()} == {
        "evtx": 1, "mft": 1, "prefetch": 1, "registry": 4, "other": 2,
    }
    assert groups["registry"]["bytes"] == 14 + 15 + 16 + 17
    assert "kein Nachweis" in result["scope_note"]
    for group in groups.values():
        assert len(group["samples"]) <= 5
        assert all(not Path(sample).is_absolute() and "original.zip" not in sample for sample in group["samples"])


def test_entry_budget_is_partial_and_samples_are_bounded(tmp_path, monkeypatch):
    root = tmp_path / "extracted"
    root.mkdir()
    for index in range(6):
        _file(root, f"sample-{index}.evtx")
    result = collect_inventory(root, max_entries=3, max_samples_per_group=2)
    assert result["entries_scanned"] == 3
    assert result["files"] == 3
    assert not result["complete"] and result["partial_reasons"] == ["entry_limit"]
    assert len(result["groups"]["evtx"]["samples"]) == 2

    monkeypatch.setattr("forensic_app.artifact_inventory.MAX_SAMPLE_PATH_LENGTH", 5)
    result = collect_inventory(root)
    assert result["complete"] and result["groups"]["evtx"]["samples"] == []


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
