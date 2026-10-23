"""Synthetic directory trees only; no user evidence or archive inspection."""

import os
import subprocess
from pathlib import Path

import pytest

from forensic_app.artifact_inventory import GROUP_LABELS, collect_inventory


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
    assert {key: group["files"] for key, group in groups.items() if group["files"]} == {
        "evtx": 1, "mft": 1, "prefetch": 1, "registry": 4, "other": 2,
    }
    assert result["schema_version"] == 1 and result["classifier_version"] == 2
    assert groups["registry"]["bytes"] == 14 + 15 + 16 + 17
    assert "kein Nachweis" in result["scope_note"]
    for group in groups.values():
        assert len(group["samples"]) <= 5
        assert all(not Path(sample).is_absolute() and "original.zip" not in sample for sample in group["samples"])


def test_windows_artifact_groups_are_path_bound_and_disjoint(tmp_path, monkeypatch):
    root = tmp_path / "Targets"
    positives = {
        "recent": [
            "C/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/file.LNK",
            "G/Users/Bob/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/a.automaticDestinations-ms",
            "case/C/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/a.customDestinations-ms",
            "C/Users/Alice/AppData/Roaming/Microsoft/Office/Recent/file.lnk",
        ],
        "srum": ["C/Windows/System32/SRU/SRUDB.dat"],
        "recycle_bin": ["G/$Recycle.Bin/S-1-5-21-123/$Iabc", "C/$Recycle.Bin/S-1-5-21-123/$Rabc"],
        "browser_profile": [
            "C/Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite",
            "C/Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite-wal",
            "C/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History",
            "G/Users/Bob/AppData/Local/Microsoft/Edge/User Data/Profile 1/Bookmarks",
            "case/C/Users/Alice/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Sessions/Session_123",
            "Users/Carol/AppData/Local/Google/Chrome/User Data/Default/Preferences",
        ],
        "cloud_client": [
            "C/Users/Alice/AppData/Local/Google/DriveFS/account/metadata_sqlite_db",
            "C/Users/Alice/AppData/Local/Microsoft/OneDrive/logs/a.odl",
            "C/Users/Alice/AppData/Local/Microsoft/OneDrive/settings/personal/a.ini",
            "G/Users/Bob/AppData/Local/Dropbox/info.json",
        ],
        "remote_app": [
            "C/Users/Alice/AppData/Roaming/AnyDesk/connection_trace.txt",
            "C/ProgramData/AnyDesk/connection_trace.txt",
            "G/Program Files (x86)/TeamViewer/Connections_incoming.txt",
        ],
        "setupapi": ["C/Windows/inf/setupapi.dev.log", "Windows/inf/setupapi.dev.log"],
    }
    negatives = [
        "C/Users/Alice/Desktop/file.lnk",
        "C/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/Nested/file.lnk",
        "C/Windows/Temp/SRUDB.dat",
        "C/$Recycle.Bin/not-a-sid/$Iabc",
        "C/Users/Alice/AppData/Local/OtherApp/Profile/History",
        "C/Users/Alice/AppData/Local/Google/Chrome/History",
        "C/Users/Alice/OneDrive/History",
        "C/Users/Alice/Google Drive/info.json",
        "C/Users/Alice/AppData/Local/Dropbox/other.json",
        "C/Users/Alice/AppData/Roaming/AnyDesk/other.txt",
        "C/Program Files/Other/connections.txt",
        "C/Windows/Temp/setupapi.dev.log",
        "C/Archive/Windows/inf/setupapi.dev.log",
        "C/Archive/G/Windows/inf/setupapi.dev.log",
    ]
    all_paths = [path for paths in positives.values() for path in paths] + negatives
    for index, path in enumerate(all_paths):
        _file(root, path, index + 1)

    def reject_read(*args, **kwargs):
        raise AssertionError("Inventory must not open evidence contents")

    monkeypatch.setattr(Path, "open", reject_read)
    result = collect_inventory(root, max_samples_per_group=2)
    assert result["complete"]
    assert result["files"] == len(all_paths)
    assert result["bytes"] == sum(range(1, len(all_paths) + 1))
    assert set(result["groups"]) == set(GROUP_LABELS)
    for group_id, paths in positives.items():
        assert result["groups"][group_id]["files"] == len(paths)
        assert len(result["groups"][group_id]["samples"]) == min(2, len(paths))
    assert result["groups"]["other"]["files"] == len(negatives)
    assert sum(group["files"] for group in result["groups"].values()) == result["files"]
    assert sum(group["bytes"] for group in result["groups"].values()) == result["bytes"]


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
