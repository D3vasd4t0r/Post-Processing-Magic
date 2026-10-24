"""All files are self-created placeholders; no installed KAPE is inspected."""

import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic_app import kape_manifest as km


@pytest.fixture
def pack(tmp_path):
    root = tmp_path / "KAPE"
    (root / "Modules" / "EZTools").mkdir(parents=True)
    (root / "Modules" / "bin" / "RECmd" / "BatchExamples").mkdir(parents=True)
    (root / "kape.exe").write_bytes(b"SYNTHETIC NEVER EXECUTABLE")
    (root / "Modules" / "bin" / "RECmd" / "RECmd.exe").write_bytes(b"helper")
    (root / "Modules" / "bin" / "RECmd" / "BatchExamples" / "Own.reb").write_bytes(b"rule")
    module = root / "Modules" / "EZTools" / "Own.mkape"
    module.write_text(
        "Description: Synthetic module\nProcessors:\n    -\n"
        "        Executable: RECmd\\RECmd.exe\n"
        "        CommandLine: -d %sourceDirectory% --bn BatchExamples\\Own.reb "
        "--csv %destinationDirectory%\n", encoding="utf-8")
    return root


def capture(pack, names="Own"):
    return km.capture_manifest(pack / "kape.exe", names)


def reasons(manifest):
    return {entry["reason"] for entry in manifest["unresolved"]}


def test_capture_direct_module_helper_and_rule_then_verify(pack):
    manifest = capture(pack)
    assert manifest["schema_version"] == 1
    assert manifest["status"] == "limited"
    assert manifest["reasons"] == ["direct_dependencies_only"]
    assert [entry["category"] for entry in manifest["files"]] == ["module", "helper", "rule"]
    for entry in manifest["files"]:
        data = (pack / entry["relative_path"]).read_bytes()
        assert entry["size"] == len(data)
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
        assert entry["identity"]["inode"]
    # JSON round trip preserves exactly what the immutable job can store.
    assert km.verify_manifest(json.loads(json.dumps(manifest))) == {
        "status": "verified", "verified_count": 3}
    assert "command_dependencies_unresolved" in reasons(manifest)


def test_case_insensitive_module_and_references(pack):
    module = pack / "Modules" / "EZTools" / "Own.mkape"
    module.write_text("Processors:\n - Executable: recmd\\recmd.EXE\n"
                      "   CommandLine: --bn batchexamples\\own.REB\n", encoding="utf-8")
    manifest = capture(pack, ["oWn"])
    assert len(manifest["files"]) == 3


def test_deduplicated_selected_and_captured_files(pack):
    manifest = capture(pack, "Own,own,Own.mkape")
    assert len(manifest["files"]) == 3


def test_missing_module_does_not_block_and_is_not_rediscovered(pack):
    manifest = capture(pack, "Absent")
    assert reasons(manifest) == {"module_missing"}
    # Verify must not start a fresh walk or capture a newly installed file.
    (pack / "Modules" / "Absent.mkape").write_bytes(b"new")
    assert km.verify_manifest(manifest)["verified_count"] == 0


def test_ambiguous_module_is_explicit(pack):
    (pack / "Modules" / "Own.mkape").write_bytes(b"ambiguous")
    manifest = capture(pack)
    assert not manifest["files"]
    assert "module_ambiguous" in reasons(manifest)


@pytest.mark.parametrize("name", ["..", "../Own", r"a\Own", "C:Own", "%Own%", "$Own", ""])
def test_unsafe_selection_names_never_read(pack, name):
    manifest = capture(pack, [name])
    assert "invalid_module_name" in reasons(manifest)
    assert not manifest["files"]


@pytest.mark.parametrize("value", [r"..\..\outside.exe", r"C:\outside.exe",
                                  r"\\server\share\a.exe", "%kapeDirectory%\\a.exe",
                                  "$tool", "a.exe:ads", "NUL", "a..\\..\\outside.exe"])
def test_nonliteral_or_unsafe_executables_are_unresolved(pack, value):
    (pack / "Modules" / "EZTools" / "Own.mkape").write_text(
        f"Processors:\n - Executable: {value}\n", encoding="utf-8")
    manifest = capture(pack)
    assert [entry["category"] for entry in manifest["files"]] == ["module"]
    assert manifest["unresolved"]
    assert km.verify_manifest(manifest)["verified_count"] == 1


def test_missing_helper_is_unresolved_and_nonblocking(pack):
    (pack / "Modules" / "bin" / "RECmd" / "RECmd.exe").unlink()
    manifest = capture(pack)
    assert "reference_missing" in reasons(manifest)
    assert km.verify_manifest(manifest)["verified_count"] == 1


@pytest.mark.parametrize("text,reason", [
    ("Processors:\n - Executable: [a, b]\n", "module_grammar_unsupported"),
    ("Description: |\n  Executable: trick.exe\n", "module_grammar_unsupported"),
    ("Processors: *alias\n", "module_grammar_unsupported"),
    ("Description: Empty\n", "module_no_direct_fields"),
    ("", "module_no_direct_fields"),
    ("Modules:\n", "compound_modules_unresolved"),
])
def test_unsupported_module_grammar_is_explicit(pack, text, reason):
    (pack / "Modules" / "EZTools" / "Own.mkape").write_text(text, encoding="utf-8")
    manifest = capture(pack)
    assert reason in reasons(manifest)
    assert len(manifest["files"]) == 1


@pytest.mark.parametrize("reference", ["--bn %rule%", "--bn ../escape.reb", "--bn a.reb --bn b.reb",
                                       '--bn "BatchExamples\\Own.reb"', "--bn foo.txt", "--bn"])
def test_nonliteral_or_ambiguous_rule_is_explicit(pack, reference):
    (pack / "Modules" / "EZTools" / "Own.mkape").write_text(
        f"Processors:\n - Executable: RECmd\\RECmd.exe\n   CommandLine: {reference}\n",
        encoding="utf-8")
    manifest = capture(pack)
    assert len(manifest["files"]) == 2
    assert reasons(manifest) - {"command_dependencies_unresolved"}


@pytest.mark.parametrize("category", ["module", "helper", "rule"])
def test_changed_captured_file_blocks(pack, category):
    manifest = capture(pack)
    entry = next(entry for entry in manifest["files"] if entry["category"] == category)
    path = pack / entry["relative_path"]
    data = path.read_bytes()
    path.write_bytes(b"X" * len(data))
    # Even restoring timestamps cannot hide the changed hash.
    os.utime(path, ns=(entry["identity"]["mtime_ns"], entry["identity"]["mtime_ns"]))
    with pytest.raises(km.ManifestVerificationError, match="captured_file_changed"):
        km.verify_manifest(manifest)


def test_missing_captured_file_blocks(pack):
    manifest = capture(pack)
    (pack / manifest["files"][0]["relative_path"]).unlink()
    with pytest.raises(km.ManifestVerificationError, match="captured_file_unavailable"):
        km.verify_manifest(manifest)


def test_replaced_identical_file_blocks(pack):
    manifest = capture(pack)
    entry = manifest["files"][-1]
    path = pack / entry["relative_path"]
    other = path.with_suffix(".new")
    other.write_bytes(path.read_bytes())
    os.utime(other, ns=(entry["identity"]["mtime_ns"], entry["identity"]["mtime_ns"]))
    os.replace(other, path)
    with pytest.raises(km.ManifestVerificationError, match="captured_file_changed"):
        km.verify_manifest(manifest)


def test_hardlinks_rejected_at_capture_and_verify(pack):
    helper = pack / "Modules" / "bin" / "RECmd" / "RECmd.exe"
    manifest = capture(pack)
    os.link(helper, pack / "hardlinked.exe")
    assert "hardlink" in reasons(capture(pack))
    with pytest.raises(km.ManifestVerificationError, match="hardlink"):
        km.verify_manifest(manifest)


def test_file_and_directory_reparse_states_rejected():
    for mode, directory in [(0o100644, False), (0o40755, True)]:
        with pytest.raises(ValueError, match="link_or_reparse"):
            km._safe_state(SimpleNamespace(st_mode=mode, st_file_attributes=0x400), directory)


def test_symlink_rejected_when_platform_allows(pack):
    link = pack / "Modules" / "OwnLink.mkape"
    try:
        link.symlink_to(pack / "Modules" / "EZTools" / "Own.mkape")
    except OSError:
        pytest.skip("Windows symlink creation privilege unavailable")
    manifest = capture(pack)
    assert not manifest["files"]
    assert "scan_link_or_reparse" in reasons(manifest)


def test_toctou_replacement_between_stat_and_open(pack, monkeypatch):
    target = pack / "Modules" / "EZTools" / "Own.mkape"
    original = km._open_pinned
    replaced = False

    @contextmanager
    def replaced_open(path, directory=False):
        nonlocal replaced
        if path == target and not directory and not replaced:
            replaced = True
            other = target.with_suffix(".new")
            other.write_bytes(target.read_bytes())
            os.replace(other, target)
        with original(path, directory) as source:
            yield source

    monkeypatch.setattr(km, "_open_pinned", replaced_open)
    manifest = capture(pack)
    assert "file_changed_during_read" in reasons(manifest)
    assert not manifest["files"]


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing contract")
def test_windows_handle_blocks_write_delete_and_ancestor_rename(pack):
    target = pack / "Modules" / "EZTools" / "Own.mkape"
    with km._open_pinned(target) as source:
        assert source.read(10)
        with pytest.raises(OSError):
            target.write_bytes(b"replaced")
        with pytest.raises(OSError):
            target.unlink()
        with pytest.raises(OSError):
            target.parent.rename(target.parent.with_name("renamed"))


def test_unreadable_module_and_reference_are_explicit(pack, monkeypatch):
    original = km._read_file

    def unavailable(path, *args, **kwargs):
        if path.name.casefold() == "recmd.exe":
            raise PermissionError("synthetic access denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(km, "_read_file", unavailable)
    manifest = capture(pack)
    assert "reference_unreadable" in reasons(manifest)
    assert len(manifest["files"]) <= 2


def test_size_and_count_limits_are_explicit(pack, monkeypatch):
    monkeypatch.setattr(km, "MAX_FILE_BYTES", 3)
    assert "file_size_limit" in reasons(capture(pack))
    monkeypatch.setattr(km, "MAX_FILES", 1)
    assert "file_count_limit" in reasons(capture(pack))


def test_module_size_limit(pack, monkeypatch):
    monkeypatch.setattr(km, "MAX_MODULE_BYTES", 10)
    manifest = capture(pack)
    assert not manifest["files"]
    assert "file_size_limit" in reasons(manifest)


def test_total_scan_and_selection_limits(pack, monkeypatch):
    monkeypatch.setattr(km, "MAX_SELECTED", 1)
    assert "selected_limit" in reasons(capture(pack, ["Own", "Absent"]))
    monkeypatch.setattr(km, "MAX_SCAN_ENTRIES", 1)
    assert "scan_entry_limit" in reasons(capture(pack))


def test_total_hash_budget(pack, monkeypatch):
    module = pack / "Modules" / "EZTools" / "Own.mkape"
    monkeypatch.setattr(km, "MAX_TOTAL_BYTES", module.stat().st_size)
    manifest = capture(pack)
    assert "total_bytes_limit" in reasons(manifest)
    assert [entry["category"] for entry in manifest["files"]] == ["module"]


def test_non_utf8_module_still_has_hash_with_explicit_unknown(pack):
    (pack / "Modules" / "EZTools" / "Own.mkape").write_bytes(b"\xff\xfe\x00")
    manifest = capture(pack)
    assert "module_encoding_unsupported" in reasons(manifest)
    assert len(manifest["files"]) == 1


def test_no_manifest_historical_noop_and_unknown_schema_blocked():
    assert km.verify_manifest(None) == {"status": "not_captured", "verified_count": 0}
    for invalid in [{}, {"schema_version": 99}, [], "bad"]:
        with pytest.raises(km.ManifestVerificationError):
            km.verify_manifest(invalid)


@pytest.mark.parametrize("relative", ["../outside", "C:/outside", "Modules/a:ads", "foo"])
def test_corrupt_manifest_paths_blocked_without_read(pack, relative, monkeypatch):
    manifest = capture(pack)
    manifest["files"][0]["relative_path"] = relative

    def forbidden(*args, **kwargs):
        pytest.fail("unsafe manifest path was read")

    monkeypatch.setattr(km, "_read_file", forbidden)
    with pytest.raises(km.ManifestVerificationError):
        km.verify_manifest(manifest)


def test_invalid_root_capture_remains_nonblocking():
    manifest = km.capture_manifest(Path("relative") / "kape.exe", ["Own"])
    assert "tool_root_not_absolute" in reasons(manifest)
    assert km.verify_manifest(manifest)["verified_count"] == 0


def test_scan_depth_limit_is_explicit(pack, monkeypatch):
    monkeypatch.setattr(km, "MAX_DEPTH", 0)
    manifest = capture(pack)
    assert "scan_depth_limit" in reasons(manifest)
    assert not manifest["files"]


def test_hash_read_count_limit_is_bounded(pack, monkeypatch):
    original = km._open_pinned
    target = pack / "Modules" / "EZTools" / "Own.mkape"
    reads = []

    class ShortReads:
        def __init__(self, source):
            self.source = source

        def fileno(self):
            return self.source.fileno()

        def read(self, count):
            reads.append(count)
            return self.source.read(1)

    @contextmanager
    def short_open(path, directory=False):
        with original(path, directory) as source:
            yield ShortReads(source) if path == target and not directory else source

    monkeypatch.setattr(km, "_open_pinned", short_open)
    manifest = capture(pack)
    assert "read_count_limit" in reasons(manifest)
    assert len(reads) == km.MAX_MODULE_BYTES // km.CHUNK_BYTES + 2
    assert not manifest["files"]


def test_mutation_during_read_is_rejected(pack, monkeypatch):
    original_fstat = km.os.fstat
    calls = 0

    def changed_fstat(descriptor):
        nonlocal calls
        state = original_fstat(descriptor)
        if os.name != "nt" and not km.stat.S_ISREG(state.st_mode):
            return state
        calls += 1
        if calls != 2:
            return state
        return SimpleNamespace(st_mode=state.st_mode, st_nlink=state.st_nlink,
            st_dev=state.st_dev, st_ino=state.st_ino, st_size=state.st_size,
            st_mtime_ns=state.st_mtime_ns + 1)

    monkeypatch.setattr(km.os, "fstat", changed_fstat)
    manifest = capture(pack)
    assert "file_changed_during_read" in reasons(manifest)
    assert not manifest["files"]


def test_unreadable_directory_keeps_uncertainty_open(pack, monkeypatch):
    original = km._open_pinned

    @contextmanager
    def denied(path, directory=False):
        if directory and path.name == "EZTools":
            raise PermissionError("synthetic denied directory")
        with original(path, directory) as source:
            yield source

    monkeypatch.setattr(km, "_open_pinned", denied)
    manifest = capture(pack)
    assert "scan_unreadable_or_unsafe" in reasons(manifest)
    assert not manifest["files"]


@pytest.mark.parametrize("field,value", [("schema_version", 2), ("scope", "other"),
                                       ("files", "bad"), ("tool_root", "relative")])
def test_malformed_manifest_top_level_blocks(pack, field, value):
    manifest = capture(pack)
    manifest[field] = value
    with pytest.raises(km.ManifestVerificationError):
        km.verify_manifest(manifest)


@pytest.mark.parametrize("field,value", [("size", -1), ("size", True), ("sha256", "bad"),
                                       ("category", "unknown"), ("identity", None)])
def test_malformed_manifest_entry_blocks(pack, field, value):
    manifest = capture(pack)
    manifest["files"][0][field] = value
    with pytest.raises(km.ManifestVerificationError):
        km.verify_manifest(manifest)


def test_manifest_limits_cannot_weaken_verification_limits(pack, monkeypatch):
    manifest = capture(pack)
    manifest["limits"]["file_bytes"] = 10**100
    monkeypatch.setattr(km, "MAX_FILE_BYTES", 1)
    with pytest.raises(km.ManifestVerificationError, match="manifest_size_invalid"):
        km.verify_manifest(manifest)
