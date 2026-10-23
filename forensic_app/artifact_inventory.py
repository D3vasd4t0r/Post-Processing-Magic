"""Bounded metadata overview of one freshly extracted KAPE ZIP tree.

The groups are filename/path heuristics, not forensic findings about a device.
This module neither opens file contents nor reads the original ZIP archive.
"""

import os
import stat
import time
from datetime import UTC, datetime
from pathlib import Path

MAX_ENTRIES = 500_000
MAX_SECONDS = 10.0
MAX_SAMPLES_PER_GROUP = 5
MAX_SAMPLE_PATH_LENGTH = 240

GROUP_LABELS = {
    "evtx": "Windows-Ereignisprotokolle (.evtx)",
    "mft": "MFT ($MFT)",
    "prefetch": "Prefetch (.pf)",
    "registry": "Registry-Hives (bekannte Pfade)",
    "other": "Weitere Dateien",
}


def _is_link_or_reparse(info):
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _registry_path(parts):
    """Recognize a few conventional Windows hive locations, not every hive."""
    lowered = tuple(part.casefold() for part in parts)
    name = lowered[-1]
    if name in {"system", "software", "sam", "security", "default"}:
        return lowered[-4:-1] == ("windows", "system32", "config")
    if name == "amcache.hve":
        return lowered[-4:-1] == ("windows", "appcompat", "programs")
    if name == "ntuser.dat":
        return any(
            lowered[index] in {"users", "documents and settings"}
            and index + 2 == len(lowered) - 1
            for index in range(len(lowered) - 2)
        )
    if name == "usrclass.dat":
        return lowered[-5:-1] == ("appdata", "local", "microsoft", "windows") and any(
            lowered[index] in {"users", "documents and settings"}
            for index in range(len(lowered) - 5)
        )
    return False


def _group_for(relative):
    parts = relative.parts
    name = parts[-1].casefold()
    if name == "$mft":
        return "mft"
    if name.endswith(".evtx"):
        return "evtx"
    if name.endswith(".pf"):
        return "prefetch"
    if _registry_path(parts):
        return "registry"
    return "other"


def collect_inventory(
    extracted_root: Path,
    *,
    check=None,
    max_entries: int = MAX_ENTRIES,
    max_seconds: float = MAX_SECONDS,
    max_samples_per_group: int = MAX_SAMPLES_PER_GROUP,
):
    """Return a JSON-ready snapshot of regular files under ``extracted_root``.

    ``check`` is the worker's optional cancellation callback. Its exception is
    propagated so cancellation cannot be misreported as a partial inventory.
    A skipped link, unreadable entry, or budget limit makes ``complete`` false.
    """
    root = Path(extracted_root)
    if max_entries < 1 or max_seconds <= 0 or max_samples_per_group < 0:
        raise ValueError("Inventory limits must be positive (sample limit may be zero).")
    root_info = root.lstat()
    if _is_link_or_reparse(root_info) or not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("Inventory root must be a regular directory without a link or reparse point.")

    groups = {
        key: {"label": label, "files": 0, "bytes": 0, "samples": []}
        for key, label in GROUP_LABELS.items()
    }
    result = {
        "schema_version": 1,
        "source": "extracted_zip_tree",
        "scope_note": (
            "Heuristische Übersicht der im entpackten ZIP erfassten Dateien; "
            "kein Nachweis für Vorhandensein oder Fehlen auf dem ursprünglichen Gerät."
        ),
        "measured_at": datetime.now(UTC).isoformat(),
        "complete": True,
        "partial_reasons": [],
        "entries_scanned": 0,
        "directories": 0,
        "files": 0,
        "bytes": 0,
        "skipped_links": 0,
        "errors": 0,
        "groups": groups,
    }
    reasons = set()
    started = time.monotonic()
    pending = [(root, Path())]
    while pending:
        if check is not None:
            check()
        if result["entries_scanned"] >= max_entries:
            reasons.add("entry_limit")
            break
        if time.monotonic() - started >= max_seconds:
            reasons.add("time_limit")
            break
        folder, relative_folder = pending.pop()
        try:
            folder_info = folder.lstat()
            if _is_link_or_reparse(folder_info):
                result["skipped_links"] += 1
                reasons.add("link_skipped")
                continue
            if not stat.S_ISDIR(folder_info.st_mode):
                result["errors"] += 1
                reasons.add("entry_error")
                continue
            with os.scandir(folder) as entries:
                for entry in entries:
                    if check is not None:
                        check()
                    if result["entries_scanned"] >= max_entries:
                        reasons.add("entry_limit")
                        break
                    if time.monotonic() - started >= max_seconds:
                        reasons.add("time_limit")
                        break
                    result["entries_scanned"] += 1
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if _is_link_or_reparse(info):
                            result["skipped_links"] += 1
                            reasons.add("link_skipped")
                        elif stat.S_ISDIR(info.st_mode):
                            result["directories"] += 1
                            pending.append((Path(entry.path), relative_folder / entry.name))
                        elif stat.S_ISREG(info.st_mode):
                            relative = relative_folder / entry.name
                            group = groups[_group_for(relative)]
                            group["files"] += 1
                            group["bytes"] += info.st_size
                            result["files"] += 1
                            result["bytes"] += info.st_size
                            sample = relative.as_posix()
                            if len(group["samples"]) < max_samples_per_group and len(sample) <= MAX_SAMPLE_PATH_LENGTH:
                                group["samples"].append(sample)
                        else:
                            result["errors"] += 1
                            reasons.add("special_file")
                    except OSError:
                        result["errors"] += 1
                        reasons.add("entry_error")
        except OSError:
            result["errors"] += 1
            reasons.add("directory_error")
        if "entry_limit" in reasons or "time_limit" in reasons:
            break
    result["partial_reasons"] = sorted(reasons)
    result["complete"] = not reasons
    return result
