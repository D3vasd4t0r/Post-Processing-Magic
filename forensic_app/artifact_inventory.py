"""Bounded metadata overview of one freshly extracted KAPE ZIP tree.

The groups are filename/path heuristics, not forensic findings about a device.
This module neither opens file contents nor reads the original ZIP archive.
"""

import os
import re
import stat
import time
from datetime import UTC, datetime
from pathlib import Path

MAX_ENTRIES = 500_000
MAX_SECONDS = 10.0
MAX_SAMPLES_PER_GROUP = 5
MAX_SAMPLE_PATH_LENGTH = 240
CLASSIFIER_VERSION = 2

GROUP_LABELS = {
    "evtx": "Windows-Ereignisprotokolle (.evtx)",
    "mft": "MFT ($MFT)",
    "prefetch": "Prefetch (.pf)",
    "registry": "Registry-Hives (bekannte Pfade)",
    "recent": "LNK/Jump Lists (bekannte Benutzerpfade)",
    "srum": "SRUM-Datenbank (Datei gefunden)",
    "recycle_bin": "Papierkorb-Dateien (lokal)",
    "browser_profile": "Browser-Profildaten (bekannte Pfade)",
    "cloud_client": "Cloud-Client-Metadaten (bekannte Pfade)",
    "remote_app": "Fernwartungs-App-Logs (bekannte Pfade)",
    "setupapi": "Geräteinstallationslog",
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


def _windows_parts(parts):
    """Strip a possible KAPE/case prefix, but require a Windows volume root."""
    lowered = tuple(part.casefold() for part in parts)
    roots = {"users", "documents and settings", "windows", "programdata", "program files", "program files (x86)", "$recycle.bin"}
    if lowered and lowered[0] in roots:
        return lowered
    for index, part in enumerate(lowered[:-1]):
        if index > 1:
            break
        if re.fullmatch(r"[a-z]:?", part) and lowered[index + 1] in roots:
            return lowered[index + 1:]
    return ()


def _profile_tail(parts):
    if len(parts) >= 3 and parts[0] in {"users", "documents and settings"}:
        return parts[2:]
    return ()


def _known_windows_group(parts):
    """Classify only path-bound file names, without opening the files."""
    path = _windows_parts(parts)
    if not path:
        return None
    name = path[-1]
    profile = _profile_tail(path)

    if profile[:4] == ("appdata", "roaming", "microsoft", "windows"):
        recent = profile[4:]
        if recent == ("recent", name) and name.endswith(".lnk"):
            return "recent"
        if len(recent) == 3 and recent[0] == "recent":
            if recent[1] == "automaticdestinations" and name.endswith(".automaticdestinations-ms"):
                return "recent"
            if recent[1] == "customdestinations" and name.endswith(".customdestinations-ms"):
                return "recent"
    if (profile[:4] == ("appdata", "roaming", "microsoft", "office")
            and len(profile) == 6 and profile[4] == "recent" and name.endswith(".lnk")):
        return "recent"

    if path == ("windows", "system32", "sru", "srudb.dat"):
        return "srum"
    if (len(path) == 3 and path[0] == "$recycle.bin"
            and re.fullmatch(r"s-1-\d+(?:-\d+)+", path[1])
            and re.fullmatch(r"\$[ir].+", name)):
        return "recycle_bin"

    if (profile[:5] == ("appdata", "roaming", "mozilla", "firefox", "profiles")
            and len(profile) == 7
            and name in {"places.sqlite", "places.sqlite-wal", "places.sqlite-shm"}):
        return "browser_profile"
    chromium_roots = {
        ("google", "chrome"),
        ("microsoft", "edge"),
        ("bravesoftware", "brave-browser"),
    }
    if profile[:2] == ("appdata", "local") and tuple(profile[2:4]) in chromium_roots:
        browser = profile[4:]
        if (len(browser) == 3 and browser[0] == "user data"
                and name in {"history", "history-wal", "history-shm", "bookmarks", "preferences"}):
            return "browser_profile"
        if (len(browser) == 4 and browser[0] == "user data" and browser[2] == "sessions"
                and name.startswith(("session_", "tabs_"))):
            return "browser_profile"

    if (profile[:4] == ("appdata", "local", "google", "drivefs")
            and len(profile) == 6 and name in {
            "metadata_sqlite_db", "metadata_sqlite_db-wal", "metadata_sqlite_db-shm"
        }):
        return "cloud_client"
    if (profile[:4] == ("appdata", "local", "microsoft", "onedrive")
            and len(profile) >= 6 and profile[4] in {"logs", "settings"}):
        return "cloud_client"
    if profile == ("appdata", "local", "dropbox", "info.json"):
        return "cloud_client"

    if profile == ("appdata", "roaming", "anydesk", "connection_trace.txt"):
        return "remote_app"
    if path == ("programdata", "anydesk", "connection_trace.txt"):
        return "remote_app"
    if (len(path) == 3 and path[0] in {"program files", "program files (x86)"}
            and path[1] == "teamviewer" and re.fullmatch(r"connections[^/]*\.txt", name)):
        return "remote_app"

    if path == ("windows", "inf", "setupapi.dev.log"):
        return "setupapi"
    return None


def _group_for(relative):
    parts = relative.parts
    name = parts[-1].casefold()
    specific = _known_windows_group(parts)
    if specific is not None:
        return specific
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
        "classifier_version": CLASSIFIER_VERSION,
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
