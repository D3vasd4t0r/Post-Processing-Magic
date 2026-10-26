"""Bounded direct KAPE file provenance, never a complete dependency resolver.

Only literal Executable scalars and RECmd's literal ``--bn file.reb`` are
recognized. KAPE Modules/bin is the executable base; RECmd batch paths are
relative to that executable's directory. YAML aliases, expansion, shell syntax,
compound modules and other argument grammars are deliberately unresolved.
No file is executed, downloaded, expanded or imported by this module.
"""

import ctypes
import hashlib
import os
import re
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path, PureWindowsPath

MAX_SELECTED = 64
MAX_FILES = 128
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_MODULE_BYTES = 1024 * 1024
MAX_SCAN_ENTRIES = 10_000
MAX_DEPTH = 16
CHUNK_BYTES = 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9_!.-]{1,180}\Z")
_PART = re.compile(r"[A-Za-z0-9_! ().-]{1,180}\Z")
_FIELD = re.compile(r"^\s*(?:-\s*)?(Executable|CommandLine|Modules)\s*:\s*(.*?)\s*$")
_REPARSE = 0x400


class ManifestVerificationError(ValueError):
    """Report a malformed manifest, unavailable captured file or snapshot mismatch."""


# Internal limitation code; callers record partial capture instead of guessing.
class _Unavailable(ValueError):
    pass


def _relative(value):
    """Accept only the narrow literal relative-path grammar used for KAPE references."""
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise _Unavailable("unsafe_path")
    win = PureWindowsPath(value)
    if win.drive or win.root or any(c in value for c in "%${}*?[]:|;&<>\x00"):
        raise _Unavailable("nonliteral_or_external_reference")
    parts = value.replace("\\", "/").split("/")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    if any(not _PART.fullmatch(p) or p in (".", "..") or p.endswith((" ", "."))
           or p.split(".")[0].upper() in reserved for p in parts):
        raise _Unavailable("unsafe_path")
    return Path(*parts)


def _identity(state):
    """Snapshot file identity and modification metadata independently of the content hash."""
    return {"device": state.st_dev, "inode": state.st_ino,
            "mtime_ns": state.st_mtime_ns, "size": state.st_size}


def _safe_state(state, directory=False):
    """Reject observed links/reparse points, unexpected file kinds and multi-link files."""
    if stat.S_ISLNK(state.st_mode) or getattr(state, "st_file_attributes", 0) & _REPARSE:
        raise _Unavailable("link_or_reparse")
    if directory:
        if not stat.S_ISDIR(state.st_mode):
            raise _Unavailable("not_directory")
    elif not stat.S_ISREG(state.st_mode):
        raise _Unavailable("not_regular_file")
    elif state.st_nlink != 1:
        raise _Unavailable("hardlink")


@contextmanager
def _windows_handle(path, directory):
    """Open a Win32 handle excluding deletion and detecting reparse points.

    Directory handles pin ancestors against rename; file handles also exclude
    writers and require one hard link. The yielded handle lives only inside this
    context and is closed on all exit paths.
    """
    from ctypes import wintypes

    class Info(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME),
                    ("accessed", wintypes.FILETIME), ("written", wintypes.FILETIME),
                    ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                    ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(Info)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    flags = 0x00200000 | (0x02000000 if directory else 0x08000000)
    handle = kernel.CreateFileW(str(path), 0x80 if directory else 0x80000000,
                                3 if directory else 1, None, 3, flags, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "manifest_open_failed")
    try:
        info = Info()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise OSError(ctypes.get_last_error(), "manifest_identity_failed")
        if info.attributes & _REPARSE:
            raise _Unavailable("link_or_reparse")
        if bool(info.attributes & 0x10) != directory:
            raise _Unavailable("not_directory" if directory else "not_regular_file")
        if not directory and info.links != 1:
            raise _Unavailable("hardlink")
        yield handle
    finally:
        kernel.CloseHandle(handle)


@contextmanager
def _open_pinned(path, directory=False):
    """Open an absolute path while retaining handles for every ancestor.

    Windows uses pinned handles and a duplicate for the Python file object; the
    non-Windows branch uses descriptor-relative opens with O_NOFOLLOW. Directory
    mode yields no file object and retains only the directory handles.
    """
    with ExitStack() as stack:
        parents = list(reversed(path.parents))
        chain = parents + ([path] if directory else [])
        if os.name == "nt":
            for folder in chain:
                stack.enter_context(_windows_handle(folder, True))
                _safe_state(folder.lstat(), True)
            if directory:
                yield None
            else:
                import msvcrt
                handle = stack.enter_context(_windows_handle(path, False))
                # Duplicate for the Python file object; the original pinned handle
                # remains owned by _windows_handle, including on fdopen failure.
                from ctypes import wintypes
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.GetCurrentProcess.restype = wintypes.HANDLE
                kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                    wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                    wintypes.BOOL, wintypes.DWORD]
                duplicate = wintypes.HANDLE()
                process = kernel.GetCurrentProcess()
                if not kernel.DuplicateHandle(process, handle, process,
                                               ctypes.byref(duplicate), 0, False, 2):
                    raise OSError(ctypes.get_last_error(), "manifest_duplicate_failed")
                try:
                    fd = msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY | os.O_BINARY)
                except OSError:
                    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                    kernel.CloseHandle(duplicate)
                    raise
                with os.fdopen(fd, "rb") as source:
                    yield source
        else:
            parent_fd = None
            for folder in chain:
                fd = os.open(str(folder) if parent_fd is None else folder.name,
                             os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent_fd)
                stack.callback(os.close, fd)
                _safe_state(os.fstat(fd), True)
                parent_fd = fd
            if directory:
                yield None
            else:
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
                with os.fdopen(fd, "rb") as source:
                    yield source


def _read_file(path, maximum, keep=False, budget=None):
    """Hash a pinned regular file under size, aggregate-byte and read-count budgets.

    When keep is true, also return bounded bytes for module-field inspection.
    Compare identity before opening, on the handle and after reading; changed or
    unsupported files become limitations rather than silently captured metadata.
    """
    before = path.lstat()
    _safe_state(before)
    if before.st_size > maximum:
        raise _Unavailable("file_size_limit")
    if budget is not None:
        remaining = MAX_TOTAL_BYTES - budget["bytes"]
        if before.st_size > remaining:
            raise _Unavailable("total_bytes_limit")
        maximum = min(maximum, max(0, remaining))
    with _open_pinned(path) as source:
        state = os.fstat(source.fileno())
        _safe_state(state)
        if _identity(state) != _identity(before):
            raise _Unavailable("file_changed_during_read")
        digest, data, size = hashlib.sha256(), bytearray(), 0
        # Read count as well as total bytes is bounded, including a final EOF read.
        for _ in range(maximum // CHUNK_BYTES + 2):
            chunk = source.read(min(CHUNK_BYTES, maximum - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if budget is not None:
                budget["bytes"] += len(chunk)
                if budget["bytes"] > MAX_TOTAL_BYTES:
                    raise _Unavailable("total_bytes_limit")
            if size > maximum:
                raise _Unavailable("file_size_limit")
            digest.update(chunk)
            if keep:
                data.extend(chunk)
        else:
            raise _Unavailable("read_count_limit")
        after = os.fstat(source.fileno())
        _safe_state(after)
        if size != state.st_size or _identity(after) != _identity(state):
            raise _Unavailable("file_changed_during_read")
        if _identity(path.lstat()) != _identity(state):
            raise _Unavailable("file_changed_during_read")
        return {"sha256": digest.hexdigest(), "size": size,
                "identity": _identity(state)}, bytes(data)


def _scalar(value):
    """Accept the limited one-line scalar syntax, removing a matching outer quote pair."""
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        value = value[1:-1]
    if not value or any(c in value for c in "\"'\n\r\t#&*|>!{}[]"):
        raise _Unavailable("unsupported_scalar")
    return value


def _direct_fields(text):
    """Recognize only block mappings/lists with single-line scalar values.

    This is deliberately not a YAML loader. Reject constructs whose meaning
    would require one, including continuation lines, before discovering paths.
    """
    lines = text.splitlines()
    if len(lines) > 4096:
        raise _Unavailable("module_line_limit")
    fields = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "\t" in line:
            raise _Unavailable("module_grammar_unsupported")
        if stripped == "-":
            continue
        simple = re.fullmatch(r"\s*(?:-\s*)?[A-Za-z][A-Za-z0-9_]*:\s*(.*?)\s*", line)
        if not simple or simple[1].startswith(("|", ">", "&", "*", "!", "{", "[")):
            raise _Unavailable("module_grammar_unsupported")
        match = _FIELD.fullmatch(line)
        if match:
            fields.append(match.groups())
    if not fields:
        raise _Unavailable("module_no_direct_fields")
    return fields


def _module_index(root, budget):
    """Index module basenames within bounded, non-bin Modules subtrees.

    A skipped/unsafe subtree invalidates the index because it may conceal duplicate
    basenames. This scans names and metadata rather than loading YAML.
    """
    found, reasons = {}, []
    pending = [(root / "Modules", 0)]
    while pending:
        folder, depth = pending.pop()
        try:
            with _open_pinned(folder, True), os.scandir(folder) as entries:
                for entry in entries:
                    budget["entries"] += 1
                    if budget["entries"] > MAX_SCAN_ENTRIES:
                        return {}, ["scan_entry_limit"]
                    state = entry.stat(follow_symlinks=False)
                    unsafe = stat.S_ISLNK(state.st_mode) or (
                        getattr(state, "st_file_attributes", 0) & _REPARSE)
                    if unsafe:
                        reasons.append("scan_link_or_reparse")
                        continue
                    if stat.S_ISDIR(state.st_mode):
                        if entry.name.casefold() == "bin" and folder == root / "Modules":
                            continue
                        if depth >= MAX_DEPTH:
                            return {}, ["scan_depth_limit"]
                        pending.append((Path(entry.path), depth + 1))
                    elif entry.name.casefold().endswith(".mkape"):
                        found.setdefault(entry.name[:-6].casefold(), []).append(Path(entry.path))
        except (_Unavailable, OSError):
            reasons.append("scan_unreadable_or_unsafe")
    # A skipped subtree could conceal another module of the same name.
    return ({} if reasons else found), sorted(set(reasons))


def _resolve_literal(root, relative, budget):
    """Resolve case insensitively, one bounded directory level at a time."""
    path = root
    for part in _relative(relative).parts:
        with _open_pinned(path, True), os.scandir(path) as entries:
            matches = []
            for entry in entries:
                budget["entries"] += 1
                if budget["entries"] > MAX_SCAN_ENTRIES:
                    raise _Unavailable("scan_entry_limit")
                if entry.name.casefold() == part.casefold():
                    matches.append(entry.name)
            if len(matches) != 1:
                raise _Unavailable("reference_missing" if not matches else "reference_ambiguous")
            path = path / matches[0]
    return path


def capture_manifest(executable, module_names):
    """Record directly recognized module, helper and RECmd-rule hashes and identities.

    Unsupported grammar, missing files and exhausted budgets become unresolved
    entries. Capture is partial and non-executing: it neither expands compound
    modules nor resolves arbitrary command dependencies or downloads files.
    """
    limits = {"selected": MAX_SELECTED, "files": MAX_FILES,
              "file_bytes": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES,
              "module_bytes": MAX_MODULE_BYTES, "scan_entries": MAX_SCAN_ENTRIES,
              "depth": MAX_DEPTH}
    result = {"schema_version": 1, "scope": "direct_kape_files", "status": "limited",
              "tool_root": "", "files": [], "unresolved": [], "limits": limits,
              "reasons": ["direct_dependencies_only"]}

    def unresolved(selection, reason):
        if len(result["unresolved"]) < MAX_FILES * 2:
            result["unresolved"].append({"selection": str(selection)[:1024], "reason": reason})

    try:
        path = Path(executable)
        if not path.is_absolute():
            raise _Unavailable("tool_root_not_absolute")
        root = Path(os.path.abspath(path.parent))
        result["tool_root"] = str(root)
        with _open_pinned(root, True):
            pass
    except (TypeError, ValueError, OSError) as error:
        unresolved("tool_root", str(error) if isinstance(error, _Unavailable) else "tool_root_unavailable")
        return result
    if isinstance(module_names, str):
        module_names = module_names.split(",", MAX_SELECTED)
    if not isinstance(module_names, (list, tuple)):
        unresolved("modules", "invalid_selection")
        return result
    if len(module_names) > MAX_SELECTED:
        unresolved("modules", "selected_limit")
        module_names = module_names[:MAX_SELECTED]
    budget = {"entries": 0, "bytes": 0}
    index, scan_reasons = _module_index(root, budget)
    for reason in scan_reasons:
        unresolved("Modules", reason)
    total, seen = 0, set()

    def capture(path, category, selection):
        nonlocal total
        relative = path.relative_to(root).as_posix()
        _relative(relative)
        if relative.casefold() in seen:
            return None
        if len(result["files"]) >= MAX_FILES:
            raise _Unavailable("file_count_limit")
        maximum = min(MAX_MODULE_BYTES if category == "module" else MAX_FILE_BYTES,
                      MAX_TOTAL_BYTES - total)
        if maximum <= 0:
            raise _Unavailable("total_bytes_limit")
        metadata, data = _read_file(path, maximum, category == "module", budget)
        total += metadata["size"]
        seen.add(relative.casefold())
        result["files"].append({"relative_path": relative, "category": category,
                                "selection": selection, **metadata})
        return data

    for name in module_names:
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in (".", ".."):
            unresolved(name, "invalid_module_name")
            continue
        key = name[:-6] if name.casefold().endswith(".mkape") else name
        candidates = index.get(key.casefold(), [])
        if len(candidates) != 1:
            unresolved(name, "module_missing" if not candidates else "module_ambiguous")
            continue
        try:
            data = capture(candidates[0], "module", name)
            if data is None:
                continue
            text = data.decode("utf-8-sig")
            fields = _direct_fields(text)
        except UnicodeError:
            unresolved(name, "module_encoding_unsupported")
            continue
        except (_Unavailable, OSError) as error:
            unresolved(name, str(error) if isinstance(error, _Unavailable) else "file_unreadable")
            continue
        helper = None
        for field, value in fields:
            try:
                if field == "Modules":
                    raise _Unavailable("compound_modules_unresolved")
                if field == "Executable":
                    helper = None
                    value = _scalar(value)
                    helper = _resolve_literal(root, "Modules/bin/" + _relative(value).as_posix(), budget)
                    capture(helper, "helper", name)
                elif field == "CommandLine":
                    # This only recognizes a direct RECmd batch scalar; it is
                    # deliberately not Windows command-line or shell parsing.
                    unresolved(name, "command_dependencies_unresolved")
                    if helper is None or helper.name.casefold() != "recmd.exe":
                        continue
                    arguments = _scalar(value).split()
                    positions = [i for i, token in enumerate(arguments) if token == "--bn"]
                    if not positions:
                        continue
                    if len(positions) != 1 or positions[0] + 1 >= len(arguments):
                        raise _Unavailable("rule_reference_ambiguous")
                    rule = arguments[positions[0] + 1]
                    if not rule.casefold().endswith(".reb"):
                        raise _Unavailable("rule_reference_unsupported")
                    relative = helper.parent.relative_to(root) / _relative(rule)
                    capture(_resolve_literal(root, relative.as_posix(), budget), "rule", name)
            except (_Unavailable, OSError) as error:
                unresolved(name, str(error) if isinstance(error, _Unavailable) else "reference_unreadable")
    return result


def verify_manifest(manifest):
    """Recheck only the files and identities frozen in a supported manifest.

    None is the historical no-capture case. Malformed records, unavailable files
    or changed hashes/identities raise ManifestVerificationError. Unresolved
    references remain limitations; new files are not discovered during verification.
    """
    if manifest is None:
        return {"status": "not_captured", "verified_count": 0}
    try:
        if not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or manifest.get("schema_version") != 1:
            raise _Unavailable("manifest_schema_invalid")
        if manifest.get("scope") != "direct_kape_files":
            raise _Unavailable("manifest_scope_invalid")
        root = Path(manifest["tool_root"])
        files = manifest["files"]
        if not isinstance(files, list) or len(files) > MAX_FILES:
            raise _Unavailable("manifest_structure_invalid")
        if files and not root.is_absolute():
            raise _Unavailable("manifest_structure_invalid")
        total, seen = 0, set()
        for entry in files:
            relative = _relative(entry["relative_path"])
            if relative.parts[0].casefold() != "modules":
                raise _Unavailable("manifest_entry_invalid")
            key = relative.as_posix().casefold()
            if key in seen or entry["category"] not in ("module", "helper", "rule"):
                raise _Unavailable("manifest_entry_invalid")
            seen.add(key)
            size = entry["size"]
            if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
                raise _Unavailable("manifest_size_invalid")
            total += size
            if total > MAX_TOTAL_BYTES:
                raise _Unavailable("manifest_total_limit")
            if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
                raise _Unavailable("manifest_hash_invalid")
            metadata, _ = _read_file(root / relative, size)
            if metadata != {key: entry[key] for key in ("size", "sha256", "identity")}:
                raise _Unavailable("captured_file_changed")
        return {"status": "verified", "verified_count": len(files)}
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as error:
        reason = str(error) if isinstance(error, _Unavailable) else "captured_file_unavailable"
        raise ManifestVerificationError(reason) from error
