"""Preflight Windows ZIP paths and limits before bounded extraction.

Extraction creates a fresh destination; nested archive files remain data. High
compression changes the ratio gate only, retaining name, entry-count, expanded
byte and initial free-space checks.
"""

import os
import shutil
import stat
import struct
from pathlib import Path, PureWindowsPath
from zipfile import ZipFile

from forensic_app.app_errors import AppValueError

MAX_FILES = 200_000
MAX_EXTRACTED = 2_000_000_000_000
MAX_RATIO = 1000
DISK_RESERVE = 512 * 1024**2


def ensure_space(root: Path, size: int = 0):
    """Require free bytes for the requested size plus the fixed application reserve."""
    free = shutil.disk_usage(root).free
    if free < size + DISK_RESERVE:
        raise AppValueError('error.316c93db774f', p0=f'{root.anchor}', p1=f'{free / 1024 ** 3:.2f}', p2=f'{(size + DISK_RESERVE) / 1024 ** 3:.2f}')


def bounded_directory(path: Path):
    # Bound ZipFile's initial central-directory allocation, including ZIP64.
    """Inspect end records before ZipFile allocates its central directory.

    Bound advertised entry count and directory bytes, including ZIP64, and reject
    unsupported multi-disk/end-record layouts. Member contents are not read here.
    """
    with path.open("rb") as source:
        source.seek(0, 2)
        length = source.tell()
        source.seek(max(0, length - 65557))
        tail = source.read()
        offset = tail.rfind(b"PK\x05\x06")
        if offset < 0 or len(tail)-offset < 22:
            raise AppValueError('error.d8b7d9bf13e4')
        end = struct.unpack_from("<4s4H2IH", tail, offset)
        if end[1] or end[2] or end[3] != end[4] or len(tail)-offset != 22+end[7]:
            raise AppValueError('error.55a7b5f87d00')
        count, size = end[4], end[5]
        if count == 65535 or size == 0xffffffff:
            eocd = length-len(tail)+offset
            if eocd < 20:
                raise AppValueError('error.d95b9f7e8a90')
            source.seek(eocd-20)
            locator = struct.unpack("<4sIQI", source.read(20))
            if locator[0] != b"PK\x06\x07" or locator[1] or locator[3] != 1:
                raise AppValueError('error.138af3d3d2e5')
            source.seek(locator[2])
            data = source.read(56)
            if len(data) != 56:
                raise AppValueError('error.f58fd15fef4e')
            record = struct.unpack("<4sQ2H2I4Q", data)
            if record[0] != b"PK\x06\x06" or record[4] or record[5] or record[6] != record[7]:
                raise AppValueError('error.39c4e4eac91a')
            count, size = record[7], record[8]
        if count > MAX_FILES or size > 64*1024**2:
            raise AppValueError('error.d8da2033d277')


def safe_name(info) -> Path:
    """Return a host-relative path for a permitted Windows ZIP member name.

    Reject rooted/traversal/ADS/reserved names, excessive depth/length, unsupported
    entry kinds and encrypted members. This validates an archive member rather
    than an existing host filesystem location.
    """
    name = info.orig_filename
    path = PureWindowsPath(name)
    if ("\x00" in name or path.drive or path.root or not path.parts or
            any(part in ("", ".", "..") for part in name.replace("\\", "/").rstrip("/").split("/"))):
        raise AppValueError('error.e1292ea9b06d', p0=f'{name!r}')
    if len(path.parts) > 64 or len(name) > 240:
        raise AppValueError('error.71012bb39a62')
    for part in path.parts:
        if (any(ord(char) < 32 or char in '<>:"|?*' for char in part)
                or part.endswith((".", " ")) or PureWindowsPath(part).is_reserved()):
            raise AppValueError('error.802d72f4fda6', p0=f'{name!r}')
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or info.external_attr & 0x400:
        raise AppValueError('error.587693dfcf3d')
    if info.flag_bits & 1:
        raise AppValueError('error.676c1ee6c8e8')
    return Path(*path.parts)


def extract_checked(archive: Path, target: Path, check, report, *, allow_high_compression: bool = False, max_extract_bytes: int = MAX_EXTRACTED):
    """Preflight every member before creating a fresh extraction tree.

    Check case-insensitive duplicates, file/directory collisions, sizes, ratio and
    initial disk space. Stream bounded chunks and verify actual byte counts;
    callbacks provide cancellation and real status. Input ZIP and member names
    remain unchanged; nested archives are not recursively extracted.
    """
    bounded_directory(archive)
    with ZipFile(archive) as zip_file:
        entries, names, files, total = [], set(), set(), 0
        for info in zip_file.infolist():
            check()
            relative = safe_name(info)
            key = str(relative).casefold()
            if key in names:
                raise AppValueError('error.6b82f056ed14')
            names.add(key)
            if not info.is_dir():
                files.add(key)
            total += info.file_size
            if total > max_extract_bytes:
                raise AppValueError('error.b6832cc86559', p0=f'{total:,}', p1=f'{max_extract_bytes:,}', p2=f'{info.filename!r}')
            ratio = info.file_size/max(1, info.compress_size)
            if ratio > MAX_RATIO:
                detail = (f"Kompressionsverhältnis {ratio:.0f}:1 über Limit {MAX_RATIO}:1; Eintrag {info.filename!r}, "
                          f"entpackt {info.file_size:,} Bytes, komprimiert {info.compress_size:,} Bytes.")
                if not allow_high_compression:
                    raise ValueError(detail)
                report("Explizit erlaubt: "+detail+" Größen- und Speicherplatzlimits bleiben aktiv.")
            entries.append((info, relative))
        if len(entries) > MAX_FILES:
            raise AppValueError('error.e23c25f405bd')
        for _, relative in entries:
            if any(str(parent).casefold() in files for parent in relative.parents if str(parent) != "."):
                raise AppValueError('error.de34e314b7dd')
        destination_parent = target.parent
        while not destination_parent.exists():
            destination_parent = destination_parent.parent
        ensure_space(destination_parent, total)
        target.mkdir(parents=True, exist_ok=False)
        written = 0
        for index, (info, relative) in enumerate(entries):
            check()
            output = target / relative
            if info.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            length = 0
            with zip_file.open(info) as source, output.open("xb") as destination:
                while chunk := source.read(1024*1024):
                    check()
                    length += len(chunk)
                    written += len(chunk)
                    if length > info.file_size or written > max_extract_bytes:
                        raise AppValueError('error.d9f1d231d502')
                    destination.write(chunk)
            if length != info.file_size:
                raise AppValueError('error.f72b979e4a12')
            if index % 100 == 0:
                report(f"ZIP entpackt: {index+1}/{len(entries)} Einträge")
        report(f"ZIP vollständig geprüft und entpackt: {len(entries)} Einträge, {written} Bytes")


def output_files(folder: Path, *, max_bytes: int = MAX_EXTRACTED):
    """List nonempty regular result files within the configured output tree.

    Reject observed symbolic links/junctions, escaped paths, special files and
    count/byte-budget overruns. Enumeration does not validate result semantics or
    forensic completeness.
    """
    if not folder.is_dir() or folder.is_symlink() or folder.is_junction():
        raise AppValueError('error.67607a262e85')
    found, size = [], 0
    for root, directories, files in os.walk(folder, followlinks=False):
        for name in [*directories, *files]:
            path = Path(root)/name
            if path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(folder.resolve()):
                raise AppValueError('error.63f0475064ef')
            if name in files:
                if not stat.S_ISREG(path.stat().st_mode):
                    raise AppValueError('error.522ae1d0574b')
                size += path.stat().st_size
                found.append(path)
                if len(found) > MAX_FILES or size > max_bytes:
                    raise AppValueError('error.032000c65ccf')
    if not found:
        raise AppValueError('error.c7df519dbf18')
    return found
