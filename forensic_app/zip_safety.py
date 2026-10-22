"""Bounded Windows ZIP extraction. Never use archive names as host paths unchecked."""

import os
import shutil
import stat
import struct
from pathlib import Path, PureWindowsPath
from zipfile import ZipFile

MAX_FILES = 200_000
MAX_EXTRACTED = 2_000_000_000_000
MAX_RATIO = 1000
DISK_RESERVE = 512 * 1024**2


def ensure_space(root: Path, size: int = 0):
    free = shutil.disk_usage(root).free
    if free < size + DISK_RESERVE:
        raise ValueError(f"Nicht genug freier Speicherplatz auf {root.anchor}: frei {free/1024**3:.2f} GiB, "
                         f"benötigt mindestens {(size+DISK_RESERVE)/1024**3:.2f} GiB einschließlich Reserve.")


def bounded_directory(path: Path):
    # Bound ZipFile's initial central-directory allocation, including ZIP64.
    with path.open("rb") as source:
        source.seek(0, 2)
        length = source.tell()
        source.seek(max(0, length - 65557))
        tail = source.read()
        offset = tail.rfind(b"PK\x05\x06")
        if offset < 0 or len(tail)-offset < 22:
            raise ValueError("Kein vollständiges ZIP-Archiv.")
        end = struct.unpack_from("<4s4H2IH", tail, offset)
        if end[1] or end[2] or end[3] != end[4] or len(tail)-offset != 22+end[7]:
            raise ValueError("Mehrteilige oder uneindeutige ZIP-Archive werden nicht unterstützt.")
        count, size = end[4], end[5]
        if count == 65535 or size == 0xffffffff:
            eocd = length-len(tail)+offset
            if eocd < 20:
                raise ValueError("ZIP64-Verzeichnis fehlt.")
            source.seek(eocd-20)
            locator = struct.unpack("<4sIQI", source.read(20))
            if locator[0] != b"PK\x06\x07" or locator[1] or locator[3] != 1:
                raise ValueError("Ungültiges ZIP64-Verzeichnis.")
            source.seek(locator[2])
            data = source.read(56)
            if len(data) != 56:
                raise ValueError("Unvollständiges ZIP64-Verzeichnis.")
            record = struct.unpack("<4sQ2H2I4Q", data)
            if record[0] != b"PK\x06\x06" or record[4] or record[5] or record[6] != record[7]:
                raise ValueError("Mehrteiliges ZIP64 wird nicht unterstützt.")
            count, size = record[7], record[8]
        if count > MAX_FILES or size > 64*1024**2:
            raise ValueError("ZIP-Verzeichnis zu groß (maximal 200.000 Einträge / 64 MiB Verzeichnis).")


def safe_name(info) -> Path:
    name = info.orig_filename
    path = PureWindowsPath(name)
    if ("\x00" in name or path.drive or path.root or not path.parts or
            any(part in ("", ".", "..") for part in name.replace("\\", "/").rstrip("/").split("/"))):
        raise ValueError(f"Unsicherer ZIP-Pfad: {name!r}")
    if len(path.parts) > 64 or len(name) > 240:
        raise ValueError("ZIP-Pfad zu lang oder zu tief verschachtelt.")
    for part in path.parts:
        if (any(ord(char) < 32 or char in '<>:"|?*' for char in part)
                or part.endswith((".", " ")) or PureWindowsPath(part).is_reserved()):
            raise ValueError(f"Unter Windows unzulässiger ZIP-Pfad: {name!r}")
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or info.external_attr & 0x400:
        raise ValueError("Links, Reparse Points und Sonderdateien im ZIP sind nicht erlaubt.")
    if info.flag_bits & 1:
        raise ValueError("Verschlüsselte ZIP-Dateien werden noch nicht unterstützt.")
    return Path(*path.parts)


def extract_checked(archive: Path, target: Path, check, report, *, allow_high_compression: bool = False, max_extract_bytes: int = MAX_EXTRACTED):
    bounded_directory(archive)
    with ZipFile(archive) as zip_file:
        entries, names, files, total = [], set(), set(), 0
        for info in zip_file.infolist():
            check()
            relative = safe_name(info)
            key = str(relative).casefold()
            if key in names:
                raise ValueError("Doppelte oder unter Windows kollidierende ZIP-Pfade.")
            names.add(key)
            if not info.is_dir():
                files.add(key)
            total += info.file_size
            if total > max_extract_bytes:
                raise ValueError(f"ZIP überschreitet das Entpacklimit: {total:,} Bytes, maximal {max_extract_bytes:,} Bytes; Eintrag {info.filename!r}.")
            ratio = info.file_size/max(1, info.compress_size)
            if ratio > MAX_RATIO:
                detail = (f"Kompressionsverhältnis {ratio:.0f}:1 über Limit {MAX_RATIO}:1; Eintrag {info.filename!r}, "
                          f"entpackt {info.file_size:,} Bytes, komprimiert {info.compress_size:,} Bytes.")
                if not allow_high_compression:
                    raise ValueError(detail)
                report("Explizit erlaubt: "+detail+" Größen- und Speicherplatzlimits bleiben aktiv.")
            entries.append((info, relative))
        if len(entries) > MAX_FILES:
            raise ValueError("Zu viele ZIP-Einträge.")
        for _, relative in entries:
            if any(str(parent).casefold() in files for parent in relative.parents if str(parent) != "."):
                raise ValueError("ZIP enthält einen Datei-/Ordnerkonflikt.")
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
                        raise ValueError("Tatsächliche ZIP-Größe überschreitet das Limit.")
                    destination.write(chunk)
            if length != info.file_size:
                raise ValueError("ZIP-Dateigröße stimmt nicht mit dem Verzeichnis überein.")
            if index % 100 == 0:
                report(f"ZIP entpackt: {index+1}/{len(entries)} Einträge")
        report(f"ZIP vollständig geprüft und entpackt: {len(entries)} Einträge, {written} Bytes")


def output_files(folder: Path, *, max_bytes: int = MAX_EXTRACTED):
    if not folder.is_dir() or folder.is_symlink() or folder.is_junction():
        raise ValueError("Ergebnisordner fehlt oder ist ein Link.")
    found, size = [], 0
    for root, directories, files in os.walk(folder, followlinks=False):
        for name in [*directories, *files]:
            path = Path(root)/name
            if path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(folder.resolve()):
                raise ValueError("Ergebnis enthält einen Link oder einen Pfad außerhalb des Ergebnisordners.")
            if name in files:
                if not stat.S_ISREG(path.stat().st_mode):
                    raise ValueError("Ergebnis enthält eine Sonderdatei.")
                size += path.stat().st_size
                found.append(path)
                if len(found) > MAX_FILES or size > max_bytes:
                    raise ValueError("Ergebnis überschreitet die Archivlimits.")
    if not found:
        raise ValueError("KAPE hat keine Ergebnisdateien im konfigurierten Ergebnisordner erzeugt.")
    return found
