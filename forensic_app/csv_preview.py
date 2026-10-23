"""Small, literal, read-only preview of one already authorized result CSV.

The caller selects a file below a verified job output directory and authorizes the
job. This module adds per-file link and resource checks; it is not a path resolver.
"""

import codecs
import os
import re
import stat
import time
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

from forensic_app.workspaces import no_links

MAX_FILE_BYTES = 2 * 1024**3
MAX_READ_BYTES = 1024**2
MAX_ROWS = 2000
MAX_COLUMNS = 64
MAX_FIELD_CHARS = 4096
MAX_SEARCH_CHARS = 128
MAX_OFFSET = 2000
MAX_PAGE_SIZE = 50
MAX_SECONDS = 1.0
DELIMITERS = (",", ";", "\t")


class CSVPreviewError(ValueError):
    """Unsupported CSV, unsafe file, or a preview budget was exceeded."""


def _delimiter(text: str) -> str:
    counts = {value: 0 for value in DELIMITERS}
    quoted = False
    index = 0
    while index < min(len(text), 16384):
        char = text[index]
        if char == '"':
            if quoted and index + 1 < len(text) and text[index + 1] == '"':
                index += 2
                continue
            quoted = not quoted
        elif not quoted:
            if char in "\r\n":
                break
            if char in counts:
                counts[char] += 1
        index += 1
    return max(DELIMITERS, key=lambda value: counts[value])


def _records(text: str, delimiter: str, complete: bool, deadline: float):
    """Yield complete CSV records with one-based physical source line numbers."""
    row, field = [], []
    quoted = False
    after_quote = False
    line = record_line = 1
    index = 0

    def push_field():
        if len(row) >= MAX_COLUMNS:
            raise CSVPreviewError(f"CSV hat mehr als {MAX_COLUMNS} Spalten.")
        row.append("".join(field))
        field.clear()

    while index < len(text):
        if index % 4096 == 0 and time.monotonic() > deadline:
            raise CSVPreviewError("Zeitlimit für die CSV-Vorschau überschritten.")
        char = text[index]
        if quoted:
            if char == '"':
                if index + 1 < len(text) and text[index + 1] == '"':
                    field.append('"')
                    index += 2
                    continue
                quoted = False
                after_quote = True
            else:
                field.append(char)
                if char == "\n" or (char == "\r" and (index + 1 == len(text) or text[index + 1] != "\n")):
                    line += 1
        elif char == delimiter:
            push_field()
            after_quote = False
        elif char in "\r\n":
            push_field()
            yield record_line, row
            row, after_quote = [], False
            if char == "\r" and index + 1 < len(text) and text[index + 1] == "\n":
                index += 1
            line += 1
            record_line = line
        elif after_quote:
            if char not in " \t":
                raise CSVPreviewError("Ungültiges Zeichen nach einem CSV-Anführungszeichen.")
        elif char == '"' and not field:
            quoted = True
        elif char == '"':
            raise CSVPreviewError("Ungültiges CSV-Anführungszeichen in einem Feld.")
        else:
            field.append(char)
        if len(field) > MAX_FIELD_CHARS:
            raise CSVPreviewError(f"CSV-Feld überschreitet {MAX_FIELD_CHARS} Zeichen.")
        index += 1
    if complete and (quoted or after_quote or row or field):
        if quoted:
            raise CSVPreviewError("CSV endet in einem offenen Anführungszeichen.")
        push_field()
        yield record_line, row


def preview_csv(path: Path, *, search: str = "", offset: int = 0, limit: int = 25,
                sort_column: int | None = None, sort_kind: str = "text", descending: bool = False) -> dict:
    """Preview one authorized CSV. Search and offsets apply only to scanned rows.

    No total count is promised. ``partial`` means further rows may exist beyond a
    byte, row, time, or page boundary. Caller must serialize cells as textContent.
    """
    if not isinstance(search, str) or len(search) > MAX_SEARCH_CHARS or "\x00" in search:
        raise CSVPreviewError("Suchtext ist ungültig oder zu lang.")
    if type(offset) is not int or not 0 <= offset <= MAX_OFFSET:
        raise CSVPreviewError("CSV-Offset ist außerhalb des erlaubten Bereichs.")
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
        raise CSVPreviewError("CSV-Seitengröße ist außerhalb des erlaubten Bereichs.")
    path = Path(path)
    if not path.is_absolute():
        raise CSVPreviewError("CSV-Pfad muss absolut sein.")
    deadline = time.monotonic() + MAX_SECONDS
    try:
        no_links(path)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise CSVPreviewError("Nur reguläre, nicht verknüpfte CSV-Dateien sind erlaubt.")
        if before.st_size > MAX_FILE_BYTES:
            raise CSVPreviewError("CSV-Datei überschreitet das Dateigrößenlimit.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise CSVPreviewError("CSV-Datei wurde durch eine Verknüpfung ersetzt.")
            if opened.st_size > MAX_FILE_BYTES:
                raise CSVPreviewError("CSV-Datei überschreitet das Dateigrößenlimit.")
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise CSVPreviewError("CSV-Datei hat sich während des Öffnens geändert.")
            data = source.read(MAX_READ_BYTES + 1)
    except OSError as exc:
        raise CSVPreviewError("CSV-Datei kann nicht sicher gelesen werden.") from exc
    if time.monotonic() > deadline:
        raise CSVPreviewError("Zeitlimit für die CSV-Vorschau überschritten.")
    truncated_bytes = len(data) > MAX_READ_BYTES
    data = data[:MAX_READ_BYTES]
    encoding = "utf-8-sig" if data.startswith(codecs.BOM_UTF8) else "utf-8"
    try:
        decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
        text = decoder.decode(data, final=not truncated_bytes)
    except UnicodeDecodeError as exc:
        raise CSVPreviewError("CSV muss UTF-8 (optional mit BOM) sein.") from exc
    if "\x00" in text:
        raise CSVPreviewError("CSV enthält ein NUL-Zeichen.")
    delimiter = _delimiter(text)
    records = _records(text, delimiter, not truncated_bytes, deadline)
    try:
        _header_line, columns = next(records)
    except StopIteration as exc:
        raise CSVPreviewError("CSV enthält keinen vollständigen Kopfdatensatz.") from exc
    if len(columns) == 1 and not columns[0]:
        raise CSVPreviewError("CSV-Kopfdatensatz ist leer.")
    if sort_kind not in ("text", "number", "time") or (sort_column is not None and
            (type(sort_column) is not int or not 0 <= sort_column < len(columns))):
        raise CSVPreviewError("Sortierspalte oder Sortiertyp ist ungültig.")
    query = search.casefold()
    window = []
    partial_reason = "read_limit" if truncated_bytes else None
    for line, values in records:
        if len(window) >= MAX_ROWS:
            partial_reason = "row_limit"
            break
        window.append({"line": line, "values": values})
    rows = [row for row in window if not query or any(query in value.casefold() for value in row["values"])]
    if sort_column is not None:
        valid, invalid = [], []
        for row in rows:
            value = row["values"][sort_column] if sort_column < len(row["values"]) else ""
            key = _sort_value(value, sort_kind)
            (invalid if key is None else valid).append((key, row))
        valid.sort(key=lambda item: item[0], reverse=descending)
        rows = [row for _, row in valid + invalid]
    matched_rows = len(rows)
    rows = rows[offset:offset + limit]
    has_more = offset + len(rows) < matched_rows
    reason = partial_reason or ("page_limit" if has_more else None)
    return {
        "columns": columns, "rows": rows, "encoding": encoding, "delimiter": delimiter,
        "offset": offset, "limit": limit, "next_offset": offset + len(rows) if has_more else None,
        "has_more": has_more, "partial": reason is not None,
        "partial_reason": reason, "scanned_rows": len(window), "matched_rows": matched_rows,
        "note": "Filter und Sortierung gelten vor der Seitenteilung für den begrenzten Dateiausschnitt. "
                "Zahlen: Dezimalpunkt, keine Tausendertrenner. Zeit: ISO 8601; Werte ohne und mit Zeitzone getrennt gruppiert, ohne erfundene Zeitzone. "
                "Leere/ungültige Werte stehen stabil am Ende.",
    }


def _sort_value(value, kind):
    if not value:
        return None
    if kind == "text":
        return value.casefold()
    if kind == "number":
        if not re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value.strip()):
            return None
        try:
            result = Decimal(value)
            return result if result.is_finite() else None
        except InvalidOperation:
            return None
    try:
        # Keep timezone-bearing values in a separate group: no invented timezone.
        if not re.match(r"^\d{4}-\d{2}-\d{2}(?:[T ]|$)", value):
            return None
        result = datetime.fromisoformat(value)
        return (result.tzinfo is not None, result.isoformat() if result.tzinfo is None else result.timestamp())
    except (ValueError, OverflowError):
        return None
