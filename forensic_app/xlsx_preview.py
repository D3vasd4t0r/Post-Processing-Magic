"""Bounded, literal XLSX preview of an already authorized job result.

The caller resolves and authorizes the output path. No formula, macro, connection,
external relationship, or embedded object is executed or fetched.
"""

from __future__ import annotations

import os
import posixpath
import re
import stat
import time
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from forensic_app.app_errors import AppValueError
from forensic_app.csv_preview import _sort_value, infer_column_types
from forensic_app.workspaces import no_links

MAX_FILE_BYTES = 64 * 1024**2
MAX_ENTRIES = 256
MAX_COMPRESSED_BYTES = 48 * 1024**2
MAX_UNCOMPRESSED_BYTES = 64 * 1024**2
MAX_XML_BYTES = 16 * 1024**2
MAX_TOTAL_XML_BYTES = 32 * 1024**2
MAX_SHARED_STRINGS = 100_000
MAX_ROWS = 2000
MAX_COLUMNS = 64
MAX_CELLS = 128_000
MAX_FIELD_CHARS = 4096
MAX_SEARCH_CHARS = 128
MAX_OFFSET = 2000
MAX_PAGE_SIZE = 50
MAX_RATIO = 100
MAX_SECONDS = 3.0

_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_CONTENT = "http://schemas.openxmlformats.org/package/2006/content-types"
_CELL = re.compile(r"^([A-Z]{1,3})([1-9][0-9]*)$")
_ACTIVE_PARTS = ("vbaproject", "activex", "externallinks", "connections",
                 "querytables", "embeddings", "oleobjects", "customxml")


class XLSXPreviewError(ValueError):
    """Unsupported or unsafe XLSX, or a preview budget was exceeded."""


def _check_time(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise XLSXPreviewError("Zeitlimit für die XLSX-Vorschau überschritten.")


def _safe_name(name: str) -> None:
    if (not name or name.startswith(("/", "\\")) or "\\" in name or ":" in name
            or "\x00" in name or any(part in ("", ".", "..") for part in name.split("/"))):
        raise XLSXPreviewError("XLSX enthält einen unsicheren Paketpfad.")


def _validate_xml_bytes(data: bytes) -> None:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise XLSXPreviewError("XLSX-XML muss UTF-8 sein.") from exc
    declaration = re.match(r"\s*<\?xml\s+[^?]*\?>", text, re.IGNORECASE)
    if declaration:
        encoding = re.search(r"""encoding\s*=\s*["']([^"']+)["']""", declaration.group(),
                             re.IGNORECASE)
        if encoding and encoding.group(1).lower() != "utf-8":
            raise XLSXPreviewError("XLSX-XML muss UTF-8 sein.")
    if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise XLSXPreviewError("XLSX-XML mit DTD, Entity oder NUL ist nicht erlaubt.")


def _xml(data: bytes, deadline: float) -> ET.Element:
    _check_time(deadline)
    _validate_xml_bytes(data)
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError) as exc:
        raise XLSXPreviewError("XLSX enthält ungültiges XML.") from exc
    _check_time(deadline)
    return root


def _read_part(archive: zipfile.ZipFile, name: str, maximum: int, deadline: float) -> bytes:
    try:
        with archive.open(name) as source:
            chunks = []
            size = 0
            while True:
                _check_time(deadline)
                chunk = source.read(min(65536, maximum + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    raise XLSXPreviewError("XLSX-Paketteil überschreitet das Leselimit.")
                chunks.append(chunk)
            return b"".join(chunks)
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile) as exc:
        raise XLSXPreviewError("XLSX-Paketteil kann nicht sicher gelesen werden.") from exc


def _relationships(root: ET.Element, source: str, names: set[str]) -> dict[str, tuple[str, str]]:
    result = {}
    for item in root.findall(f"{{{_PKG_REL}}}Relationship"):
        ident = item.get("Id")
        target = item.get("Target", "")
        kind = item.get("Type", "")
        if not ident or ident in result or item.get("TargetMode", "").lower() == "external":
            raise XLSXPreviewError("XLSX enthält externe oder ungültige Beziehungen.")
        if target.startswith("/"):
            normalized = target.lstrip("/")
        else:
            normalized = posixpath.normpath(posixpath.join(posixpath.dirname(source), target))
        if (not target or "://" in target or "\\" in target or ":" in target
                or target.startswith("//") or any(part in (".", "..") for part in target.split("/"))
                or normalized.startswith("../")):
            raise XLSXPreviewError("XLSX enthält eine unsichere Beziehung.")
        _safe_name(normalized)
        if normalized not in names:
            raise XLSXPreviewError("XLSX-Beziehung verweist auf einen fehlenden Teil.")
        result[ident] = (normalized, kind)
    return result


def _preflight(archive: zipfile.ZipFile, deadline: float) -> dict[str, bytes]:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ENTRIES:
        raise XLSXPreviewError("XLSX überschreitet das Eintragslimit.")
    names = set()
    folded = set()
    total_compressed = total_plain = total_xml = 0
    for info in infos:
        _check_time(deadline)
        name = info.filename.rstrip("/") if info.is_dir() else info.filename
        _safe_name(name)
        if name.casefold() in folded:
            raise XLSXPreviewError("XLSX enthält doppelte Paketpfade.")
        names.add(name)
        folded.add(name.casefold())
        mode = (info.external_attr >> 16) & 0o170000
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or (info.flag_bits & 1):
            raise XLSXPreviewError("XLSX enthält Verknüpfungen, Sonderdateien oder Verschlüsselung.")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise XLSXPreviewError("XLSX verwendet eine nicht unterstützte Kompression.")
        if any(part in info.filename.casefold() for part in _ACTIVE_PARTS):
            raise XLSXPreviewError("XLSX enthält aktive oder externe Inhalte.")
        total_compressed += info.compress_size
        total_plain += info.file_size
        if info.file_size and info.file_size / max(1, info.compress_size) > MAX_RATIO:
            raise XLSXPreviewError("XLSX-Kompressionsverhältnis überschreitet das Limit.")
        if name.endswith((".xml", ".rels")):
            if info.file_size > MAX_XML_BYTES:
                raise XLSXPreviewError("XLSX-XML überschreitet das Größenlimit.")
            total_xml += info.file_size
    if (total_compressed > MAX_COMPRESSED_BYTES or total_plain > MAX_UNCOMPRESSED_BYTES
            or total_xml > MAX_TOTAL_XML_BYTES):
        raise XLSXPreviewError("XLSX-Paket überschreitet das Größenlimit.")
    required = {"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
                "xl/_rels/workbook.xml.rels"}
    if not required.issubset(names):
        raise XLSXPreviewError("XLSX-Paketstruktur ist unvollständig.")
    xml_parts = {}
    for name in names:
        if name.endswith((".xml", ".rels")):
            xml_parts[name] = _read_part(archive, name, MAX_XML_BYTES, deadline)
            _validate_xml_bytes(xml_parts[name])
    # Validate every relationship, including parts not selected for display.
    for name, data in xml_parts.items():
        if name.endswith(".rels"):
            parent = name.removeprefix("_rels/") if name.startswith("_rels/") else name
            if "/_rels/" in parent:
                parent = parent.replace("/_rels/", "/")
            parent = parent.removesuffix(".rels")
            _relationships(_xml(data, deadline), parent, names)
    types = _xml(xml_parts["[Content_Types].xml"], deadline)
    if types.tag != f"{{{_CONTENT}}}Types":
        raise XLSXPreviewError("XLSX-Inhaltstypen sind ungültig.")
    for item in types:
        content_type = item.get("ContentType", "").lower()
        if "macroenabled" in content_type or "vba" in content_type:
            raise XLSXPreviewError("Makrohaltige Arbeitsmappen sind nicht erlaubt.")
    return xml_parts


def _open(path: Path, deadline: float) -> tuple[zipfile.ZipFile, object]:
    path = Path(path)
    if not path.is_absolute() or path.suffix.lower() != ".xlsx":
        raise XLSXPreviewError("Ein absoluter XLSX-Dateipfad ist erforderlich.")
    no_links(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise XLSXPreviewError("Nur reguläre, nicht verknüpfte XLSX-Dateien sind erlaubt.")
    if before.st_size > MAX_FILE_BYTES:
        raise XLSXPreviewError("XLSX-Datei überschreitet das Dateigrößenlimit.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    source = os.fdopen(descriptor, "rb")
    try:
        opened = os.fstat(source.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_size > MAX_FILE_BYTES
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise XLSXPreviewError("XLSX-Datei hat sich während des Öffnens geändert.")
        _check_time(deadline)
        archive = zipfile.ZipFile(source)
        return archive, source
    except BaseException:
        source.close()
        raise


def _sheets(parts: dict[str, bytes], deadline: float) -> list[dict]:
    names = set(parts)
    workbook = _xml(parts["xl/workbook.xml"], deadline)
    if workbook.tag != f"{{{_NS}}}workbook":
        raise XLSXPreviewError("XLSX-Arbeitsmappe ist ungültig.")
    relations = _relationships(
        _xml(parts["xl/_rels/workbook.xml.rels"], deadline), "xl/workbook.xml", names)
    sheets = []
    for element in workbook.findall(f"{{{_NS}}}sheets/{{{_NS}}}sheet"):
        relation_id = element.get(f"{{{_REL}}}id")
        target, kind = relations.get(relation_id, ("", ""))
        if not kind.endswith("/worksheet") or not target.startswith("xl/worksheets/"):
            raise XLSXPreviewError("XLSX-Blattbeziehung ist ungültig.")
        if target not in parts:
            raise XLSXPreviewError("XLSX-Blatt fehlt.")
        sheets.append({"id": f"s{len(sheets) + 1}", "name": element.get("name", ""),
                       "state": element.get("state", "visible"), "_part": target})
    if not sheets or len(sheets) > 64:
        raise XLSXPreviewError("XLSX enthält keine unterstützte Blattliste.")
    return sheets


def _shared_strings(parts: dict[str, bytes], deadline: float) -> list[str]:
    data = parts.get("xl/sharedStrings.xml")
    if data is None:
        return []
    root = _xml(data, deadline)
    if root.tag != f"{{{_NS}}}sst":
        raise XLSXPreviewError("XLSX-Texttabelle ist ungültig.")
    result = []
    for item in root.findall(f"{{{_NS}}}si"):
        _check_time(deadline)
        if len(result) >= MAX_SHARED_STRINGS:
            raise XLSXPreviewError("XLSX-Texttabelle überschreitet das Eintragslimit.")
        value = "".join(text.text or "" for text in item.iter(f"{{{_NS}}}t"))
        if len(value) > MAX_FIELD_CHARS:
            raise XLSXPreviewError("XLSX-Feld überschreitet das Zeichenlimit.")
        result.append(value)
    return result


def _cell_value(cell: ET.Element, shared: list[str]) -> tuple[str, bool]:
    kind = cell.get("t", "n")
    formula = cell.find(f"{{{_NS}}}f") is not None
    value_element = cell.find(f"{{{_NS}}}v")
    value = value_element.text or "" if value_element is not None else ""
    if kind == "s":
        try:
            if not value.isascii() or not value.isdecimal():
                raise AppValueError('error.8eb67729270f')
            value = shared[int(value)]
        except (ValueError, IndexError) as exc:
            raise XLSXPreviewError("XLSX-Textindex ist ungültig.") from exc
    elif kind == "inlineStr":
        inline = cell.find(f"{{{_NS}}}is")
        value = "" if inline is None else "".join(
            text.text or "" for text in inline.iter(f"{{{_NS}}}t"))
    elif kind == "b":
        value = "TRUE" if value == "1" else "FALSE" if value == "0" else value
    elif kind not in ("n", "str", "e", "d"):
        raise XLSXPreviewError("XLSX-Zelltyp ist nicht unterstützt.")
    if len(value) > MAX_FIELD_CHARS:
        raise XLSXPreviewError("XLSX-Feld überschreitet das Zeichenlimit.")
    return value, formula


def _rows(root: ET.Element, shared: list[str], deadline: float) -> tuple[list[dict], str | None]:
    if root.tag != f"{{{_NS}}}worksheet":
        raise XLSXPreviewError("XLSX-Blatt-XML ist ungültig.")
    result = []
    cells_seen = 0
    partial_reason = None
    for row in root.findall(f"{{{_NS}}}sheetData/{{{_NS}}}row"):
        _check_time(deadline)
        if len(result) >= MAX_ROWS + 1:
            partial_reason = "row_limit"
            break
        values = [""] * MAX_COLUMNS
        formulas = []
        for cell in row.findall(f"{{{_NS}}}c"):
            cells_seen += 1
            if cells_seen > MAX_CELLS:
                raise XLSXPreviewError("XLSX-Blatt überschreitet das Zelllimit.")
            match = _CELL.fullmatch(cell.get("r", ""))
            if not match:
                raise XLSXPreviewError("XLSX-Zelladresse ist ungültig.")
            column = 0
            for char in match.group(1):
                column = column * 26 + ord(char) - ord("A") + 1
            if column > MAX_COLUMNS:
                raise XLSXPreviewError("XLSX-Blatt überschreitet das Spaltenlimit.")
            value, formula = _cell_value(cell, shared)
            values[column - 1] = value
            if formula:
                formulas.append(column - 1)
        while values and values[-1] == "":
            values.pop()
        line = int(row.get("r", "0"))
        if line < 1:
            raise XLSXPreviewError("XLSX-Zeilennummer ist ungültig.")
        result.append({"line": line, "values": values, "formula_cells": formulas})
    return result, partial_reason


def _sort_key(value: str, kind: str):
    key = _sort_value(value, kind)
    return (1, "") if key is None else (0, key)


def _validated_options(search, sort_column, sort_kind, descending, offset, limit):
    if not isinstance(search, str) or len(search) > MAX_SEARCH_CHARS or "\x00" in search:
        raise XLSXPreviewError("Suchtext ist ungültig oder zu lang.")
    if sort_column is not None and (type(sort_column) is not int
                                    or not 0 <= sort_column < MAX_COLUMNS):
        raise XLSXPreviewError("Sortierspalte ist ungültig.")
    if sort_kind not in ("text", "number", "time") or type(descending) is not bool:
        raise XLSXPreviewError("Sortierung ist ungültig.")
    if type(offset) is not int or not 0 <= offset <= MAX_OFFSET:
        raise XLSXPreviewError("XLSX-Offset ist außerhalb des erlaubten Bereichs.")
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
        raise XLSXPreviewError("XLSX-Seitengröße ist außerhalb des erlaubten Bereichs.")


def _load(path: Path, deadline: float) -> tuple[dict[str, bytes], list[dict]]:
    try:
        archive, source = _open(path, deadline)
        with source, archive:
            parts = _preflight(archive, deadline)
        return parts, _sheets(parts, deadline)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise XLSXPreviewError("XLSX-Datei kann nicht sicher gelesen werden.") from exc


def list_xlsx_sheets(path: Path) -> dict:
    """List stable sheet IDs and names from one authorized XLSX file."""
    deadline = time.monotonic() + MAX_SECONDS
    _parts, sheets = _load(path, deadline)
    return {"sheets": [{key: value for key, value in item.items() if key != "_part"}
                       for item in sheets]}


def preview_xlsx(
    path: Path, *, sheet_id: str = "s1", search: str = "", sort_column: int | None = None,
    sort_kind: str = "text", descending: bool = False, offset: int = 0, limit: int = 25,
) -> dict:
    """Preview one sheet; search/sort/page apply only to the bounded row prefix.

    First nonempty sheet row is used as table headings. Formula values are only
    cached values in the file; blank caches remain blank. Caller uses textContent.
    """
    _validated_options(search, sort_column, sort_kind, descending, offset, limit)
    deadline = time.monotonic() + MAX_SECONDS
    parts, sheets = _load(path, deadline)
    selected = next((sheet for sheet in sheets if sheet["id"] == sheet_id), None)
    if selected is None:
        raise XLSXPreviewError("Unbekannte XLSX-Blatt-ID.")
    shared = _shared_strings(parts, deadline)
    rows, partial_reason = _rows(_xml(parts[selected["_part"]], deadline), shared, deadline)
    if not rows:
        columns, data = [], []
    else:
        columns = rows[0]["values"]
        data = rows[1:]
    column_types = infer_column_types(columns,data)
    scanned_rows = len(data)
    query = search.casefold()
    if query:
        data = [row for row in data if any(query in value.casefold() for value in row["values"])]
    if sort_column is not None:
        def key(row):
            value = row["values"][sort_column] if sort_column < len(row["values"]) else ""
            return _sort_key(value, sort_kind)

        data.sort(key=key, reverse=descending)
        if descending:
            data.sort(key=lambda row: key(row)[0])
    page = data[offset:offset + limit]
    has_more = offset + limit < len(data)
    if has_more and partial_reason is None:
        partial_reason = "page_limit"
    visible_sheets = [{key: value for key, value in item.items() if key != "_part"}
                      for item in sheets]
    return {
        "sheets": visible_sheets, "sheet_id": sheet_id, "columns": columns, "column_types": column_types, "rows": page,
        "offset": offset, "limit": limit, "next_offset": offset + len(page) if has_more else None,
        "has_more": has_more, "partial": partial_reason is not None,
        "partial_reason": partial_reason, "scanned_rows": scanned_rows,
        "matched_rows_in_preview": len(data),
        "note": "Nur gespeicherte Formelwerte; keine Berechnung. Suche/Sortierung gelten nur für "
                "den begrenzten Blattausschnitt. Zahlen mit Dezimalpunkt. Zeit: ISO 8601; "
                "Werte ohne Zeitzone und mit Zeitzone werden getrennt gruppiert, ohne eine Zeitzone zu erfinden. "
                "Leere/ungültige Werte stehen stabil am Ende; Excel-Datumsserien bleiben roh."
    }




