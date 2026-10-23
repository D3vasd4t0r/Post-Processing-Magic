"""Bounded, presentation-ready facts from one static inspector's saved JSON.

This module only transforms an existing result mapping. It never opens a sample.
"""

from collections.abc import Mapping
from itertools import islice

_INSPECTORS = {
    "metadata": ("Metadaten und Entropie", "Entropie der ersten 1 MiB"),
    "strings": ("Rohtextsuche", "Rohtext der ersten 8 MiB"),
    "pdf": ("PDF-Namenssuche", "Wörtliche Namen der ersten 16 MiB"),
    "office": ("Office-Verzeichnis", "Container-Verzeichnis, ohne Inhaltsanalyse"),
    "pe": ("PE-Header", "Header und Sektionstabelle, ohne Codeanalyse"),
}
_DEFAULT_LIMITATION = (
    "Begrenzte statische Prüfung; Indikatoren sind weder Malware-Diagnose noch Entwarnung."
)


def _text(value: object, limit: int = 240) -> str | None:
    if not isinstance(value, str):
        return None
    clean = " ".join(value.split())
    return clean[:limit] if clean else None


def _count(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 10**15 else None


def _flag(value: object) -> bool | None:
    return value if type(value) is bool else None


def _hash(value: object, length: int) -> str | None:
    if not isinstance(value, str) or len(value) != length:
        return None
    lowered = value.lower()
    return lowered if all(char in "0123456789abcdef" for char in lowered) else None


def _names(value: object, maximum: int = 5) -> list[str]:
    if not isinstance(value, list):
        return []
    return [name for item in value[:maximum] if (name := _text(item, 160))]


def summarize_finding(result: dict) -> dict:
    """Summarize one run_static JSON object without asserting a malware verdict.

    Unknown coverage stays ``None``. ``completed`` refers only to the explicitly
    stated inspector scope; it never means that the entire file was analyzed.
    """
    source = result if isinstance(result, Mapping) else {}
    findings = source.get("findings")
    findings = findings if isinstance(findings, Mapping) else {}
    input_data = source.get("input")
    input_data = input_data if isinstance(input_data, Mapping) else {}

    inspector_id = source.get("inspection")
    inspector_id = inspector_id if isinstance(inspector_id, str) and inspector_id in _INSPECTORS else "unknown"
    name, scope = _INSPECTORS.get(inspector_id, ("Unbekannte Prüfung", "Umfang unbekannt"))
    file_bytes = _count(findings.get("file_bytes"))
    input_bytes = _count(input_data.get("bytes"))
    if file_bytes is None:
        file_bytes = input_bytes
    inspected_bytes = _count(findings.get("inspected_bytes"))
    byte_partial = _flag(findings.get("partial"))
    if inspected_bytes is not None and file_bytes is not None:
        byte_partial = inspected_bytes < file_bytes

    limitations = [_text(findings.get("limitation")), _text(source.get("scope"), 360)]
    limitations = [value for value in limitations if value]
    if not limitations:
        limitations = [_DEFAULT_LIMITATION]

    error = _text(findings.get("error") or source.get("error"), 240)
    declared_status = findings.get("status") or source.get("status")
    unsupported = _flag(findings.get("unsupported")) is True or declared_status == "unsupported"
    container = findings.get("container") if inspector_id == "office" else None
    if container == "OLE":
        unsupported = True
        scope = "Legacy-OLE-Inhalte nicht geparst"
    elif container == "OOXML":
        scope = "OOXML-Zentralverzeichnis, ohne Entpackung oder Inhaltsanalyse"
    status = "error" if error or declared_status == "error" else "unsupported" if unsupported else "unknown"
    valid = {
        "metadata": inspected_bytes is not None and type(findings.get("entropy_bits_per_byte")) in (int, float),
        "strings": inspected_bytes is not None and isinstance(findings.get("strings"), list)
        and _flag(findings.get("limit_reached")) is not None,
        "pdf": inspected_bytes is not None and isinstance(findings.get("keyword_counts"), Mapping)
        and _flag(findings.get("name_token_limit_reached")) is not None,
        "office": container == "OOXML" and isinstance(findings.get("entries"), list),
        "pe": isinstance(findings.get("sections"), list),
    }
    if status == "unknown" and valid.get(inspector_id):
        status = "limited" if byte_partial or _flag(findings.get("limit_reached")) or _flag(findings.get("name_token_limit_reached")) else "completed"

    observations: dict = {}
    if inspector_id == "metadata":
        entropy = findings.get("entropy_bits_per_byte")
        if type(entropy) in (int, float) and 0 <= entropy <= 8:
            observations["entropy_bits_per_byte"] = entropy
            observations["entropy_scope"] = "first_1_mib"
            observations["entropy_sample_bytes"] = inspected_bytes
    elif inspector_id == "strings":
        strings = findings.get("strings")
        observations["reported_strings"] = min(len(strings), 2000) if isinstance(strings, list) else None
        observations["entry_limit"] = _count(findings.get("entry_limit"))
        observations["entry_limit_reached"] = _flag(findings.get("limit_reached"))
    elif inspector_id == "pdf":
        counts = findings.get("keyword_counts")
        if isinstance(counts, Mapping):
            observations["keyword_counts"] = {
                key: count for key, value in islice(counts.items(), 20)
                if isinstance(key, str) and len(key) <= 32 and (count := _count(value)) is not None
            }
        observations["name_token_limit"] = _count(findings.get("name_token_limit"))
        observations["name_token_limit_reached"] = _flag(findings.get("name_token_limit_reached"))
    elif inspector_id == "office":
        observations["container"] = container if container in ("OLE", "OOXML") else None
        if container == "OOXML":
            entries = findings.get("entries")
            observations["directory_entries"] = len(entries) if isinstance(entries, list) else None
            observations["macro_named_entries"] = _names(findings.get("macro_named_entries"))
            observations["embedded_named_entries"] = _names(findings.get("embedded_named_entries"))
    elif inspector_id == "pe":
        sections = findings.get("sections")
        observations["section_count"] = len(sections) if isinstance(sections, list) else None
        observations["machine_hex"] = _text(findings.get("machine_hex"), 16)
        observations["raw_range_invalid_count"] = (
            sum(item.get("raw_range_valid") is False for item in sections[:96] if isinstance(item, Mapping))
            if isinstance(sections, list) else None
        )
    if error:
        observations["error"] = error

    sha1 = _hash(input_data.get("sha1"), 40)
    sha256 = _hash(input_data.get("sha256"), 64)

    return {
        "schema_version": 1,
        "inspector": {"id": inspector_id, "name": name, "status": status,
                      "scope": scope, "limitations": limitations},
        "coverage": {"inspected_bytes": inspected_bytes, "file_bytes": file_bytes,
                     "byte_partial": byte_partial,
                     "entry_limit_reached": _flag(findings.get("limit_reached")) if inspector_id == "strings" else None,
                     "name_token_limit_reached": _flag(findings.get("name_token_limit_reached")) if inspector_id == "pdf" else None},
        "input": {"bytes": input_bytes, "sha1": sha1, "sha256": sha256,
                  "hash_scope": "whole_input" if sha1 or sha256 else None},
        "observations": observations,
    }
