"""Bounded text observations from existing static strings, with no sample or IO access.

Values are observations, never a reputation verdict. Domain/path recognition is
heuristic; the schema and conservative exclusions are documented in the handoff.
"""

import ipaddress
import re
import unicodedata
from collections.abc import Mapping
from urllib.parse import urlsplit

LIMITS = {
    "results": 64,
    "strings_per_result": 2000,
    "strings_total": 16000,
    "text_bytes": 2 * 1024 * 1024,
    "text_characters_per_string": 4096,
    "indicators": 2000,
    "sources_per_indicator": 8,
    "occurrences": 16000,
    "value_characters": 2048,
    "source_step_characters": 128,
    "encoding_characters": 32,
}
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`\\]{1,4096}")
_PATH = re.compile(r"(?<![\w\\])(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\)")
_TOKEN = re.compile(r"[\w.:%-]+", re.UNICODE)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_FILE_SUFFIXES = frozenset(["exe", "dll", "sys", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "zip", "rar", "7z", "tar", "gz", "txt", "csv", "tsv", "json", "xml", "html", "htm", "js", "css", "ps1", "bat", "cmd", "vbs", "py", "pyc", "log", "ini", "cfg", "db", "sqlite", "dat", "bin", "png", "jpg", "jpeg", "gif", "ico", "bmp", "tmp", "bak", "evtx", "lnk", "iso", "vhd", "vmdk", "e01"])


def _domain(value):
    """IDNA round trips, letter/digit/hyphen labels, no numeric/file suffixes."""
    value = value.rstrip(".")
    if not 3 <= len(value) <= 253 or "." not in value:
        return None
    if any(not (c.isalnum() or c in "-.") for c in value):
        return None
    try:
        encoded = value.encode("idna").decode("ascii").lower()
        decoded = encoded.encode("ascii").decode("idna")
        if decoded.encode("idna").decode("ascii").lower() != encoded:
            return None
    except UnicodeError:
        return None
    if len(encoded) > 253:
        return None
    labels = encoded.split(".")
    if any(not _LABEL.fullmatch(label) for label in labels):
        return None
    # Avoid IDNA mappings such as sharp-s -> ss and symbols disguised as letters.
    if any(not (c.isalnum() or c in "-.") for c in decoded) or (
        not value.isascii() and unicodedata.normalize("NFC", decoded).lower()
        != unicodedata.normalize("NFC", value).lower()
    ):
        return None
    suffix = labels[-1]
    if suffix in _FILE_SUFFIXES or not (
        (suffix.isalpha() and len(suffix) >= 2) or suffix.startswith("xn--")
    ):
        return None
    if not any(c.isalpha() for c in "".join(labels[:-1])):
        return None
    return encoded


def _host(value):
    try:
        # Scoped IPv6 names are interface hints, not portable IP observations.
        if "%" not in value:
            return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    domain = _domain(value)
    return ("domain", domain) if domain else None


def _trim(value):
    value = value.rstrip(".,;!?")
    for left, right in (("(", ")"), ("[", "]"), ("{", "}")):
        excess = value.count(right) - value.count(left)
        end = len(value)
        while excess > 0 and end and value[end - 1] == right:
            end -= 1
            excess -= 1
        value = value[:end]
    return value


def _observations(text, reason):
    """Return ordered non-overlapping tokens plus hosts within URLs."""
    occupied = bytearray(len(text))
    observations = []
    for match in _PATH.finditer(text):
        start = match.start()
        if occupied[start]:
            continue
        quote = text[start - 1] if start and text[start - 1] in "\"'" else None
        end = match.end()
        while end < len(text):
            char = text[end]
            if char == quote or char in '<>"|?*\x00\r\n' or (
                quote is None and (char.isspace() or char == "'")
            ):
                break
            end += 1
        value = _trim(text[start:end])
        occupied[start:end] = b"\1" * (end - start)
        if len(value) > LIMITS["value_characters"]:
            reason("value_length_limit")
            continue
        if value.startswith("\\\\") and not value[2:].split("\\", 1)[-1]:
            continue  # UNC must include a share.
        observations.append((start, "unc_path" if value.startswith("\\\\")
                             else "windows_path", value, value))
    for match in _URL.finditer(text):
        start = match.start()
        if occupied[start]:
            continue
        occupied[start:match.end()] = b"\1" * (match.end() - start)
        value = _trim(match.group())
        if len(value) > LIMITS["value_characters"]:
            reason("value_length_limit")
            continue
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            _ = parsed.port  # Reject malformed ports without resolving/opening the URL.
        except ValueError:
            continue
        if not hostname or not (host := _host(hostname)):
            continue
        observations.append((start, "url", value, value))
        authority_start = value.index("://") + 3
        authority = parsed.netloc
        host_start = authority_start + authority.rfind("@") + 1
        if value[host_start:host_start + 1] == "[":
            host_start += 1
        raw_host = value[host_start:host_start + len(hostname)]
        observations.append((start + host_start, host[0], host[1], raw_host))
    for match in _TOKEN.finditer(text):
        start = match.start()
        if occupied[start]:
            continue
        raw = match.group().rstrip(".")
        if len(raw) > 253:
            continue
        # Single-colon host:port syntax is not a naked IPv6 address.
        candidate = _host(raw)
        if candidate:
            observations.append((start, candidate[0], candidate[1], raw))
    return sorted(observations, key=lambda item: (item[0], item[1]))


def collect_indicators(results):
    """Collect JSON-compatible source observations; accept only finite list/tuple input.

    No recursion or generic iterable consumption. Offsets are zero-based and refer
    to the sample only for validated ASCII / UTF-16LE string source metadata.
    """
    reasons = []

    def reason(code):
        if code not in reasons:
            reasons.append(code)

    output = {"schema_version": 1, "scope": "existing_static_strings_only",
              "status": "completed", "partial": False, "reasons": reasons,
              "limits": dict(LIMITS), "indicators": []}
    if not isinstance(results, (list, tuple)):
        reason("invalid_results")
        results = []
    if len(results) > LIMITS["results"]:
        reason("result_limit")
    index = {}
    consumed = strings_count = occurrences = 0
    found_strings = False
    stop = False
    for result in results[:LIMITS["results"]]:
        if not isinstance(result, Mapping):
            reason("invalid_result")
            continue
        if result.get("inspection") != "strings":
            continue
        findings = result.get("findings")
        if not isinstance(findings, Mapping):
            reason("invalid_strings_result")
            continue
        strings = findings.get("strings")
        if not isinstance(strings, (list, tuple)):
            reason("missing_strings")
            continue
        found_strings = True
        if findings.get("partial"):
            reason("upstream_partial")
        if findings.get("limit_reached"):
            reason("upstream_entry_limit")
        if len(strings) > LIMITS["strings_per_result"]:
            reason("string_entry_limit")
        step = result.get("step_id")
        if step is not None and not (
            isinstance(step, str) or type(step) is int and 0 <= step <= 2**63 - 1
        ):
            step = None
            reason("invalid_source_step")
        if isinstance(step, str) and len(step) > LIMITS["source_step_characters"]:
            step = step[:LIMITS["source_step_characters"]]
            reason("source_metadata_limit")
        for entry in strings[:LIMITS["strings_per_result"]]:
            if strings_count >= LIMITS["strings_total"]:
                reason("total_string_limit")
                stop = True
                break
            strings_count += 1
            if not isinstance(entry, Mapping) or not isinstance(entry.get("text"), str):
                reason("invalid_string_entry")
                continue
            text = entry["text"]
            if len(text) > LIMITS["text_characters_per_string"]:
                reason("string_length_limit")
                continue
            encoded = text.encode("utf-8", errors="replace")
            remaining = LIMITS["text_bytes"] - consumed
            if len(encoded) > remaining:
                # Do not create a false domain/path by cutting an arbitrary token.
                reason("text_budget")
                stop = True
                break
            consumed += len(encoded)
            encoding = entry.get("encoding")
            if not isinstance(encoding, str):
                encoding = None
            elif len(encoding) > LIMITS["encoding_characters"]:
                encoding = encoding[:LIMITS["encoding_characters"]]
                reason("source_metadata_limit")
            source_offset = entry.get("offset")
            if type(source_offset) is not int or not 0 <= source_offset <= 2**63 - 1:
                source_offset = None
            codec = encoding.lower().replace("_", "-") if encoding else ""
            precise = codec == "ascii" and text.isascii()
            wide = codec in ("utf-16le", "utf-16-le") and not any(
                0xD800 <= ord(char) <= 0xDFFF for char in text
            )
            byte_positions = [0]
            if wide:
                for char in text:
                    byte_positions.append(byte_positions[-1] + (4 if ord(char) > 65535 else 2))
            for offset, kind, value, raw in _observations(text, reason):
                if occurrences >= LIMITS["occurrences"]:
                    reason("occurrence_limit")
                    stop = True
                    break
                occurrences += 1
                byte_offset = None
                if source_offset is not None and (precise or wide):
                    byte_offset = source_offset + (byte_positions[offset] if wide else offset)
                    if byte_offset > 2**63 - 1:
                        byte_offset = None
                if byte_offset is None:
                    reason("offset_precision_unavailable")
                source = {"source_step": step, "inspection": "strings", "encoding": encoding,
                          "source_offset": source_offset, "byte_offset": byte_offset,
                          "text_offset": offset, "raw_value": raw}
                key = kind, value
                if key not in index:
                    if len(index) >= LIMITS["indicators"]:
                        reason("indicator_limit")
                        continue
                    index[key] = {"type": kind, "value": value, "sources": []}
                    output["indicators"].append(index[key])
                sources = index[key]["sources"]
                if source not in sources:
                    if len(sources) >= LIMITS["sources_per_indicator"]:
                        reason("source_limit")
                    else:
                        sources.append(source)
            if stop:
                break
        if stop:
            break
    if not found_strings:
        reason("missing_strings")
    output["partial"] = bool(reasons)
    output["status"] = "unsupported" if not found_strings else "limited" if reasons else "completed"
    return output
