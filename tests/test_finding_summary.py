"""The summary must keep the scope of each static inspector explicit."""

from forensic_app.finding_summary import summarize_finding


def saved(inspector, findings, *, file_bytes=20_000_000):
    return {
        "scope": "Nur statische Rohdatenprüfung. Keine Malware-Diagnose und keine Entwarnung.",
        "inspection": inspector,
        "input": {"bytes": file_bytes, "sha1": "a" * 40, "sha256": "b" * 64},
        "findings": findings,
    }


def test_metadata_separates_whole_input_hashes_from_first_mib_entropy():
    summary = summarize_finding(saved("metadata", {
        "file_bytes": 20_000_000, "inspected_bytes": 1_048_576, "partial": True,
        "entropy_bits_per_byte": 7.991,
        "limitation": "Entropie nur über das erste MiB; kein Malware-Nachweis.",
    }))
    assert summary["inspector"]["status"] == "limited"
    assert summary["coverage"]["byte_partial"] is True
    assert summary["observations"]["entropy_scope"] == "first_1_mib"
    assert summary["observations"]["entropy_sample_bytes"] == 1_048_576
    assert summary["input"]["bytes"] == 20_000_000
    assert summary["input"]["sha256"] == "b" * 64
    assert summary["input"]["hash_scope"] == "whole_input"


def test_strings_and_pdf_record_independent_limits_even_when_bytes_fit():
    strings = summarize_finding(saved("strings", {
        "file_bytes": 100, "inspected_bytes": 100, "partial": False,
        "strings": [{"text": "x"}] * 2000, "entry_limit": 2000, "limit_reached": True,
    }, file_bytes=100))
    assert strings["coverage"]["byte_partial"] is False
    assert strings["coverage"]["entry_limit_reached"] is True
    assert strings["inspector"]["status"] == "limited"
    assert strings["observations"]["reported_strings"] == 2000

    pdf = summarize_finding(saved("pdf", {
        "file_bytes": 100, "inspected_bytes": 100, "partial": False,
        "keyword_counts": {"JavaScript": 2, "OpenAction": 0},
        "name_token_limit": 100000, "name_token_limit_reached": True,
    }, file_bytes=100))
    assert pdf["coverage"]["byte_partial"] is False
    assert pdf["coverage"]["name_token_limit_reached"] is True
    assert pdf["inspector"]["status"] == "limited"
    assert pdf["observations"]["keyword_counts"] == {"JavaScript": 2, "OpenAction": 0}


def test_office_legacy_is_unsupported_and_ooxml_is_directory_only():
    legacy = summarize_finding(saved("office", {
        "container": "OLE", "limitation": "Legacy-Inhalte nicht geparst. Keine Aussage zu Makros."
    }))
    assert legacy["inspector"]["status"] == "unsupported"
    assert "nicht geparst" in legacy["inspector"]["scope"]
    assert legacy["coverage"]["byte_partial"] is None

    ooxml = summarize_finding(saved("office", {
        "container": "OOXML", "entries": [{}] * 12,
        "macro_named_entries": ["word/vbaProject.bin"] * 12,
        "embedded_named_entries": [],
    }))
    assert ooxml["inspector"]["status"] == "completed"
    assert "Zentralverzeichnis" in ooxml["inspector"]["scope"]
    assert ooxml["coverage"]["inspected_bytes"] is None
    assert ooxml["observations"]["directory_entries"] == 12
    assert len(ooxml["observations"]["macro_named_entries"]) == 5


def test_pe_scope_is_headers_only_and_missing_legacy_keys_stay_unknown():
    pe = summarize_finding(saved("pe", {
        "sections": [{"raw_range_valid": True}, {"raw_range_valid": False}],
        "machine_hex": "0x8664",
    }))
    assert pe["inspector"]["status"] == "completed"
    assert "Header" in pe["inspector"]["scope"]
    assert pe["coverage"]["byte_partial"] is None
    assert pe["observations"]["raw_range_invalid_count"] == 1

    old = summarize_finding({"inspection": "metadata", "findings": {"limitation": "old"}})
    assert old["inspector"]["status"] == "unknown"
    assert old["coverage"]["byte_partial"] is None
    assert old["input"]["sha256"] is None
    assert old["input"]["hash_scope"] is None
    old_strings = summarize_finding({"inspection": "strings", "findings": {
        "inspected_bytes": 10, "strings": [],
    }})
    assert old_strings["inspector"]["status"] == "unknown"


def test_supplied_error_and_unsupported_data_are_bounded():
    failed = summarize_finding({"inspection": "pdf", "status": "error", "error": "X" * 2000,
                                "findings": {"limitation": "Y" * 2000}})
    assert failed["inspector"]["status"] == "error"
    assert len(failed["observations"]["error"]) == 240
    assert len(failed["inspector"]["limitations"][0]) == 240
    unsupported = summarize_finding({"inspection": "strings", "findings": {"unsupported": True}})
    assert unsupported["inspector"]["status"] == "unsupported"
    assert summarize_finding({"inspection": [], "findings": []})["inspector"]["status"] == "unknown"
