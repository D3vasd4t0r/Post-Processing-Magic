"""Synthetic in-memory observations only; no sample/tool access."""

import copy
import json

import pytest

from forensic_app.indicator_sources import LIMITS, collect_indicators


def results(*texts, encoding="ascii", offset=100, **findings):
    return [{"inspection": "strings", "step_id": "own-strings", "findings": {
        "strings": [{"text": text, "encoding": encoding, "offset": offset} for text in texts],
        **findings,
    }}]


def values(document, kind):
    return {item["value"] for item in document["indicators"] if item["type"] == kind}


def indicator(document, kind, value):
    return next(item for item in document["indicators"]
                if item["type"] == kind and item["value"] == value)


def test_pure_sources_dedup_and_url_host_offsets():
    text = "x https://Example.COM/a?q=1. 192.0.2.1 Example.COM"
    raw = results(text, text)
    original = copy.deepcopy(raw)
    document = collect_indicators(raw)
    assert raw == original
    assert document["status"] == "completed"
    assert values(document, "url") == {"https://Example.COM/a?q=1"}
    assert values(document, "domain") == {"example.com"}
    assert values(document, "ip") == {"192.0.2.1"}
    sources = indicator(document, "domain", "example.com")["sources"]
    assert [s["text_offset"] for s in sources] == [10, 39]
    assert [s["byte_offset"] for s in sources] == [110, 139]
    assert sources[0]["raw_value"] == "Example.COM"
    assert sources[0]["source_step"] == "own-strings"
    json.dumps(document, allow_nan=False)


@pytest.mark.parametrize("encoding", ["utf-16le", "utf-16-le", "UTF_16LE"])
def test_utf16_offsets_include_non_bmp_code_units(encoding):
    text = "\U0001f600 x example.org 2001:db8::1"
    document = collect_indicators(results(text, encoding=encoding, offset=12))
    assert document["status"] == "completed"
    for item in document["indicators"]:
        source = item["sources"][0]
        expected = 12 + len(text[:source["text_offset"]].encode("utf-16-le"))
        assert source["byte_offset"] == expected


@pytest.mark.parametrize("encoding,offset", [("utf8", 0), ("bogus", 1),
                                             ("ascii", None), ("ascii", -1),
                                             ("ascii", True), ("ascii", 2**63)])
def test_unknown_or_invalid_precision_is_not_invented(encoding, offset):
    document = collect_indicators(results("example.org", encoding=encoding, offset=offset))
    assert document["partial"]
    assert "offset_precision_unavailable" in document["reasons"]
    assert document["indicators"][0]["sources"][0]["byte_offset"] is None


def test_ascii_unicode_and_lone_surrogate_cannot_claim_exact_bytes():
    for encoding, text in [("ascii", "ü example.org"),
                           ("utf-16le", "\ud800 example.org")]:
        document = collect_indicators(results(text, encoding=encoding))
        assert document["indicators"][0]["sources"][0]["byte_offset"] is None


def test_strict_ip_domain_and_idna_no_version_or_file_suffixes():
    document = collect_indicators(results(
        "192.0.2.1 999.1.2.3 01.2.3.4 1.2.3.4.5 v1.2.3 2.10.20 "
        "file.exe file.pdf data.csv some.dll host_name.org -bad.org bad-.org "
        "example.org example.123 2001:db8::1 2001:db8::zz fe80::1%eth0 "
        "bücher.de xn--bcher-kva.de xn--invalid-.org faß.de xn--e28h.com",
        encoding="utf-16le"))
    assert values(document, "ip") == {"192.0.2.1", "2001:db8::1"}
    assert values(document, "domain") == {"example.org", "xn--bcher-kva.de"}
    assert len(indicator(document, "domain", "xn--bcher-kva.de")["sources"]) == 2


def test_paths_quotes_punctuation_unc_and_do_not_turn_names_into_domains():
    document = collect_indicators(results(
        r'''("C:\Program Files\test.exe"). \\server\share\test.pdf, C:\Temp\one.txt;'''))
    assert values(document, "windows_path") == {r"C:\Program Files\test.exe", r"C:\Temp\one.txt"}
    assert values(document, "unc_path") == {r"\\server\share\test.pdf"}
    assert not values(document, "domain")
    assert collect_indicators(results("\\\\server\\"))["indicators"] == []


def test_urls_ipv6_brackets_credentials_port_and_punctuation():
    document = collect_indicators(results(
        "(https://[2001:db8::1]:443/test). http://user:pw@EXAMPLE.org:80/x "
        "http://999.1.2.3/x http://example.org:bad/x http://example.org:99999/x"))
    assert values(document, "url") == {
        "https://[2001:db8::1]:443/test", "http://user:pw@EXAMPLE.org:80/x"}
    ip_source = indicator(document, "ip", "2001:db8::1")["sources"][0]
    assert ip_source["text_offset"] == 10
    assert ip_source["raw_value"] == "2001:db8::1"


def test_no_strings_empty_strings_and_unsupported_results():
    assert collect_indicators([])["status"] == "unsupported"
    assert collect_indicators([{"inspection": "pe", "findings": {}}])["indicators"] == []
    assert collect_indicators(results())["status"] == "completed"
    document = collect_indicators([{"inspection": "strings", "findings": {}}])
    assert document["reasons"] == ["missing_strings"]


def test_generic_iterables_are_never_consumed():
    def forbidden():
        raise AssertionError("must not consume iterables")
        yield None
    assert collect_indicators(forbidden())["reasons"] == ["invalid_results", "missing_strings"]
    document = collect_indicators([{"inspection": "strings", "findings": {"strings": forbidden()}}])
    assert document["status"] == "unsupported"


def test_duplicates_do_not_consume_indicator_limit_and_sources_are_bounded():
    document = collect_indicators(results(*[f"{' ' * n}same.example" for n in range(20)]))
    assert len(document["indicators"]) == 1
    assert len(document["indicators"][0]["sources"]) == LIMITS["sources_per_indicator"]
    assert document["reasons"] == ["source_limit"]


def test_indicator_limit_is_global_and_retained_duplicate_still_gets_sources():
    raw = results(*[f"d{n}.example d{n + 2000}.example" for n in range(1000)],
                  "excess.example d0.example")
    document = collect_indicators(raw)
    assert len(document["indicators"]) == 2000
    assert "indicator_limit" in document["reasons"]
    assert len(indicator(document, "domain", "d0.example")["sources"]) == 2


def test_result_string_and_upstream_limits_are_reported():
    raw = results("example.org", partial=True, limit_reached=True) * 65
    document = collect_indicators(raw)
    assert document["reasons"] == ["result_limit", "upstream_partial", "upstream_entry_limit"]
    raw = results(*["example.org"] * 2001)
    assert "string_entry_limit" in collect_indicators(raw)["reasons"]
    raw = results(*["example.org"] * 2000) * 9
    assert "total_string_limit" in collect_indicators(raw)["reasons"]


def test_text_budget_is_global_and_never_scans_a_cut_token():
    raw = results(*[" " * 4096] * 512, "not_scanned.example")
    document = collect_indicators(raw)
    assert document["indicators"] == []
    assert document["reasons"] == ["text_budget"]


def test_long_string_is_skipped_rather_than_inventing_a_truncated_domain():
    document = collect_indicators(results("example.org" + "x" * 5000))
    assert document["indicators"] == []
    assert document["reasons"] == ["string_length_limit"]


@pytest.mark.parametrize("prefix", ["https://example.org/", "C:\\"])
def test_oversized_url_or_path_has_explicit_limit(prefix):
    document = collect_indicators(results(prefix + "a" * 2100))
    assert not document["indicators"]
    assert document["reasons"] == ["value_length_limit"]


def test_occurrence_limit_bounds_repeated_sources_without_unbounded_output():
    document = collect_indicators(results(*["example.org " * 100] * 161))
    assert "occurrence_limit" in document["reasons"]
    assert len(document["indicators"]) == 1
    assert len(document["indicators"][0]["sources"]) == 8


def test_malformed_metadata_is_bounded_and_input_remains_unchanged():
    raw = results("example.org", encoding="a" * 100)
    raw[0]["step_id"] = "x" * 1000
    original = copy.deepcopy(raw)
    document = collect_indicators(raw)
    assert raw == original
    source = document["indicators"][0]["sources"][0]
    assert len(source["encoding"]) == 32
    assert len(source["source_step"]) == 128
    assert document["reasons"] == ["source_metadata_limit", "offset_precision_unavailable"]


def test_nested_malformed_values_do_not_crash():
    document = collect_indicators([None, {"inspection": "strings", "findings": None},
                                  {"inspection": "strings", "findings": {"strings": [None]}}])
    assert document["status"] == "limited"
    assert document["reasons"] == ["invalid_result", "invalid_strings_result", "invalid_string_entry"]
