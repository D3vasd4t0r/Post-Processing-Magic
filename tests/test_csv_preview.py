"""Synthetic CSV previews: no user evidence or running service is touched."""

import os

import pytest

from forensic_app import csv_preview


def test_search_pages_are_literal_and_cells_remain_text(tmp_path):
    path = tmp_path / "table.csv"
    path.write_bytes(
        b'name,note\n'
        b'Alpha,"<img src=x onerror=alert(1)>"\n'
        b'Beta,"first line\nsecond line"\n'
        b'Gamma,"a ""quoted"" value"\n'
        b'Delta,"100%_literal"\n')
    first = csv_preview.preview_csv(path, limit=2)
    assert first["columns"] == ["name", "note"]
    assert first["rows"][0] == {"line": 2, "values": ["Alpha", "<img src=x onerror=alert(1)>"]}
    assert first["rows"][1]["values"] == ["Beta", "first line\nsecond line"]
    assert first["has_more"] and first["partial_reason"] == "page_limit"
    second = csv_preview.preview_csv(path, offset=first["next_offset"], limit=2)
    assert [item["line"] for item in second["rows"]] == [5, 6]
    assert second["rows"][0]["values"][1] == 'a "quoted" value'
    assert not second["has_more"] and not second["partial"]
    assert csv_preview.preview_csv(path, search="%_", limit=5)["rows"][0]["line"] == 6
    assert csv_preview.preview_csv(path, search="ALPHA")["rows"][0]["line"] == 2


@pytest.mark.parametrize(("separator", "expected"), [(";", ";"), ("\t", "\t")])
def test_bom_and_separator(tmp_path, separator, expected):
    path = tmp_path / "table.csv"
    path.write_bytes(f'Name{separator}Value\r\nOne{separator}"two{separator}three"\r\n'
                     .encode("utf-8-sig"))
    result = csv_preview.preview_csv(path)
    assert result["delimiter"] == expected
    assert result["encoding"] == "utf-8-sig"
    assert result["rows"] == [{"line": 2, "values": ["One", f"two{separator}three"]}]


def test_byte_boundary_drops_incomplete_record_and_declares_partial(tmp_path, monkeypatch):
    monkeypatch.setattr(csv_preview, "MAX_READ_BYTES", 24)
    path = tmp_path / "table.csv"
    path.write_text("A,B\n1,ok\n2,unfinished value\n3,unseen\n", encoding="utf-8")
    result = csv_preview.preview_csv(path)
    assert result["rows"] == [{"line": 2, "values": ["1", "ok"]}]
    assert result["partial"] and result["partial_reason"] == "read_limit"
    assert result["next_offset"] is None
    assert "begrenzt" in result["note"]


def test_row_limit_and_unbounded_total_never_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(csv_preview, "MAX_ROWS", 2)
    path = tmp_path / "table.csv"
    path.write_text("A\n1\n2\n3\n", encoding="utf-8")
    result = csv_preview.preview_csv(path, limit=5)
    assert [row["values"] for row in result["rows"]] == [["1"], ["2"]]
    assert result["partial_reason"] == "row_limit"
    assert result["scanned_rows"] == 2
    assert "total" not in result


def test_overlong_field_and_too_many_columns_fail_before_large_output(tmp_path, monkeypatch):
    monkeypatch.setattr(csv_preview, "MAX_FIELD_CHARS", 8)
    path = tmp_path / "table.csv"
    path.write_text('A,B\n1,"123456789"\n', encoding="utf-8")
    with pytest.raises(csv_preview.CSVPreviewError, match="Feld"):
        csv_preview.preview_csv(path)
    monkeypatch.setattr(csv_preview, "MAX_COLUMNS", 2)
    path.write_text("A,B,C\n1,2,3\n", encoding="utf-8")
    with pytest.raises(csv_preview.CSVPreviewError, match="Spalten"):
        csv_preview.preview_csv(path)


def test_invalid_encoding_and_arguments(tmp_path):
    path = tmp_path / "table.csv"
    path.write_bytes(b"A,B\n1,\xff\n")
    with pytest.raises(csv_preview.CSVPreviewError, match="UTF-8"):
        csv_preview.preview_csv(path)
    path.write_text("A,B\n1,2\n", encoding="utf-8")
    for options in ({"offset": -1}, {"limit": 0}, {"limit": 51}, {"search": "x" * 129},
                    {"offset": True}, {"limit": True}):
        with pytest.raises(csv_preview.CSVPreviewError):
            csv_preview.preview_csv(path, **options)


def test_file_size_and_malformed_quote_rejected(tmp_path, monkeypatch):
    path = tmp_path / "table.csv"
    path.write_bytes(b"A\n123456\n")
    monkeypatch.setattr(csv_preview, "MAX_FILE_BYTES", 5)
    with pytest.raises(csv_preview.CSVPreviewError, match="Dateigrößenlimit"):
        csv_preview.preview_csv(path)
    monkeypatch.setattr(csv_preview, "MAX_FILE_BYTES", 2 * 1024**3)
    path.write_bytes(b'A,B\n1,"unclosed')
    with pytest.raises(csv_preview.CSVPreviewError, match="offenen"):
        csv_preview.preview_csv(path)


def test_link_and_hardlink_rejected(tmp_path):
    path = tmp_path / "table.csv"
    path.write_text("A\n1\n", encoding="utf-8")
    alias = tmp_path / "hardlink.csv"
    os.link(path, alias)
    with pytest.raises(csv_preview.CSVPreviewError, match="reguläre"):
        csv_preview.preview_csv(path)
    alias.unlink()
    shortcut = tmp_path / "link.csv"
    try:
        shortcut.symlink_to(path)
    except (NotImplementedError, OSError):
        pytest.skip("Symlinks are unavailable in this test environment")
    with pytest.raises(ValueError, match="Verknüpfung"):
        csv_preview.preview_csv(shortcut)


def test_sort_and_filter_apply_before_page_and_preserve_values(tmp_path):
    path = tmp_path / "sort.csv"
    path.write_text("Name,Value,Time\nC,10,2026-01-03\nA,2,2026-01-01\nB,no,invalid\nD,1,2026-01-02\n", encoding="utf-8")
    result = csv_preview.preview_csv(path, sort_column=1, sort_kind="number", limit=2)
    assert [row["values"][1] for row in result["rows"]] == ["1", "2"]
    assert result["scanned_rows"] == 4
    assert csv_preview.preview_csv(path, sort_column=1, sort_kind="number", offset=2)["rows"][0]["values"][1] == "10"
    result = csv_preview.preview_csv(path, sort_column=2, sort_kind="time", descending=True)
    assert [row["values"][0] for row in result["rows"]] == ["C", "D", "A", "B"]
    assert len(csv_preview.preview_csv(path, search="2026", limit=2)["rows"]) == 2
    for options in ({"sort_column": 4}, {"sort_column": True}, {"sort_kind": "eval"}):
        with pytest.raises(csv_preview.CSVPreviewError):
            csv_preview.preview_csv(path, **options)
