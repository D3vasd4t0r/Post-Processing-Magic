"""Synthetic XLSX package tests; no real evidence, Office, or viewer is opened."""

import os
import zipfile
from xml.sax.saxutils import escape

import pytest

from forensic_app import xlsx_preview as preview


def package(path, sheet_xml=None, *, extras=None, target="worksheets/sheet1.xml"):
    sheet_xml = sheet_xml or (
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Name</t></is></c>'
        '<c r="B1" t="inlineStr"><is><t>Count</t></is></c></row>'
        '<row r="2"><c r="A2" t="inlineStr"><is><t>Beta</t></is></c>'
        '<c r="B2"><v>10</v></c></row>'
        '<row r="3"><c r="A3" t="inlineStr"><is><t>Alpha</t></is></c>'
        '<c r="B3"><v>2</v></c></row></sheetData></worksheet>'
    )
    parts = {
        "[Content_Types].xml": (
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/></Types>'
        ),
        "_rels/.rels": (
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="r1" Type="officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>'
        ),
        "xl/workbook.xml": (
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Evidence" sheetId="1" r:id="rId1"/></sheets></workbook>'
        ),
        "xl/_rels/workbook.xml.rels": (
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="{escape(target)}"/>'
            '</Relationships>'
        ),
        "xl/worksheets/sheet1.xml": sheet_xml,
    }
    parts.update(extras or {})
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in parts.items():
            archive.writestr(name, content)


def test_sheet_selection_literal_search_and_numeric_sort_before_page(tmp_path):
    path = tmp_path / "result.xlsx"
    package(path)
    assert preview.list_xlsx_sheets(path) == {
        "sheets": [{"id": "s1", "name": "Evidence", "state": "visible"}]}
    result = preview.preview_xlsx(path, sort_column=1, sort_kind="number", limit=1)
    assert result["columns"] == ["Name", "Count"]
    assert result["rows"][0]["values"] == ["Alpha", "2"]
    assert result["has_more"] and result["partial_reason"] == "page_limit"
    assert preview.preview_xlsx(path, offset=1, sort_column=1, sort_kind="number")[
        "rows"][0]["values"] == ["Beta", "10"]
    assert preview.preview_xlsx(path, search="ALP")["rows"][0]["line"] == 3
    with pytest.raises(preview.XLSXPreviewError, match="Blatt-ID"):
        preview.preview_xlsx(path, sheet_id="../sheet1.xml")


def test_formula_is_only_cached_text_and_never_evaluated(tmp_path):
    path = tmp_path / "formula.xlsx"
    sheet = (
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Result</t></is></c></row>'
        '<row r="2"><c r="A2"><f>WEBSERVICE("https://invalid.example")</f>'
        '<v>42</v></c></row>'
        '<row r="3"><c r="A3"><f>1+2</f></c></row></sheetData></worksheet>'
    )
    package(path, sheet)
    result = preview.preview_xlsx(path)
    assert [row["values"] for row in result["rows"]] == [["42"], []]
    assert [row["formula_cells"] for row in result["rows"]] == [[0], [0]]
    assert "keine Berechnung" in result["note"]


@pytest.mark.parametrize("name", ["../evil.xml", "/absolute.xml", "xl/../evil.xml",
                                  "C:/evil.xml", "xl/file:stream"])
def test_unsafe_archive_names_are_rejected(tmp_path, name):
    path = tmp_path / "unsafe.xlsx"
    package(path, extras={name: "bad"})
    with pytest.raises(preview.XLSXPreviewError, match="Paketpfad"):
        preview.preview_xlsx(path)


def test_malformed_zip_and_relationships_rejected(tmp_path):
    path = tmp_path / "broken.xlsx"
    path.write_bytes(b"not a ZIP")
    with pytest.raises(preview.XLSXPreviewError):
        preview.list_xlsx_sheets(path)
    package(path, target="../../outside.xml")
    with pytest.raises(preview.XLSXPreviewError):
        preview.preview_xlsx(path)
    package(path, extras={"xl/worksheets/_rels/sheet1.xml.rels": (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="x" Type="hyperlink" Target="https://invalid.example" '
        'TargetMode="External"/></Relationships>'
    )})
    with pytest.raises(preview.XLSXPreviewError, match="externe"):
        preview.preview_xlsx(path)


def test_dtd_and_macro_content_type_rejected(tmp_path):
    path = tmp_path / "unsafe.xlsx"
    package(path, extras={"xl/other.xml": '<!DOCTYPE x [<!ENTITY e "hi">]><x>&e;</x>'})
    with pytest.raises(preview.XLSXPreviewError, match="DTD"):
        preview.preview_xlsx(path)
    package(path, extras={"xl/vbaProject.bin": b"fake"})
    with pytest.raises(preview.XLSXPreviewError, match="aktive"):
        preview.preview_xlsx(path)


def test_preflight_budgets_and_row_partial(tmp_path, monkeypatch):
    path = tmp_path / "limits.xlsx"
    package(path)
    monkeypatch.setattr(preview, "MAX_ENTRIES", 4)
    with pytest.raises(preview.XLSXPreviewError, match="Eintragslimit"):
        preview.preview_xlsx(path)
    monkeypatch.setattr(preview, "MAX_ENTRIES", 256)
    monkeypatch.setattr(preview, "MAX_XML_BYTES", 32)
    with pytest.raises(preview.XLSXPreviewError, match="XML"):
        preview.preview_xlsx(path)
    monkeypatch.setattr(preview, "MAX_XML_BYTES", 16 * 1024**2)
    monkeypatch.setattr(preview, "MAX_ROWS", 1)
    result = preview.preview_xlsx(path)
    assert result["partial_reason"] == "row_limit"
    assert result["scanned_rows"] == 1


def test_regular_file_and_argument_validation(tmp_path):
    path = tmp_path / "result.xlsx"
    package(path)
    for options in ({"offset": True}, {"limit": 0}, {"search": "x" * 129},
                    {"sort_column": -1}, {"sort_kind": "formula"}, {"descending": 1}):
        with pytest.raises(preview.XLSXPreviewError):
            preview.preview_xlsx(path, **options)
    alias = tmp_path / "alias.xlsx"
    os.link(path, alias)
    with pytest.raises(preview.XLSXPreviewError, match="reguläre"):
        preview.preview_xlsx(path)

def test_backslash_name_and_utf16_dtd_rejected(tmp_path):
    with pytest.raises(preview.XLSXPreviewError, match="Paketpfad"):
        preview._safe_name("xl\\evil.xml")
    path = tmp_path / "utf16.xlsx"
    package(path, extras={"xl/other.xml": (
        '<!DOCTYPE x [<!ENTITY e "hi">]><x>&e;</x>'.encode("utf-16")
    )})
    with pytest.raises(preview.XLSXPreviewError, match="UTF-8"):
        preview.preview_xlsx(path)


def test_descending_sort_keeps_invalid_number_at_end(tmp_path):
    path = tmp_path / "sort.xlsx"
    sheet = (
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>N</t></is></c></row>'
        '<row r="2"><c r="A2"><v>2</v></c></row>'
        '<row r="3"><c r="A3" t="inlineStr"><is><t>bad</t></is></c></row>'
        '<row r="4"><c r="A4"><v>10</v></c></row></sheetData></worksheet>'
    )
    package(path, sheet)
    rows = preview.preview_xlsx(path, sort_column=0, sort_kind="number", descending=True)["rows"]
    assert [row["values"][0] for row in rows] == ["10", "2", "bad"]
