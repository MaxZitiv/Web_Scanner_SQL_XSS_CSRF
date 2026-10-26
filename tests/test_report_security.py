import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest
from bs4 import BeautifulSoup

from export.export import (
    export_single_scan_to_csv,
    export_single_scan_to_html,
    export_to_csv,
    export_to_html,
    export_to_json,
    format_scan_data_for_export,
)
from utils.report_safety import csv_cell, result_records, write_csv_rows

MARKER = '<img src="https://attacker.invalid/pixel" onerror="alert(1)"><script>alert(2)</script>&"'


def hostile_scan() -> dict[str, Any]:
    return {
        "id": MARKER,
        "url": MARKER,
        "timestamp": MARKER,
        "scan_type": MARKER,
        "status": MARKER,
        "result": [
            dict.fromkeys(
                ("url", "type", "parameter", "method", "field", "action", "payload", "test_url", "details"), MARKER
            )
            | {"status": "Vulnerable", "severity": "high"}
        ],
    }


@pytest.mark.parametrize("single", [False, True])
def test_html_is_inert_and_keeps_payload_as_text(tmp_path: Path, single: bool) -> None:
    path = tmp_path / "report.html"
    scan = hostile_scan()
    if single:
        scan["result"] = json.dumps(scan["result"])
        assert export_single_scan_to_html(scan, str(path))
    else:
        assert export_to_html([scan], str(path))
    text = path.read_text()
    document = BeautifulSoup(text, "html.parser")
    assert not document.find_all(["script", "img", "iframe", "form", "object", "embed", "svg"])
    assert MARKER in document.get_text()
    assert "&lt;script&gt;" in text
    csp = document.find("meta", attrs={"http-equiv": "Content-Security-Policy"})
    assert csp is not None
    assert "default-src 'none'" in str(csp)
    assert "script-src 'none'" in str(csp)
    assert "base-uri 'none'" in str(csp)
    for element in document.find_all(True):
        assert not any(str(key).startswith("on") for key in element.attrs)


@pytest.mark.parametrize(
    "value", ["=1+1", "+cmd", "-cmd", "@SUM(1)", "  =1", "\t=1", "\r=1", "\n=1", "\ufeff=1", "\u200b=1", "＝1"]
)
def test_csv_formulas_are_neutralized(value: str) -> None:
    assert csv_cell(value) == "'" + value


@pytest.mark.parametrize("value", ["ordinary", "https://scanner.example", "already ' text", 42, -3, 1.5, None])
def test_non_formula_values_are_unchanged(value: object) -> None:
    assert csv_cell(value) == value


def test_csv_headers_and_late_columns_are_protected() -> None:
    stream = io.StringIO()
    write_csv_rows(stream, [{"=header": "=1", "a": "ok"}, {"b": "\t=2", "=header": "normal"}])
    rows = list(csv.reader(io.StringIO(stream.getvalue())))
    assert rows == [["'=header", "a", "b"], ["'=1", "ok", ""], ["normal", "", "'\t=2"]]


@pytest.mark.parametrize("single", [False, True])
def test_csv_exporters_cover_values_and_dynamic_column_names(tmp_path: Path, single: bool) -> None:
    path = tmp_path / "report.csv"
    scan: dict[str, Any] = {
        "url": "=HYPERLINK()",
        "result": [{"type": "=formula", "payload": "@command", "status": "Vulnerable"}],
    }
    if single:
        scan["result"] = json.dumps(scan["result"])
        assert export_single_scan_to_csv(scan, str(path))
    else:
        assert export_to_csv([scan, {"url": "second", "result": [{"type": "xss"}]}], str(path))
    rows = list(csv.reader(io.StringIO(path.read_text())))
    assert any(cell.startswith("'=formula") for cell in rows[0])
    assert any("'=HYPERLINK()" in row for row in rows[1:])
    if single:
        assert any("'@command" in row for row in rows[1:])


def test_json_keeps_raw_payloads_and_source_objects_are_not_modified(tmp_path: Path) -> None:
    scan = hostile_scan()
    snapshot = json.dumps(scan)
    path = tmp_path / "report.json"
    assert export_to_json([scan], str(path))
    parsed = json.loads(path.read_text())
    assert parsed["detailed_results"][0]["vulnerabilities"][MARKER]["details"][0]["payload"] == MARKER
    assert json.dumps(scan) == snapshot


def test_gui_high_severity_is_not_silently_downgraded() -> None:
    report = format_scan_data_for_export(
        [{"URL": "https://scanner.example", "Тип уязвимости": "SQL", "Серьёзность": "Высокая"}]
    )
    assert report[0]["summary"]["risk_level"] == "HIGH"
    assert report[0]["summary"]["vulnerable_count"] == 1


@pytest.mark.parametrize("raw", [None, 1, {}, "{bad json", '[null, 1, "text", {"type": "xss"}]'])
def test_result_records_tolerate_malformed_entries(raw: object) -> None:
    records = result_records(raw)
    assert records == ([{"type": "xss"}] if isinstance(raw, str) and raw.startswith("[null") else [])
