import pytest

from views.dashboard.presentation import normalize_stat_value, scan_summary
from views.dashboard.scan_state import ScanControls, ScanState, controls_for, prepare_scan_options


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 0), (0, 0), (12, 12), ("12", 12), (3.9, 3), (-8, 0), ("bad", 0), (float("nan"), 0), (float("inf"), 0)],
)
def test_numeric_stats_are_non_negative_integers(value: object, expected: int) -> None:
    assert normalize_stat_value("urls_scanned", value) == expected


@pytest.mark.parametrize(("value", "expected"), [(None, "00:00:00"), ("01:02:03", "01:02:03"), (15, "15")])
def test_scan_time_preserves_string_representation(value: object, expected: str) -> None:
    assert normalize_stat_value("scan_time", value) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("  example.com/path?q=Value  ", "https://example.com/path?q=Value"),
        ("http://example.com", "http://example.com"),
        ("https://example.com", "https://example.com"),
        ("HTTPS://example.com/CaseSensitive", "HTTPS://example.com/CaseSensitive"),
    ],
)
def test_scan_options_normalize_url_and_preserve_selected_types(url: str, expected: str) -> None:
    options = prepare_scan_options(url, ["xss", "sql", "xss"])
    assert options.url == expected
    assert options.scan_types == ("xss", "sql")
    assert options.timeout == 30


@pytest.mark.parametrize("url", ["", "   ", "http://", "https://", "ftp://example.com", "http://[invalid"])
def test_invalid_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        prepare_scan_options(url, ["sql"])


def test_url_length_is_checked_after_adding_https_prefix() -> None:
    url = "example.com/" + "a" * (2048 - len("https://example.com/"))
    assert len(prepare_scan_options(url, ["sql"]).url) == 2048
    with pytest.raises(ValueError, match="2048"):
        prepare_scan_options(url + "a", ["sql"])


@pytest.mark.parametrize("scan_types", [[], ["unknown"], ["sql", "unknown"]])
def test_missing_or_unknown_scan_types_are_rejected(scan_types: list[str]) -> None:
    with pytest.raises(ValueError):
        prepare_scan_options("https://example.com", scan_types)


@pytest.mark.parametrize(
    ("state", "controls"),
    [
        (ScanState.IDLE, ScanControls(True, True, False, False, False)),
        (ScanState.RUNNING, ScanControls(False, False, True, False, True)),
        (ScanState.PAUSED, ScanControls(False, False, False, True, True)),
        (ScanState.STOPPING, ScanControls(False, False, False, False, False)),
    ],
)
def test_scan_controls_have_one_consistent_state_table(state: ScanState, controls: ScanControls) -> None:
    assert controls_for(state) == controls


@pytest.mark.parametrize("duration", [None, "invalid", -1, float("nan"), float("inf")])
def test_summary_handles_invalid_duration_without_losing_results(duration: object) -> None:
    lines = scan_summary({"scan_duration": duration, "total_urls_scanned": 4, "total_vulnerabilities": 2})
    assert lines[0] == "✅ Сканирование завершено!"
    assert "4" in lines[2]
    assert "2" in lines[3]
    assert lines[-1].endswith("0.00s")


def test_summary_distinguishes_stopped_scan() -> None:
    lines = scan_summary({"scan_duration": "3.25"}, stopped=True)
    assert lines[0] == "⏹ Сканирование остановлено"
    assert lines[-1].endswith("3.25s")
