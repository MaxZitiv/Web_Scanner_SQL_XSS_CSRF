"""Сквозной путь пейлоада: проверка → контроллер → БД → выбор алерта в ZAP."""

import asyncio
import json
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest

from payloads.sql import SAFE_SQL_PAYLOADS
from payloads.xss import SAFE_XSS_PAYLOADS
from utils.database import Database
from utils.vulnerability_info import format_vulnerability_details

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication, QDialog
except ImportError as error:
    pytest.skip(f"Native Qt libraries are unavailable: {error}", allow_module_level=True)
else:
    import aiohttp
    from bs4 import BeautifulSoup
    from bs4.element import Tag

    from controllers.scan_controller import ScanController
    from scanner.scanner_fixed import ScanWorker
    from ui import vulnerability_viewer as viewer_module
    from ui.vulnerability_viewer import ZapStyleVulnerabilityViewer


def select_finding(viewer: ZapStyleVulnerabilityViewer, finding_id: int) -> None:
    for row in range(viewer.alerts_table.rowCount()):
        item = viewer.alerts_table.item(row, 2)
        if item is not None and item.data(Qt.ItemDataRole.UserRole) == finding_id:
            viewer.on_alert_clicked(row, 2)
            return
    pytest.fail(f"Finding {finding_id} is missing from the alerts table")


@pytest.mark.asyncio
@pytest.mark.parametrize("scan_type", ["sql", "xss"])
async def test_detected_payload_survives_save_reload_and_zap_export(
    application: QApplication,
    history_database: Database,
    monkeypatch: pytest.MonkeyPatch,
    dialogs: dict[str, Mock],
    tmp_path: Path,
    scan_type: str,
) -> None:
    url = "https://scanner.example" + ("?id=1" if scan_type == "sql" else "")
    worker = ScanWorker(url, [scan_type], 1)
    session = cast(aiohttp.ClientSession, Mock())
    forms: list[Tag] = []
    if scan_type == "sql":
        # Срабатывает ВТОРОЙ пейлоад: UI не должен подставлять первый из каталога.
        request = AsyncMock(side_effect=[(Mock(), "ordinary page"), (Mock(), "syntax error")])
        expected = SAFE_SQL_PAYLOADS[1]
    else:
        expected = SAFE_XSS_PAYLOADS[0]
        request = AsyncMock(return_value=(Mock(), expected))
        form = BeautifulSoup(
            '<form action="/submit" method="post"><input type="text" name="q"></form>', "html.parser"
        ).find("form")
        assert isinstance(form, Tag)
        forms = [form]
    monkeypatch.setattr(worker, "smart_request", request)
    grouped: dict[str, list[dict[str, Any]]] = {scan_type: []}
    await worker.scan_single_url(
        session, asyncio.Semaphore(1), url, set(), grouped, asyncio.Queue(), 0, forms_to_scan=forms
    )
    assert request.await_count == (2 if scan_type == "sql" else 1)
    assert len(grouped[scan_type]) == 1
    assert grouped[scan_type][0]["payload"] == expected
    controller = ScanController(url, [scan_type], 1)
    assert await controller.save_scan_result({"url": url, "scan_types": [scan_type], "results": grouped})
    history_database.get_db_connection().close()

    monkeypatch.setattr(viewer_module, "db", history_database)
    viewer = ZapStyleVulnerabilityViewer(1)
    try:
        finding_id = history_database.get_all_vulnerabilities(1)[0]["id"]
        select_finding(viewer, finding_id)
        assert viewer.current_vulnerability is not None
        assert viewer.current_vulnerability["payload"] == expected
        assert viewer.detail_payload.text() == expected
        assert viewer.detail_payload.textFormat() == Qt.TextFormat.PlainText
        assert viewer.detail_payload.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByMouse
        assert viewer.detail_payload_label.text() == "Пейлоад:"

        # Экспорт из самого окна также берёт нормализованные данные из БД.
        path = tmp_path / "findings.json"
        dialog = Mock()
        dialog.exec.return_value = QDialog.DialogCode.Accepted
        dialog.get_export_settings.return_value = ("JSON", str(path))
        monkeypatch.setattr(viewer_module, "ExportDialog", Mock(return_value=dialog))
        viewer.export_vulnerabilities()
        exported = json.loads(path.read_text())
        assert next(row for row in exported if row["id"] == finding_id)["payload"] == expected
        dialogs["critical"].assert_not_called()
    finally:
        viewer.refresh_timer.stop()
        viewer.close()
        viewer.deleteLater()
        application.processEvents()


@pytest.mark.parametrize("stored", [True, False])
def test_legacy_payload_display_and_missing_data_message(
    application: QApplication,
    history_database: Database,
    monkeypatch: pytest.MonkeyPatch,
    stored: bool,
) -> None:
    expected = SAFE_SQL_PAYLOADS[3]
    with history_database.get_db_connection_cm() as conn:
        conn.execute(
            "UPDATE vulnerabilities SET payload = NULL, details = ? WHERE id = 1",
            (format_vulnerability_details(payload=expected) if stored else "Old finding without payload",),
        )
    monkeypatch.setattr(viewer_module, "db", history_database)
    viewer = ZapStyleVulnerabilityViewer(1)
    try:
        select_finding(viewer, 1)
        assert viewer.detail_payload.text() == (expected if stored else "Не сохранён")
        assert viewer.detail_payload.textFormat() == Qt.TextFormat.PlainText
        viewer.clear_vulnerability_details()
        assert viewer.detail_payload.text() == ""
    finally:
        viewer.refresh_timer.stop()
        viewer.close()
        viewer.deleteLater()
        application.processEvents()
