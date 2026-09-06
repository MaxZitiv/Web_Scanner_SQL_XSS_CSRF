"""Форматирование статистики, сообщений и строк результатов панели."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QTableWidget, QTextEdit


def normalize_stat_value(stat_name: str, value: object) -> int | str:
    if stat_name == "scan_time":
        return str(value) if value is not None else "00:00:00"
    try:
        number = int(value) if isinstance(value, (int, float)) else int(str(value))
    except (ValueError, TypeError, OverflowError):  # fmt: skip
        number = 0
    return max(0, number)


def scan_summary(result: Mapping[str, Any], *, stopped: bool = False) -> tuple[str, ...]:
    try:
        duration = float(result.get("scan_duration", 0) or 0)
    except (TypeError, ValueError, OverflowError):  # fmt: skip
        duration = 0.0
    if not math.isfinite(duration) or duration < 0:
        duration = 0.0
    return (
        "⏹ Сканирование остановлено" if stopped else "✅ Сканирование завершено!",
        "📊 Результаты:",
        f"  • Просканировано URL: {result.get('total_urls_scanned', 0)}",
        f"  • Найдено уязвимостей: {result.get('total_vulnerabilities', 0)}",
        f"  • Время сканирования: {duration:.2f}s",
    )


def append_log(log_text: QTextEdit, message: str) -> None:
    from PyQt6.QtGui import QTextCursor

    # QTextEdit.append распознаёт HTML. Вставка обычного текста сохраняет
    # и теги payload, и значимые пробелы/переносы, не интерпретируя разметку.
    document = log_text.document()
    if document is None:
        return
    cursor = QTextCursor(document)
    cursor.movePosition(QTextCursor.MoveOperation.End)
    if not document.isEmpty():
        cursor.insertBlock()
    cursor.insertText(message)
    scroll_bar = log_text.verticalScrollBar()
    if scroll_bar is not None:
        scroll_bar.setValue(scroll_bar.maximum())


def add_vulnerability_row(table: QTableWidget, url: str, vulnerability_type: str, details: str) -> None:
    from PyQt6.QtGui import QColor
    from PyQt6.QtWidgets import QTableWidgetItem

    from utils.performance import get_local_timestamp
    from utils.vulnerability_info import extract_location_from_details

    row = table.rowCount()
    table.insertRow(row)
    color = QColor({"sql": "#ffcccc", "xss": "#ffffcc"}.get(vulnerability_type.lower(), "#ccffcc"))
    values = (
        vulnerability_type,
        url,
        extract_location_from_details(details) or details,
        "Высокая",
        get_local_timestamp(),
    )
    for column, value in enumerate(values):
        item = QTableWidgetItem(value)
        item.setBackground(color)
        if column == 2:
            item.setToolTip(details)
        table.setItem(row, column, item)
