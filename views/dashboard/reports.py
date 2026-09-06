"""Сбор данных таблицы и выбор формата отчёта; сохранение выполняет ExportUtils."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QTableWidget, QWidget

REPORT_COLUMNS = ("Тип уязвимости", "URL", "Параметр", "Серьёзность", "Время обнаружения")
REPORT_FORMATS = {"JSON": "json", "CSV": "csv", "PDF": "pdf", "HTML": "html", "TXT": "txt"}


def collect_report_rows(table: QTableWidget) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for row in range(table.rowCount()):
        items = [table.item(row, column) for column in range(len(REPORT_COLUMNS))]
        # Незавершённая строка не должна попадать в экспорт.
        if any(item is None for item in items):
            continue
        rows.append({key: item.text() for key, item in zip(REPORT_COLUMNS, items, strict=True) if item is not None})
    return rows


def select_report_format(parent: QWidget) -> tuple[str, str] | None:
    from PyQt6.QtWidgets import QMessageBox

    dialog = QMessageBox(parent)
    dialog.setWindowTitle("Формат отчёта")
    dialog.setText("Выберите формат сохранения:")
    dialog.setIcon(QMessageBox.Icon.Question)
    for option in REPORT_FORMATS:
        dialog.addButton(option, QMessageBox.ButtonRole.AcceptRole)
    cancel_button = dialog.addButton("Отмена", QMessageBox.ButtonRole.RejectRole)
    dialog.setEscapeButton(cancel_button)
    dialog.exec()
    clicked = dialog.clickedButton()
    selected = clicked.text() if clicked is not None else ""
    if selected not in REPORT_FORMATS:
        return None
    return selected, REPORT_FORMATS[selected]


def export_dashboard_report(parent: QWidget, table: QTableWidget, user_id: int) -> None:
    from utils.error_handler import error_handler
    from utils.export_utils import ExportUtils

    rows = collect_report_rows(table)
    if not rows:
        error_handler.show_info_message("Информация", "Нет данных для отчета. Сначала выполните сканирование.")
        return
    selected = select_report_format(parent)
    if selected is None:
        return
    format_name, extension = selected
    # ExportUtils сам показывает результат и ошибки. Отмена выбора файла
    # не должна сопровождаться дополнительным сообщением об ошибке.
    ExportUtils.export_data(parent, rows, format_name, extension, user_id)
