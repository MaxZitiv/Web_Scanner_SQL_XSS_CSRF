"""Построение интерфейса панели без навигации и логики сканирования."""

from dataclasses import dataclass
from typing import Any, cast

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from views.statistics_widget import StatisticsWidget

DASHBOARD_STYLE = """
    QMainWindow { background-color: #ffffff; }
    QLabel { color: #333333; }
    QLineEdit {
        border: 1px solid #cccccc; border-radius: 3px;
        padding: 5px; background-color: #fafafa;
    }
    QLineEdit:focus { border: 2px solid #4CAF50; background-color: #ffffff; }
    QCheckBox { color: #333333; spacing: 5px; }
    QTableWidget {
        background-color: #ffffff; alternate-background-color: #f9f9f9;
        border: 1px solid #cccccc; gridline-color: #e0e0e0;
    }
    QTableWidget::item:selected { background-color: #4CAF50; }
    QHeaderView::section {
        background-color: #f0f0f0; padding: 5px;
        border: 1px solid #cccccc; font-weight: bold;
    }
"""


@dataclass(frozen=True)
class DashboardWidgets:
    central: QWidget
    profile_label: QLabel
    profile_btn: QPushButton
    statistics_btn: QPushButton
    reports_btn: QPushButton
    vulnerabilities_btn: QPushButton
    logout_btn: QPushButton
    url_input: QLineEdit
    sql_checkbox: QCheckBox
    xss_checkbox: QCheckBox
    csrf_checkbox: QCheckBox
    start_scan_btn: QPushButton
    pause_scan_btn: QPushButton
    resume_scan_btn: QPushButton
    stop_scan_btn: QPushButton
    statistics_widget: StatisticsWidget
    results_table: QTableWidget
    log_text: QTextEdit


def _label(text: str, *, bold: bool = False) -> QLabel:
    label = QLabel(text)
    font = QFont()
    font.setPointSize(10)
    font.setBold(bold)
    label.setFont(font)
    return label


def _scan_button_style(color: str, hover: str, pressed: str) -> str:
    return f"""
        QPushButton {{
            background-color: {color}; color: white; border: none;
            border-radius: 5px; font-weight: bold; padding: 5px;
        }}
        QPushButton:hover {{ background-color: {hover}; }}
        QPushButton:pressed {{ background-color: {pressed}; }}
        QPushButton:disabled {{ background-color: #cccccc; color: #666666; }}
    """


def build_dashboard_ui(parent: QWidget, username: str) -> DashboardWidgets:
    central = QWidget(parent)
    layout = QVBoxLayout(central)
    layout.setSpacing(10)
    layout.setContentsMargins(10, 10, 10, 10)

    profile_row = QHBoxLayout()
    profile_label = _label(f"👤 Пользователь: {username}")
    profile_row.addWidget(profile_label)
    profile_row.addStretch()
    nav_buttons = [
        QPushButton(text) for text in ("👤 Профиль", "📊 Статистика", "📋 Отчеты", "🔎 Уязвимости (ZAP)", "🚪 Выход")
    ]
    profile_btn, statistics_btn, reports_btn, vulnerabilities_btn, logout_btn = nav_buttons
    for button in nav_buttons:
        button.setMaximumWidth(140 if button is vulnerabilities_btn else 100)
        profile_row.addWidget(button)
    layout.addLayout(profile_row)

    url_row = QHBoxLayout()
    url_row.addWidget(_label("🔗 URL:"))
    url_input = QLineEdit()
    url_input.setPlaceholderText("Введите URL (https://example.com)")
    url_row.addWidget(url_input)
    url_row.addWidget(_label("🔎 Сканирование выполняется полностью"))
    layout.addLayout(url_row)

    types_row = QHBoxLayout()
    types_row.addWidget(_label("🔍 Типы сканирования:", bold=True))
    checkboxes = [QCheckBox(text) for text in ("SQL Injection", "XSS", "CSRF")]
    sql_checkbox, xss_checkbox, csrf_checkbox = checkboxes
    for checkbox in checkboxes:
        checkbox.setChecked(True)
        types_row.addWidget(checkbox)
    types_row.addStretch()
    layout.addLayout(types_row)

    scan_row = QHBoxLayout()
    scan_row.setSpacing(5)
    scan_buttons = [QPushButton(text) for text in ("▶ Начать сканирование", "⏸ Пауза", "▶ Продолжить", "⏹ Остановить")]
    start_btn, pause_btn, resume_btn, stop_btn = scan_buttons
    start_btn.setStyleSheet(_scan_button_style("#4CAF50", "#45a049", "#3d8b40"))
    stop_btn.setStyleSheet(_scan_button_style("#f44336", "#da190b", "#ba0000"))
    for button in scan_buttons:
        button.setMinimumHeight(35)
        scan_row.addWidget(button)
    layout.addLayout(scan_row)

    statistics = StatisticsWidget()
    layout.addWidget(statistics)
    layout.addWidget(_label("📋 Найденные уязвимости:", bold=True))
    results = QTableWidget(0, 5)
    cast(Any, results).setHorizontalHeaderLabels(
        ["Тип уязвимости", "URL", "Место в коде", "Серьёзность", "Время обнаружения"]
    )
    header = results.horizontalHeader()
    if header is not None:
        header.setStretchLastSection(True)
    results.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    results.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    results.setMinimumHeight(150)
    results.setAlternatingRowColors(True)
    results.resizeColumnsToContents()
    layout.addWidget(results)

    layout.addWidget(_label("📝 Лог событий:", bold=True))
    log_text = QTextEdit()
    log_text.setReadOnly(True)
    log_text.setMaximumHeight(120)
    log_text.setStyleSheet("""
        QTextEdit {
            background-color: #f5f5f5; border: 1px solid #cccccc;
            border-radius: 3px; font-family: Courier; font-size: 9pt;
        }
    """)
    document = log_text.document()
    if document is not None:
        # Ограничиваем память GUI при длительных сканированиях; файловые логи
        # и сохранённая история этим ограничением не затрагиваются.
        document.setMaximumBlockCount(2000)
    layout.addWidget(log_text)

    return DashboardWidgets(
        central=central,
        profile_label=profile_label,
        profile_btn=profile_btn,
        statistics_btn=statistics_btn,
        reports_btn=reports_btn,
        vulnerabilities_btn=vulnerabilities_btn,
        logout_btn=logout_btn,
        url_input=url_input,
        sql_checkbox=sql_checkbox,
        xss_checkbox=xss_checkbox,
        csrf_checkbox=csrf_checkbox,
        start_scan_btn=start_btn,
        pause_scan_btn=pause_btn,
        resume_scan_btn=resume_btn,
        stop_scan_btn=stop_btn,
        statistics_widget=statistics,
        results_table=results,
        log_text=log_text,
    )
