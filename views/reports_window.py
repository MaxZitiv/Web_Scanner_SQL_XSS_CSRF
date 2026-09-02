"""
Окно для просмотра и экспорта отчетов
views/reports_window.py
"""

from typing import Any, cast

from PyQt6.QtCore import QDate, Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDateEdit,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from utils.database import db
from utils.encryption import decrypt_sensitive_data_safe
from utils.export_utils import ExportUtils
from utils.logger import logger


class ReportsWindow(QMainWindow):
    """Окно для просмотра и экспорта отчетов"""

    def __init__(self, user_id: int, parent: QWidget | None = None):
        super().__init__(parent)
        self.user_id = user_id
        self.setWindowTitle("📋 Отчеты")
        self.setGeometry(100, 100, 1200, 800)

        self.setup_ui()
        self.load_reports()

    def setup_ui(self):
        """Настройка интерфейса"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()

        # Заголовок
        title_label = QLabel("📋 Отчеты о сканировании")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)

        # Панель фильтров
        filters_layout = QHBoxLayout()

        # Фильтр по дате начала
        start_date_label = QLabel("Начальная дата:")
        filters_layout.addWidget(start_date_label)

        self.start_date = QDateEdit()
        self.start_date.setCalendarPopup(True)
        self.start_date.setDate(QDate.currentDate().addMonths(-1))
        filters_layout.addWidget(self.start_date)

        # Фильтр по дате окончания
        end_date_label = QLabel("Конечная дата:")
        filters_layout.addWidget(end_date_label)

        self.end_date = QDateEdit()
        self.end_date.setCalendarPopup(True)
        self.end_date.setDate(QDate.currentDate())
        filters_layout.addWidget(self.end_date)

        # Кнопка применения фильтра
        apply_filter_btn = QPushButton("Применить фильтр")
        cast(Any, apply_filter_btn.clicked).connect(self.apply_filter)
        filters_layout.addWidget(apply_filter_btn)

        # Кнопка сброса фильтра
        reset_filter_btn = QPushButton("Сбросить фильтр")
        cast(Any, reset_filter_btn.clicked).connect(self.reset_filter)
        filters_layout.addWidget(reset_filter_btn)

        filters_layout.addStretch()

        # Кнопка экспорта
        export_btn = QPushButton("Экспортировать отчет")
        cast(Any, export_btn.clicked).connect(self.export_report)
        filters_layout.addWidget(export_btn)

        main_layout.addLayout(filters_layout)

        # Таблица отчетов
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(7)
        cast(Any, self.reports_table).setHorizontalHeaderLabels(
            ["ID сканирования", "URL", "Дата", "Тип уязвимости", "Место в коде", "Серьезность", "Подробности"]
        )
        self.reports_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        main_layout.addWidget(self.reports_table)

        # Панель экспорта
        export_layout = QHBoxLayout()

        export_format_label = QLabel("Формат экспорта:")
        export_layout.addWidget(export_format_label)

        self.export_format = QComboBox()
        cast(Any, self.export_format).addItems(["HTML", "PDF", "JSON", "CSV"])
        export_layout.addWidget(self.export_format)

        export_layout.addStretch()

        main_layout.addLayout(export_layout)

        # Кнопка закрытия
        close_btn = QPushButton("Закрыть")
        cast(Any, close_btn.clicked).connect(self.close_window)
        main_layout.addWidget(close_btn)

        central_widget.setLayout(main_layout)

    def close_window(self) -> None:
        """Закрытие окна"""
        self.close()

    def load_reports(self):
        """Загрузка отчетов из базы данных"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            start_date_str = self.start_date.date().toString("yyyy-MM-dd")
            end_date_str = self.end_date.date().toString("yyyy-MM-dd")

            cursor.execute(
                """
                SELECT s.id, s.url, s.timestamp, v.type,
                       v.request_params, v.severity,
                       COALESCE(v.details, v.description, '')
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE s.user_id = ? AND DATE(s.timestamp) BETWEEN ? AND ?
                ORDER BY s.timestamp DESC
                LIMIT 500
            """,
                (self.user_id, start_date_str, end_date_str),
            )

            rows = cursor.fetchall()
            conn.close()

            self.reports_table.setRowCount(len(rows))

            for i, row in enumerate(rows):
                scan_id = str(row[0])
                url = str(decrypt_sensitive_data_safe(row[1], None)) if row[1] else "N/A"
                if not url:
                    url = "N/A"
                timestamp = row[2] or "N/A"
                vuln_type = row[3] or "N/A"
                parameter = row[4] or "N/A"
                severity = row[5] or "N/A"
                details = row[6] or "N/A"

                self.reports_table.setItem(i, 0, QTableWidgetItem(scan_id))
                self.reports_table.setItem(i, 1, QTableWidgetItem(url))
                self.reports_table.setItem(i, 2, QTableWidgetItem(timestamp))
                self.reports_table.setItem(i, 3, QTableWidgetItem(vuln_type))
                self.reports_table.setItem(i, 4, QTableWidgetItem(parameter))
                self.reports_table.setItem(i, 5, QTableWidgetItem(severity))
                self.reports_table.setItem(i, 6, QTableWidgetItem(details))

            # Настраиваем ширину колонок
            self.reports_table.resizeColumnsToContents()

        except Exception as e:
            logger.error(f"Ошибка при загрузке отчетов: {e}")

    def apply_filter(self):
        """Применение фильтра к отчетам"""
        try:
            self.load_reports()
        except Exception as e:
            logger.error(f"Ошибка при применении фильтра: {e}")

    def reset_filter(self):
        """Сброс фильтра"""
        try:
            self.start_date.setDate(QDate.currentDate().addMonths(-1))
            self.end_date.setDate(QDate.currentDate())
            self.load_reports()
        except Exception as e:
            logger.error(f"Ошибка при сбросе фильтра: {e}")

    def export_report(self):
        """Экспорт отчета"""
        try:
            # Получаем формат экспорта
            format_name = self.export_format.currentText()
            file_extension = format_name.lower()

            # Собираем данные для экспорта
            reports_data: list[dict[str, str]] = []

            for row in range(self.reports_table.rowCount()):
                # Безопасно получаем значения из ячеек
                def get_item_text(col: int, *, row: int = row) -> str:
                    item = self.reports_table.item(row, col)
                    return item.text() if item else "N/A"

                report_data = {
                    "scan_id": get_item_text(0),
                    "url": get_item_text(1),
                    "timestamp": get_item_text(2),
                    "vulnerability_type": get_item_text(3),
                    "parameter": get_item_text(4),
                    "severity": get_item_text(5),
                    "details": get_item_text(6),
                }
                reports_data.append(report_data)

            if not reports_data:
                QMessageBox.warning(self, "Предупреждение", "Нет данных для экспорта")
                return

            # Экспортируем данные
            success = ExportUtils.export_data(self, reports_data, format_name, file_extension, self.user_id)

            if success:
                QMessageBox.information(self, "Успех", f"Отчет успешно экспортирован в формате {format_name}")

        except Exception as e:
            logger.error(f"Ошибка при экспорте отчета: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать отчет: {e!s}")
