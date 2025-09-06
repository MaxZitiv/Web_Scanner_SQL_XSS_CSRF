from typing import Dict, Any, List, Optional, Union
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox, QLineEdit,
    QCheckBox, QDateTimeEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QFileDialog, QAbstractItemView
)
from PyQt5.QtCore import QDateTime
from PyQt5.QtGui import QColor
from utils.logger import log_and_notify
from utils.error_handler import error_handler
from utils.performance import get_local_timestamp
import json

from datetime import datetime

class ReportsTabWidget(QWidget):
    def __init__(self, user_id: int, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.user_id: int = user_id
        self._filtered_scans: List[Dict[str, Any]] = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # 1) Фильтры
        filter_group = QGroupBox("Фильтры")
        filter_layout = QVBoxLayout()
        
        # Фильтр по URL
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("URL:"))
        self.url_filter = QLineEdit()
        self.url_filter.setPlaceholderText("Введите URL для фильтрации")
        url_layout.addWidget(self.url_filter)
        filter_layout.addLayout(url_layout)
        
        # Фильтры по типам уязвимостей
        vuln_layout = QHBoxLayout()
        vuln_layout.addWidget(QLabel("Типы уязвимостей:"))
        self.sql_checkbox = QCheckBox("SQL Injection")
        self.xss_checkbox = QCheckBox("XSS")
        self.csrf_checkbox = QCheckBox("CSRF")
        vuln_layout.addWidget(self.sql_checkbox)
        vuln_layout.addWidget(self.xss_checkbox)
        vuln_layout.addWidget(self.csrf_checkbox)
        filter_layout.addLayout(vuln_layout)
        
        # Фильтр по дате
        date_layout = QHBoxLayout()
        date_layout.addWidget(QLabel("Период:"))
        self.date_from = QDateTimeEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDateTime(QDateTime.currentDateTime().addDays(-30))
        date_layout.addWidget(self.date_from)
        self.date_to = QDateTimeEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDateTime(QDateTime.currentDateTime())
        date_layout.addWidget(self.date_to)
        filter_layout.addLayout(date_layout)
        
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # 2) Таблица с отчетами
        table_group = QGroupBox("Отчеты о сканированиях")
        table_layout = QVBoxLayout()
        
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(7)
        self.reports_table.setHorizontalHeaderLabels([
            "ID", "URL", "Дата", "Тип", "Статус", "Длительность", "Уязвимости"
        ])
        
        # Настройка размеров колонок
        header = self.reports_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        
        self.reports_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.reports_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table_layout.addWidget(self.reports_table)
        
        table_group.setLayout(table_layout)
        layout.addWidget(table_group)
        
        # 3) Кнопки управления
        buttons_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Обновить")
        self.refresh_button.clicked.connect(self.refresh_reports)
        self.export_json_button = QPushButton("Экспорт в JSON")
        self.export_json_button.clicked.connect(self.export_to_json)
        self.export_csv_button = QPushButton("Экспорт в CSV")
        self.export_csv_button.clicked.connect(self.export_to_csv)
        self.export_html_button = QPushButton("Экспорт в HTML")
        self.export_html_button.clicked.connect(self.export_to_html)
        
        buttons_layout.addWidget(self.refresh_button)
        buttons_layout.addWidget(self.export_json_button)
        buttons_layout.addWidget(self.export_csv_button)
        buttons_layout.addWidget(self.export_html_button)
        buttons_layout.addStretch()
        
        layout.addLayout(buttons_layout)
        
        # Загрузка данных при инициализации
        self.refresh_reports()

    def refresh_reports(self):
        try:
            from utils.database import db
            scans: List[Dict[str, Any]] = db.get_scans_by_user(self.user_id)
            
            url_filter: str = self.url_filter.text().strip().lower()
            selected_types: List[str] = [
                t for cb, t in [
                    (self.sql_checkbox.isChecked(), "SQL Injection"),
                    (self.xss_checkbox.isChecked(), "XSS"),
                    (self.csrf_checkbox.isChecked(), "CSRF"),
                ] if cb
            ]
            
            from_dt: datetime = self.date_from.dateTime().toPyDateTime()
            to_dt: datetime = self.date_to.dateTime().toPyDateTime()
            
            self.populate_reports_table(scans, url_filter, selected_types, from_dt, to_dt)
            
        except Exception as e:
            error_handler.handle_database_error(e, "refresh_reports")
            log_and_notify('error', f"Error refreshing reports: {e}")

    def populate_reports_table(self, scans: List[Dict[str, Any]], url_filter: str, selected_types: List[str], from_dt: datetime, to_dt: datetime) -> None:
        try:
            self.reports_table.setRowCount(0)
            filtered_scans: List[Dict[str, Any]] = []
            
            for scan in scans:
                scan: Dict[str, Any]
                timestamp_str = scan.get("timestamp", "")
                if isinstance(timestamp_str, str):
                    scan_dt: datetime = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                else:
                    continue  # Пропускаем запись, если timestamp отсутствует или не является строкой
                
                # Применяем фильтры
                if not (from_dt <= scan_dt <= to_dt):
                    continue
                if url_filter and url_filter not in scan["url"].lower():
                    continue
                
                scan_results: Any = scan.get("result", scan.get("results", []))
                if isinstance(scan_results, str):
                    try:
                        scan_results = json.loads(scan_results)
                    except (json.JSONDecodeError, TypeError):
                        scan_results = []
                
                if selected_types:
                    has_selected_type: bool = False
                    for result in scan_results:
                        result: Dict[str, Any]
                        if result.get("type") in selected_types:
                            has_selected_type = True
                            break
                    if not has_selected_type:
                        continue
                
                filtered_scans.append(scan)
            
            self.reports_table.setRowCount(len(filtered_scans))
            
            for row, scan in enumerate(filtered_scans):
                row: int
                scan: Dict[str, Any]
                scan_results: Any = scan.get("result", scan.get("results", []))
                if isinstance(scan_results, str):
                    try:
                        scan_results = json.loads(scan_results)
                    except (json.JSONDecodeError, TypeError):
                        scan_results = []
                
                vulnerability_counts: Dict[str, int] = {
                    'SQL Injection': 0,
                    'XSS': 0,
                    'CSRF': 0
                }
                
                for result in scan_results:
                    result: Dict[str, Any]
                    vuln_type: str = result.get('type', '')
                    if vuln_type in vulnerability_counts:
                        vulnerability_counts[vuln_type] += 1
                
                vuln_details: List[str] = []
                total_vulns = 0
                for vuln_type, count in vulnerability_counts.items():
                    if count > 0:
                        vuln_details.append(f"{vuln_type}: {count}")
                        total_vulns += 1
                
                vuln_text = " | ".join(vuln_details) if vuln_details else "Нет уязвимостей"
                
                self.reports_table.setItem(row, 0, QTableWidgetItem(str(scan['id'])))
                self.reports_table.setItem(row, 1, QTableWidgetItem(scan['url']))
                self.reports_table.setItem(row, 2, QTableWidgetItem(scan['timestamp']))
                self.reports_table.setItem(row, 3, QTableWidgetItem(scan['scan_type']))
                self.reports_table.setItem(row, 4, QTableWidgetItem(scan['status']))
                self.reports_table.setItem(row, 5, QTableWidgetItem(self.format_duration(scan.get('scan_duration', 0))))
                
                vuln_item = QTableWidgetItem(vuln_text)
                self.reports_table.setItem(row, 6, vuln_item)
                
                if total_vulns > 0:
                    vuln_item.setBackground(QColor("red"))
                    vuln_item.setForeground(QColor("white"))
                else:
                    vuln_item.setBackground(QColor("green"))
                    vuln_item.setForeground(QColor("black"))
            
            self._filtered_scans = filtered_scans
            
        except Exception as e:
            error_handler.handle_database_error(e, "populate_reports_table")
            log_and_notify('error', f"Error populating reports table: {e}")

    def format_duration(self, seconds: Union[int, float]) -> str:
        """Форматирует длительность в секундах в читаемый вид"""
        hours: int = int(seconds // 3600)
        minutes: int = int((seconds % 3600) // 60)
        seconds_int: int = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds_int:02d}"

    def export_to_json(self):
        try:
            if not self._filtered_scans:
                error_handler.show_warning_message("Нет данных", "Нет данных для экспорта")
                return
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить отчет", 
                f"security_report_{get_local_timestamp().replace(':', '').replace(' ', '_')}.json",
                "JSON Files (*.json)"
            )
            
            if path:
                from export.export import export_to_json
                if export_to_json(self._filtered_scans, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл JSON успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл JSON.")
                    
        except Exception as e:
            error_handler.handle_file_error(e, "export_to_json")

    def export_to_csv(self):
        try:
            if not self._filtered_scans:
                error_handler.show_warning_message("Нет данных", "Нет данных для экспорта")
                return
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить отчет", 
                f"security_report_{get_local_timestamp().replace(':', '').replace(' ', '_')}.csv",
                "CSV Files (*.csv)"
            )
            
            if path:
                from export.export import export_to_csv
                if export_to_csv(self._filtered_scans, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл CSV успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл CSV.")
                    
        except Exception as e:
            error_handler.handle_file_error(e, "export_to_csv")

    def export_to_html(self):
        try:
            if not self._filtered_scans:
                error_handler.show_warning_message("Нет данных", "Нет данных для экспорта")
                return
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить отчет", 
                f"security_report_{get_local_timestamp().replace(':', '').replace(' ', '_')}.html",
                "HTML Files (*.html)"
            )
            
            if path:
                from export.export import export_to_html
                if export_to_html(self._filtered_scans, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл HTML успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл HTML.")
                    
        except Exception as e:
            error_handler.handle_file_error(e, "export_to_html")
