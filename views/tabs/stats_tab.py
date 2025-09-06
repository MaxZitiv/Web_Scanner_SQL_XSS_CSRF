import os
import json
from datetime import datetime, date
from pydoc import text
from typing import Dict, List, Any, Optional, cast

import sqlite3
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox, 
    QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QDate
from PyQt5.QtGui import QColor, QPixmap
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib.axes import Axes
from matplotlib.text import Text

from utils.database import db
from utils.error_handler import error_handler
from utils.logger import logger
from utils.unified_error_handler import log_and_notify

class StatsTabWidget(QWidget):
    """Виджет вкладки статистики сканирований"""
    
    def __init__(self, user_id: int, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.user_id = user_id
        self._stats = {
            'total_scans': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'vulnerabilities_found': 0,
            'sql_injection_count': 0,
            'xss_count': 0,
            'csrf_count': 0,
            'high_risk_targets': 0,
            'medium_risk_targets': 0,
            'low_risk_targets': 0
        }
        self.setup_ui()
        self.load_statistics()
        
    def setup_ui(self):
        """Настройка пользовательского интерфейса вкладки статистики"""
        # Основной layout
        main_layout = QVBoxLayout(self)
        
        # Верхняя панель с фильтрами
        filter_panel = self._create_filter_panel()
        main_layout.addWidget(filter_panel)
        
        # Основной контент с разделением
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # График статистики
        self.stats_canvas = FigureCanvas(Figure(figsize=(10, 6)))
        splitter.addWidget(self.stats_canvas)
        
        # Таблица со статистикой
        self.stats_table = self._create_stats_table()
        splitter.addWidget(self.stats_table)
        
        # Устанавливаем пропорции разделения
        splitter.setSizes([400, 300])
        main_layout.addWidget(splitter)
        
        # Панель с кнопками действий
        actions_panel = self._create_actions_panel()
        main_layout.addWidget(actions_panel)
    
    def _create_filter_panel(self) -> QWidget:
        """Создание панели фильтров"""
        panel = QWidget()
        layout = QHBoxLayout(panel)
        
        # Фильтр по периоду
        layout.addWidget(QLabel("Период:"))
        self.period_combo = QComboBox()
        self.period_combo.addItems([
            "За все время", 
            "За последний месяц", 
            "За последнюю неделю", 
            "За сегодня",
            "Произвольный период"
        ])
        self.period_combo.currentTextChanged.connect(self._on_period_changed)
        layout.addWidget(self.period_combo)
        
        # Фильтр по типу сканирования
        layout.addWidget(QLabel("Тип сканирования:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems([
            "Все типы",
            "Быстрое сканирование",
            "Полное сканирование",
            "Только SQL",
            "Только XSS",
            "Только CSRF"
        ])
        self.scan_type_combo.currentTextChanged.connect(self._on_filter_changed)
        layout.addWidget(self.scan_type_combo)
        
        # Кнопка применения фильтров
        self.apply_filter_btn = QPushButton("Применить")
        self.apply_filter_btn.clicked.connect(self._on_filter_changed)
        layout.addWidget(self.apply_filter_btn)
        
        # Растягивающийся элемент для выравнивания
        layout.addStretch()
        
        return panel
    
    def _create_stats_table(self) -> QTableWidget:
        """Создание таблицы статистики"""
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Показатель", "Значение", "Детали"])

        # Получаем заголовок и проверяем, что он не None
        header = table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        table.setAlternatingRowColors(True)
        table.setStyleSheet("""
            QTableWidget {
                gridline-color: #cccccc;
                background-color: #ffffff;
                border: 1px solid #cccccc;
                border-radius: 5px;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
                color: #ffffff;
            }
        """)
        return table
    
    def _create_actions_panel(self) -> QWidget:
        """Создание панели с кнопками действий"""
        panel = QWidget()
        layout = QHBoxLayout(panel)
        
        # Кнопка обновления
        self.refresh_btn = QPushButton("Обновить")
        self.refresh_btn.clicked.connect(self.load_statistics)
        layout.addWidget(self.refresh_btn)
        
        # Кнопка экспорта в PNG
        self.export_png_btn = QPushButton("Экспорт в PNG")
        self.export_png_btn.clicked.connect(self._export_to_png)
        layout.addWidget(self.export_png_btn)
        
        # Кнопка экспорта в CSV
        self.export_csv_btn = QPushButton("Экспорт в CSV")
        self.export_csv_btn.clicked.connect(self._export_to_csv)
        layout.addWidget(self.export_csv_btn)
        
        # Растягивающийся элемент для выравнивания
        layout.addStretch()
        
        return panel
    
    def load_statistics(self):
        """Загрузка и отображение статистики"""
        try:
            # Получаем данные сканирований
            scans = db.get_scans_by_user(self.user_id)
            
            # Применяем фильтры
            filtered_scans = self._apply_filters(scans)
            
            # Обновляем статистику
            self._calculate_statistics(filtered_scans)
            
            # Обновляем график
            self._refresh_stats_with_matplotlib(filtered_scans)
            
            # Обновляем таблицу
            self._populate_stats_table()
            
            logger.info(f"Statistics loaded successfully for user {self.user_id}")
        except Exception as e:
            error_handler.handle_database_error(e, "load_statistics")
            log_and_notify('error', f"Error loading statistics: {e}")
    
    def _apply_filters(self, scans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Применение фильтров к списку сканирований"""
        filtered_scans = scans.copy()
        
        # Фильтр по периоду
        period = self.period_combo.currentText()
        if period != "За все время":
            now = datetime.now()
            if period == "За последний месяц":
                start_date = now.replace(day=1)
            elif period == "За последнюю неделю":
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
                start_date = start_date.replace(day=start_date.day - 7)
            elif period == "За сегодня":
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            else:  # Произвольный период
                # Здесь можно добавить диалог выбора периода
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Фильтрация по дате
            filtered_scans = [
                scan for scan in filtered_scans 
                if datetime.strptime(scan['timestamp'], "%Y-%m-%d %H:%M:%S") >= start_date
            ]
        
        # Фильтр по типу сканирования
        scan_type = self.scan_type_combo.currentText()
        if scan_type != "Все типы":
            scan_type_map = {
                "Быстрое сканирование": "quick",
                "Полное сканирование": "full",
                "Только SQL": "sql",
                "Только XSS": "xss",
                "Только CSRF": "csrf"
            }
            filtered_type = scan_type_map.get(scan_type, "")
            filtered_scans = [
                scan for scan in filtered_scans 
                if scan.get('scan_type', '') == filtered_type
            ]
        
        return filtered_scans
    
    def _calculate_statistics(self, scans: List[Dict[str, Any]]):
        """Расчет статистики на основе данных сканирований"""
        # Сброс статистики
        for key in self._stats:
            self._stats[key] = 0
        
        # Обработка сканирований
        for scan in scans:
            self._stats['total_scans'] += 1
            
            # Определение успешности сканирования
            if scan.get('status') == 'completed':
                self._stats['successful_scans'] += 1
            else:
                self._stats['failed_scans'] += 1
            
            # Обработка результатов сканирования
            scan_results = scan.get('result', scan.get('results', []))
            if isinstance(scan_results, str):
                try:
                    scan_results = json.loads(scan_results)
                except (json.JSONDecodeError, TypeError):
                    scan_results = []

            # Явно указываем тип для Pylance
            scan_results: List[Dict[str, Any]]
            
            # Подсчет уязвимостей
            scan_vulnerabilities = 0
            for result in scan_results:
                # Явно указываем тип для Pylance
                result: Dict[str, Any]
                # Проверяем vulnerabilities в новой структуре
                if 'vulnerabilities' in result:
                    for vuln_cat, vulns in result['vulnerabilities'].items():
                        # Явно указываем тип для Pylance
                        vulns: List[Any]
                        if vulns:
                            scan_vulnerabilities += len(vulns)
                            # Маппинг категорий к типам
                            if vuln_cat == 'sql':
                                self._stats['sql_injection_count'] += len(vulns)
                            elif vuln_cat == 'xss':
                                self._stats['xss_count'] += len(vulns)
                            elif vuln_cat == 'csrf':
                                self._stats['csrf_count'] += len(vulns)
                # Проверяем старую структуру
                elif result.get('type') or result.get('vuln_type'):
                    vuln_type = result.get('type', result.get('vuln_type', ''))
                    scan_vulnerabilities += 1
                    if vuln_type == 'SQL Injection':
                        self._stats['sql_injection_count'] += 1
                    elif vuln_type == 'XSS':
                        self._stats['xss_count'] += 1
                    elif vuln_type == 'CSRF':
                        self._stats['csrf_count'] += 1
            
            self._stats['vulnerabilities_found'] += scan_vulnerabilities
            
            # Определение уровня риска
            if scan_vulnerabilities > 5:
                self._stats['high_risk_targets'] += 1
            elif scan_vulnerabilities > 0:
                self._stats['medium_risk_targets'] += 1
            else:
                self._stats['low_risk_targets'] += 1
    
    def _refresh_stats_with_matplotlib(self, scans: List[Dict[str, Any]]):
        """Обновление статистики с использованием matplotlib"""
        try:
            if not scans:
                logger.warning("No scan data available")
                self.stats_canvas.figure.clear()
                # Явно указываем тип для Pylance
                ax: Axes = self.stats_canvas.figure.add_subplot(111)
                # Явно указываем тип возвращаемого значения для Pylance
                # Сохраняем ссылку на текстовый объект для возможного будущего использования
                _ = ax.text(0.5, 0.5, "Нет данных для отображения", 
                                    horizontalalignment='center', verticalalignment='center')  # type: ignore

                self.stats_canvas.draw()
                return
            
            self.stats_canvas.figure.clear()
            # Явно указываем тип для Pylance
            ax: Axes = self.stats_canvas.figure.add_subplot(111)

            # Подготовка данных
            # Явно указываем тип для Pylance
            from typing import Any
            dates: List[Any] = []  # Список дат сканирований
            # type: List[datetime.date]
            vulnerability_counts: Dict[str, int] = {"SQL Injection": 0, "XSS": 0, "CSRF": 0}
            date_vulnerability_counts: Dict[str, Dict[str, int]] = {}

            for scan in scans:
                scan_date = datetime.strptime(scan['timestamp'], "%Y-%m-%d %H:%M:%S").date()
                # Явно указываем тип для Pylance
                scan_date: Any
                # type: datetime.date
                dates.append(scan_date)

                scan_result = scan.get('result', {})
                if not scan_result:
                    continue
                
                # Парсим результаты сканирования
                try:
                    results = json.loads(scan_result) if isinstance(scan_result, str) else scan_result
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse scan result: {e}")
                    continue
                
                # Обновляем общие счетчики
                if isinstance(results, list):
                    for result in results:  # type: ignore
                        # Проверяем разные возможные структуры результатов
                        vuln_type: Optional[str] = None
                        if isinstance(result, dict):
                            # Явно указываем типы для Pylance
                            result: Dict[str, Any]
                            # Явно указываем типы для Pylance
                            result_dict: Dict[str, Any] = cast(Dict[str, Any], result)
                            type_value: Optional[str] = cast(Optional[str], result_dict.get('type'))
                            vuln_type_value: Optional[str] = cast(Optional[str], result_dict.get('vuln_type'))
                            vuln_type = type_value or vuln_type_value
                            # Если нет прямого типа, проверяем в vulnerabilities
                            if not vuln_type and 'vulnerabilities' in result:
                                # Явно указываем типы для Pylance
                                vulnerabilities_data: Dict[str, List[Any]] = result_dict.get('vulnerabilities', {})  # type: Dict[str, List[Any]]
                                for vuln_cat, vulns_data in vulnerabilities_data.items():
                                    # Явно указываем типы для Pylance
                                    vuln_cat: str
                                    # Используем Any для избежания циклических ссылок
                                    if vulns_data:  # type: ignore  # Если есть уязвимости в этой категории
                                        vulns: List[Any] = vulns_data  # type: ignore
                                        if vuln_cat == 'sql':
                                            vuln_type = 'SQL Injection'
                                        elif vuln_cat == 'xss':
                                            vuln_type = 'XSS'
                                        elif vuln_cat == 'csrf':
                                            vuln_type = 'CSRF'
                                        break
                        
                        if vuln_type and vuln_type in vulnerability_counts:
                            vulnerability_counts[vuln_type] += 1
                            
                            # Обновляем счетчики по датам
                            if scan_date not in date_vulnerability_counts:
                                date_vulnerability_counts[scan_date] = {"SQL Injection": 0, "XSS": 0, "CSRF": 0}

                            if vuln_type and vuln_type in date_vulnerability_counts[scan_date]:
                                date_vulnerability_counts[scan_date][vuln_type] += 1
                elif isinstance(results, dict):
                    # Если результат - это словарь с vulnerabilities
                    if 'vulnerabilities' in results:
                        # Явно указываем типы для Pylance
                        results_dict: Dict[str, Any] = cast(Dict[str, Any], results)
                        vulnerabilities_data: Dict[str, List[Any]] = results_dict.get('vulnerabilities', {})  # type: Dict[str, List[Any]]
                        for vuln_cat, vulns_data in vulnerabilities_data.items():
                            # Явно указываем типы для Pylance
                            vuln_cat: str
                            # Используем Any для избежания циклических ссылок
                            if vulns_data:
                                vulns: List[Any] = vulns_data
                                vuln_type: Optional[str] = None
                                if vuln_cat == 'sql':
                                    vuln_type = 'SQL Injection'
                                elif vuln_cat == 'xss':
                                    vuln_type = 'XSS'
                                elif vuln_cat == 'csrf':
                                    vuln_type = 'CSRF'
                                
                                if vuln_type and vuln_type in vulnerability_counts:
                                    vulnerability_counts[vuln_type] += len(vulns)
                                    
                                    # Обновляем счетчики по датам
                                    if scan_date not in date_vulnerability_counts:
                                        date_vulnerability_counts[scan_date] = {"SQL Injection": 0, "XSS": 0, "CSRF": 0}
                                    date_vulnerability_counts[scan_date][vuln_type] += len(vulns)

            # Сортируем даты
            sorted_dates = sorted(set(dates))

            # Линейный график по датам
            # Явно указываем типы для Pylance
            ax: Axes = self.stats_canvas.figure.add_subplot(111)

            for vuln_type in vulnerability_counts.keys():
                # Явно указываем типы для Pylance
                counts: List[int] = []
                for date in sorted_dates:
                    # Явно указываем типы для Pylance
                    date_vuln_counts: Dict[str, int] = date_vulnerability_counts.get(date, {})
                    count: int = date_vuln_counts.get(vuln_type, 0)
                    counts.append(count)
                ax.plot(sorted_dates, counts, marker='o', linestyle='-', label=vuln_type)

            ax.set_title("Статистика сканирований по типам уязвимостей")
            ax.set_xlabel("Дата")
            ax.set_ylabel("Количество обнаружений")
            ax.grid(True)
            ax.legend()

            self.stats_canvas.figure.tight_layout()
            self.stats_canvas.draw()
        except (ValueError, sqlite3.Error, KeyError, AttributeError) as e:
            log_and_notify('error', f"Error updating matplotlib stats: {e}")
            self.stats_canvas.figure.clear()
            ax: Axes = self.stats_canvas.figure.add_subplot(111)
            ax.text(0.5, 0.5, f"Ошибка отображения статистики: {str(e)}",  # type: ignore 
                   horizontalalignment='center', verticalalignment='center')
            self.stats_canvas.draw()
    
    def _populate_stats_table(self):
        """Заполнение таблицы статистики"""
        self.stats_table.setRowCount(0)
        
        # Данные для таблицы
        stats_data = [
            ("Всего сканирований", self._stats['total_scans'], ""),
            ("Успешных сканирований", self._stats['successful_scans'], 
             f"{self._stats['successful_scans']/max(1, self._stats['total_scans'])*100:.1f}%"),
            ("Неудачных сканирований", self._stats['failed_scans'], 
             f"{self._stats['failed_scans']/max(1, self._stats['total_scans'])*100:.1f}%"),
            ("Всего найдено уязвимостей", self._stats['vulnerabilities_found'], ""),
            ("SQL-инъекций", self._stats['sql_injection_count'], 
             f"{self._stats['sql_injection_count']/max(1, self._stats['vulnerabilities_found'])*100:.1f}%"),
            ("XSS-атак", self._stats['xss_count'], 
             f"{self._stats['xss_count']/max(1, self._stats['vulnerabilities_found'])*100:.1f}%"),
            ("CSRF-уязвимостей", self._stats['csrf_count'], 
             f"{self._stats['csrf_count']/max(1, self._stats['vulnerabilities_found'])*100:.1f}%"),
            ("Целей с высоким риском", self._stats['high_risk_targets'], ""),
            ("Целей со средним риском", self._stats['medium_risk_targets'], ""),
            ("Целей с низким риском", self._stats['low_risk_targets'], "")
        ]
        
        # Заполнение таблицы
        for row, (label, value, details) in enumerate(stats_data):
            self.stats_table.insertRow(row)
            
            # Название показателя
            item = QTableWidgetItem(label)
            item.setFlags(Qt.ItemFlag(item.flags() & ~Qt.ItemFlag.ItemIsEditable))
            self.stats_table.setItem(row, 0, item)
            
            # Значение
            value_item = QTableWidgetItem(str(value))
            value_item.setFlags(Qt.ItemFlag(value_item.flags() & ~Qt.ItemFlag.ItemIsEditable))
            value_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Выделение цветом в зависимости от значений
            if "уязвимость" in label.lower() and value > 0:
                value_item.setBackground(QColor("#ffcccc"))
            elif "высоким риском" in label.lower() and value > 0:
                value_item.setBackground(QColor("#ff9999"))
            elif "средним риском" in label.lower() and value > 0:
                value_item.setBackground(QColor("#ffcc99"))
            elif "низким риском" in label.lower():
                value_item.setBackground(QColor("#ccffcc"))
            
            self.stats_table.setItem(row, 1, value_item)
            
            # Детали
            details_item = QTableWidgetItem(details)
            details_item.setFlags(Qt.ItemFlag(details_item.flags() & ~Qt.ItemFlag.ItemIsEditable))
            self.stats_table.setItem(row, 2, details_item)
    
    def _on_period_changed(self):
        """Обработчик изменения периода фильтрации"""
        # Если выбран "Произвольный период", можно показать диалог выбора дат
        if self.period_combo.currentText() == "Произвольный период":
            # Здесь можно добавить диалог выбора периода
            pass
        else:
            # Применяем фильтры
            self._on_filter_changed()
    
    def _on_filter_changed(self):
        """Обработчик изменения фильтров"""
        self.load_statistics()
    
    def _export_to_png(self):
        """Экспорт графика в PNG"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить график", "", "PNG Files (*.png)"
            )
            if file_path:
                self.stats_canvas.figure.savefig(file_path, dpi=300, bbox_inches='tight')
                QMessageBox.information(self, "Успех", "График успешно сохранен")
                logger.info(f"Statistics chart exported to {file_path}")
        except Exception as e:
            error_handler.handle_error(e, "_export_to_png")
            log_and_notify('error', f"Error exporting chart to PNG: {e}")
    
    def _export_to_csv(self):
        """Экспорт статистики в CSV"""
        try:
            import csv
            
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить статистику", "", "CSV Files (*.csv)"
            )
            if file_path:
                with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    
                    # Заголовок
                    writer.writerow(["Показатель", "Значение", "Детали"])
                    
                    # Данные
                    stats_data = [
                        ("Всего сканирований", self._stats['total_scans'], 
                         f"{self._stats['successful_scans']/max(1, self._stats['total_scans'])*100:.1f}%"),
                        ("Успешных сканирований", self._stats['successful_scans'], ""),
                        ("Неудачных сканирований", self._stats['failed_scans'], ""),
                        ("Всего найдено уязвимостей", self._stats['vulnerabilities_found'], ""),
                        ("SQL-инъекций", self._stats['sql_injection_count'], ""),
                        ("XSS-атак", self._stats['xss_count'], ""),
                        ("CSRF-уязвимостей", self._stats['csrf_count'], ""),
                        ("Целей с высоким риском", self._stats['high_risk_targets'], ""),
                        ("Целей со средним риском", self._stats['medium_risk_targets'], ""),
                        ("Целей с низким риском", self._stats['low_risk_targets'], "")
                    ]
                    
                    for row in stats_data:
                        writer.writerow(row)
                
                QMessageBox.information(self, "Успех", "Статистика успешно сохранена")
                logger.info(f"Statistics exported to {file_path}")
        except Exception as e:
            error_handler.handle_error(e, "_export_to_csv")
            log_and_notify('error', f"Error exporting statistics to CSV: {e}")
