import asyncio
import json
import os
import sqlite3
import threading
import time
from attr import has
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from PyQt5.QtCore import Qt, QTimer, QDateTime, QTime, QMetaObject, Q_ARG, pyqtSignal


class SignalWrapper:
    """Обертка для pyqtSignal с явным объявлением метода emit"""
    def __init__(self, signal: pyqtSignal):
        self._signal = signal
        # Сохраняем ссылку на оригинальный метод emit
        self._emit_method = getattr(signal, 'emit', None)
    
    def emit(self, *args):
        """Явно объявленный метод emit"""
        # Используем сохраненную ссылку на метод emit
        if self._emit_method is not None:
            self._emit_method(*args)
from PyQt5.QtGui import QPixmap, QIcon, QColor
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                         QPushButton, QLineEdit, QCheckBox,
                         QTabWidget, QSpinBox, QMessageBox,
                         QFileDialog, QComboBox, QTableWidgetItem,
                         QGroupBox, QDateTimeEdit, QDialog, QDialogButtonBox, QTreeWidgetItem, QApplication,
                         QFormLayout, QTextEdit, QScrollArea, QTreeWidget, QProgressBar, QTableWidget)

from controllers.scan_controller import ScanController
from utils import error_handler
from utils.database import db
from utils.error_handler import ErrorHandler
from utils.logger import logger, log_and_notify
from utils.performance import performance_monitor, get_local_timestamp, extract_time_from_timestamp
from utils.security import is_safe_url, sanitize_filename
from views.edit_profile_window import EditProfileWindow
from views.tabs.profile_tab import ProfileTabWidget
from views.tabs.reports_tab import ReportsTabWidget
from views.tabs.scan_tab import ScanTabWidget
from views.tabs.stats_tab import StatsTabWidget
from views.managers.scan_manager import ScanManagerStatsMixin
from views.managers.stats_manager import StatsManager
from views.dashboard_optimized import DashboardStatsMixin
from views.mixins.export_mixin import ExportMixin
from views.mixins.scan_mixin import ScanMixin
from views.mixins.log_mixin import LogMixin

import matplotlib
matplotlib.use('Qt5Agg')

# Импорт matplotlib с обработкой ошибок
try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError as e:
    logger.warning(f"matplotlib not available: {e}")
    MATPLOTLIB_AVAILABLE = False
    FigureCanvas = None
    Figure = None

from qasync import asyncSlot
from policies.policy_manager import PolicyManager


def _generate_json_report(scan_details):
    """Генерация JSON отчета"""
    try:
        # Создание имени файла
        filename = f"scan_report_{scan_details['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join("reports", filename)

        # Убедимся, что директория существует
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Сохранение JSON файла
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scan_details, f, ensure_ascii=False, indent=2)

        logger.info(f"Generated JSON report: {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Error generating JSON report: {e}")
        return None


class DashboardWindowMethodsMixin:
    """Дополнительные методы для DashboardWindow"""

    def __init__(self):
        """Инициализация миксина"""
        # Сигнал для результатов сканирования
        self._scan_result_signal = SignalWrapper(pyqtSignal(dict))
        # Компоненты для работы с логами
        self.detailed_log: Optional[QTextEdit] = None
        # Метка для отображения статуса лога
        self.log_status_label: Optional[QLabel] = None
        # ID пользователя
        self.user_id: Optional[int] = None
        # Таблица последних сканирований
        self.recent_scans_table: Optional[QTableWidget] = None
        # Вкладка статистики
        self.stats_tab: Optional[QWidget] = None

    def _process_log_content(self, content: str, log_type: int):
        """Обработка загруженного содержимого лога"""
        try:
            if log_type == 1:  # Системный лог
                self._process_system_log(content)
            elif log_type == 2:  # Лог сканирования
                self._process_scan_log(content)
            else:
                logger.warning(f"Unknown log type: {log_type}")
        except Exception as e:
            logger.error(f"Error processing log content: {e}")

    def _process_system_log(self, content: str):
        """Обработка системного лога"""
        try:
            lines = content.strip().split('\n')
            self._log_entries = []

            for line in lines:
                if line.strip():
                    try:
                        # Парсинг строки лога
                        parts = line.split(' - ', 2)
                        if len(parts) >= 3:
                            timestamp_str = parts[0].strip()
                            level = parts[1].strip()
                            message = parts[2].strip()

                            # Преобразование временной метки
                            timestamp = extract_time_from_timestamp(timestamp_str)

                            # Добавление записи в список
                            self._log_entries.append({
                                'timestamp': timestamp,
                                'level': level,
                                'message': message,
                                'raw': line
                            })
                    except Exception as e:
                        logger.warning(f"Error parsing log line: {line}, error: {e}")

            # Обновление UI
            self._update_log_display()
            logger.info(f"Processed {len(self._log_entries)} system log entries")
        except Exception as e:
            logger.error(f"Error processing system log: {e}")

    def _process_scan_log(self, content: str):
        """Обработка лога сканирования"""
        try:
            # Попытка распарсить JSON
            try:
                data = json.loads(content)

                # Обработка результатов сканирования
                if isinstance(data, dict) and 'results' in data:
                    self._scan_result_signal.emit(data)
                    logger.info("Processed scan log results")
            except json.JSONDecodeError:
                # Если не JSON, обрабатываем как текст
                lines = content.strip().split('\n')
                scan_results = []

                for line in lines:
                    if line.strip():
                        scan_results.append({
                            'timestamp': get_local_timestamp(),
                            'message': line.strip()
                        })

                # Отправка сигнала с результатами
                self._scan_result_signal.emit({
                    'results': scan_results,
                    'url': 'Unknown',
                    'scan_type': 'Unknown'
                })

                logger.info(f"Processed {len(scan_results)} scan log entries")
        except Exception as e:
            logger.error(f"Error processing scan log: {e}")

    def _update_log_display(self):
        """Обновление отображения логов"""
        try:
            if hasattr(self, 'detailed_log') and self.detailed_log is not None:
                # Очистка текущего содержимого
                self.detailed_log.clear()

                # Фильтрация записей, если применен фильтр
                entries_to_display = self._filtered_log_entries if self._filtered_log_entries else self._log_entries

                # Отображение записей
                for entry in entries_to_display:
                    # Форматирование записи
                    timestamp = entry.get('timestamp', '')
                    level = entry.get('level', '')
                    message = entry.get('message', '')

                    # Определение цвета в зависимости от уровня
                    color = 'black'
                    if level == 'ERROR':
                        color = 'red'
                    elif level == 'WARNING':
                        color = 'orange'
                    elif level == 'INFO':
                        color = 'blue'

                    # Форматирование текста
                    formatted_text = f'<span style="color:{color}">[{timestamp}] [{level}] {message}</span>'

                    # Добавление в виджет
                    self.detailed_log.append(formatted_text)

                # Обновление статуса
                if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                    self.log_status_label.setText(f"Показано записей: {len(entries_to_display)} из {len(self._log_entries)}")

                logger.info(f"Updated log display with {len(entries_to_display)} entries")
        except Exception as e:
            logger.error(f"Error updating log display: {e}")

    def filter_logs(self, level: Optional[str] = None, text: Optional[str] = None):
        """Фильтрация логов по уровню и тексту"""
        try:
            self._filtered_log_entries = []

            for entry in self._log_entries:
                # Проверка уровня
                if level and entry.get('level', '').upper() != level.upper():
                    continue

                # Проверка текста
                if text and text.lower() not in entry.get('message', '').lower():
                    continue

                # Добавление записи в отфильтрованный список
                self._filtered_log_entries.append(entry)

            # Обновление отображения
            self._update_log_display()

            logger.info(f"Filtered logs: {len(self._filtered_log_entries)} entries match criteria")
        except Exception as e:
            logger.error(f"Error filtering logs: {e}")

    def clear_log_filter(self):
        """Очистка фильтра логов"""
        try:
            self._filtered_log_entries = []
            self._update_log_display()
            logger.info("Cleared log filter")
        except Exception as e:
            logger.error(f"Error clearing log filter: {e}")

    def export_logs(self, file_path: str):
        """Экспорт логов в файл"""
        try:
            # Определение записей для экспорта
            entries_to_export = self._filtered_log_entries if self._filtered_log_entries else self._log_entries

            if not entries_to_export:
                QMessageBox.warning(None, "Предупреждение", "Нет записей для экспорта")
                return

            # Определение формата файла
            if file_path.endswith('.json'):
                # Экспорт в JSON
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(entries_to_export, f, ensure_ascii=False, indent=2)
            else:
                # Экспорт в текстовый формат
                with open(file_path, 'w', encoding='utf-8') as f:
                    for entry in entries_to_export:
                        f.write(f"{entry.get('raw', entry.get('message', ''))}\n")

            QMessageBox.information(None, "Успех", f"Логи успешно экспортированы в {file_path}")
            logger.info(f"Exported {len(entries_to_export)} log entries to {file_path}")
        except Exception as e:
            logger.error(f"Error exporting logs: {e}")
            QMessageBox.critical(None, "Ошибка", f"Не удалось экспортировать логи: {e}")

    def load_recent_scans(self, limit: int = 10):
        """Загрузка последних сканирований"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Получение последних сканирований
            cursor.execute("""
                SELECT id, url, scan_types, start_time, end_time, status, vulnerabilities_count
                FROM scans
                WHERE user_id = ?
                ORDER BY start_time DESC
                LIMIT ?
            """, (self.user_id, limit))

            scans = cursor.fetchall()
            conn.close()

            # Преобразование в список словарей
            recent_scans = []
            for scan in scans:
                recent_scans.append({
                    'id': scan[0],
                    'url': scan[1],
                    'scan_types': scan[2],
                    'start_time': scan[3],
                    'end_time': scan[4],
                    'status': scan[5],
                    'vulnerabilities_count': scan[6]
                })

            # Обновление UI, если необходимо
            if hasattr(self, 'recent_scans_table') and self.recent_scans_table is not None:
                self._update_recent_scans_table(recent_scans)

            logger.info(f"Loaded {len(recent_scans)} recent scans")
            return recent_scans
        except Exception as e:
            logger.error(f"Error loading recent scans: {e}")
            return []

    def _update_recent_scans_table(self, scans):
        """Обновление таблицы последних сканирований"""
        try:
            # Проверка, что таблица существует
            if self.recent_scans_table is None:
                return
                
            # Очистка таблицы
            self.recent_scans_table.setRowCount(0)

            # Заполнение таблицы
            for i, scan in enumerate(scans):
                self.recent_scans_table.insertRow(i)

                # URL
                self.recent_scans_table.setItem(i, 0, QTableWidgetItem(scan['url']))

                # Типы сканирования
                self.recent_scans_table.setItem(i, 1, QTableWidgetItem(scan['scan_types']))

                # Время начала
                start_time = scan['start_time']
                if start_time:
                    self.recent_scans_table.setItem(i, 2, QTableWidgetItem(start_time))
                else:
                    self.recent_scans_table.setItem(i, 2, QTableWidgetItem("N/A"))

                # Статус
                status_item = QTableWidgetItem(scan['status'])

                # Цвет статуса
                if scan['status'] == 'completed':
                    status_item.setBackground(QColor(200, 255, 200))  # Зеленый
                elif scan['status'] == 'failed':
                    status_item.setBackground(QColor(255, 200, 200))  # Красный
                elif scan['status'] == 'running':
                    status_item.setBackground(QColor(255, 255, 200))  # Желтый

                self.recent_scans_table.setItem(i, 3, status_item)

                # Количество уязвимостей
                vuln_count = scan['vulnerabilities_count'] or 0
                vuln_item = QTableWidgetItem(str(vuln_count))

                # Цвет в зависимости от количества уязвимостей
                if vuln_count > 0:
                    vuln_item.setBackground(QColor(255, 200, 200))  # Красный

                self.recent_scans_table.setItem(i, 4, vuln_item)

            logger.info(f"Updated recent scans table with {len(scans)} entries")
        except Exception as e:
            logger.error(f"Error updating recent scans table: {e}")

    def get_scan_details(self, scan_id: int):
        """Получение деталей сканирования"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Получение информации о сканировании
            cursor.execute("""
                SELECT id, url, scan_types, start_time, end_time, status, vulnerabilities_count
                FROM scans
                WHERE id = ? AND user_id = ?
            """, (scan_id, self.user_id))

            scan = cursor.fetchone()

            if not scan:
                conn.close()
                return None

            # Получение уязвимостей
            cursor.execute("""
                SELECT id, url, vulnerability_type, description, severity, evidence
                FROM vulnerabilities
                WHERE scan_id = ?
                ORDER BY severity DESC
            """, (scan_id,))

            vulnerabilities = cursor.fetchall()
            conn.close()

            # Преобразование в словари
            scan_details = {
                'id': scan[0],
                'url': scan[1],
                'scan_types': scan[2],
                'start_time': scan[3],
                'end_time': scan[4],
                'status': scan[5],
                'vulnerabilities_count': scan[6],
                'vulnerabilities': []
            }

            for vuln in vulnerabilities:
                scan_details['vulnerabilities'].append({
                    'id': vuln[0],
                    'url': vuln[1],
                    'type': vuln[2],
                    'description': vuln[3],
                    'severity': vuln[4],
                    'evidence': vuln[5]
                })

            logger.info(f"Loaded details for scan {scan_id}")
            return scan_details
        except Exception as e:
            logger.error(f"Error getting scan details: {e}")
            return None

    def delete_scan(self, scan_id: int):
        """Удаление сканирования"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Удаление уязвимостей
            cursor.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))

            # Удаление сканирования
            cursor.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, self.user_id))

            conn.commit()
            conn.close()

            # Обновление UI
            self.load_recent_scans()

            logger.info(f"Deleted scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting scan: {e}")
            return False

    def init_stats_manager(self):
        """Инициализация менеджера статистики"""
        try:
            self.stats_manager = StatsManager()

            # Подключение сигналов
            if hasattr(self.stats_manager, 'stats_updated'):
                self.stats_manager.stats_updated.connect(self._handle_stats_updated)

            logger.info("Initialized stats manager")
        except Exception as e:
            logger.error(f"Error initializing stats manager: {e}")

    def _handle_stats_updated(self, stats):
        """Обработка обновления статистики"""
        try:
            self._stats = stats

            # Обновление UI, если необходимо
            if hasattr(self, 'stats_tab') and self.stats_tab is not None:
                self.stats_tab.update_stats(stats)

            logger.info("Handled stats update")
        except Exception as e:
            logger.error(f"Error handling stats update: {e}")

    def refresh_stats(self):
        """Обновление статистики"""
        try:
            if self.stats_manager is not None:
                self.stats_manager.refresh_stats(self.user_id)
                logger.info("Requested stats refresh")
        except Exception as e:
            logger.error(f"Error refreshing stats: {e}")

    def get_vulnerability_stats(self):
        """Получение статистики уязвимостей"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Получение статистики по типам уязвимостей
            cursor.execute("""
                SELECT vulnerability_type, COUNT(*) as count
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE s.user_id = ?
                GROUP BY vulnerability_type
            """, (self.user_id,))

            type_stats = cursor.fetchall()

            # Получение статистики по уровням серьезности
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE s.user_id = ?
                GROUP BY severity
            """, (self.user_id,))

            severity_stats = cursor.fetchall()

            conn.close()

            # Преобразование в словари
            vulnerability_stats = {
                'by_type': {row[0]: row[1] for row in type_stats},
                'by_severity': {row[0]: row[1] for row in severity_stats}
            }

            logger.info("Retrieved vulnerability statistics")
            return vulnerability_stats
        except Exception as e:
            logger.error(f"Error getting vulnerability stats: {e}")
            return {'by_type': {}, 'by_severity': {}}

    def get_scan_stats(self):
        """Получение статистики сканирований"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Получение общего количества сканирований
            cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (self.user_id,))
            total_scans = cursor.fetchone()[0]

            # Получение количества сканирований по статусам
            cursor.execute("""
                SELECT status, COUNT(*) as count
                FROM scans
                WHERE user_id = ?
                GROUP BY status
            """, (self.user_id,))

            status_stats = cursor.fetchall()

            conn.close()

            # Преобразование в словари
            scan_stats = {
                'total': total_scans,
                'by_status': {row[0]: row[1] for row in status_stats}
            }

            logger.info("Retrieved scan statistics")
            return scan_stats
        except Exception as e:
            logger.error(f"Error getting scan stats: {e}")
            return {'total': 0, 'by_status': {}}

    def generate_report(self, scan_id: int, format_type: str = 'pdf'):
        """Генерация отчета о сканировании"""
        try:
            # Получение деталей сканирования
            scan_details = self.get_scan_details(scan_id)

            if not scan_details:
                QMessageBox.warning(None, "Предупреждение", "Сканирование не найдено")
                return None

            # Генерация отчета в зависимости от формата
            if format_type.lower() == 'pdf':
                return self._generate_pdf_report(scan_details)
            elif format_type.lower() == 'html':
                return self._generate_html_report(scan_details)
            elif format_type.lower() == 'json':
                return _generate_json_report(scan_details)
            else:
                QMessageBox.warning(None, "Предупреждение", f"Неподдерживаемый формат отчета: {format_type}")
                return None
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            QMessageBox.critical(None, "Ошибка", f"Не удалось сгенерировать отчет: {e}")
            return None

    def _generate_pdf_report(self, scan_details):
        """Генерация PDF отчета"""
        try:
            # Проверка доступности библиотеки для генерации PDF
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
                from reportlab.lib.styles import getSampleStyleSheet
                from reportlab.lib import colors
                from reportlab.lib.units import inch

                # Создание документа
                filename = f"scan_report_{scan_details['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                filepath = os.path.join("reports", filename)

                # Убедимся, что директория существует
                os.makedirs(os.path.dirname(filepath), exist_ok=True)

                doc = SimpleDocTemplate(filepath, pagesize=letter)
                styles = getSampleStyleSheet()
                story = []

                # Заголовок
                title = Paragraph(f"Отчет о сканировании #{scan_details['id']}", styles['h1'])
                story.append(title)
                story.append(Spacer(1, 0.2*inch))

                # Информация о сканировании
                info_data = [
                    ['URL:', scan_details['url']],
                    ['Типы сканирования:', scan_details['scan_types']],
                    ['Время начала:', scan_details['start_time'] or 'N/A'],
                    ['Время окончания:', scan_details['end_time'] or 'N/A'],
                    ['Статус:', scan_details['status']],
                    ['Найдено уязвимостей:', str(scan_details['vulnerabilities_count'])]
                ]

                info_table = Table(info_data, colWidths=[1.5*inch, 4*inch])
                info_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))

                story.append(info_table)
                story.append(Spacer(1, 0.3*inch))

                # Уязвимости
                if scan_details['vulnerabilities']:
                    vuln_title = Paragraph("Найденные уязвимости", styles['h2'])
                    story.append(vuln_title)
                    story.append(Spacer(1, 0.2*inch))

                    # Заголовки таблицы уязвимостей
                    vuln_headers = ['Тип', 'Серьезность', 'URL', 'Описание']
                    vuln_data = [vuln_headers]

                    for vuln in scan_details['vulnerabilities']:
                        vuln_data.append([
                            vuln['type'],
                            vuln['severity'],
                            vuln['url'][:50] + '...' if len(vuln['url']) > 50 else vuln['url'],
                            vuln['description'][:100] + '...' if len(vuln['description']) > 100 else vuln['description']
                        ])

                    vuln_table = Table(vuln_data, colWidths=[1*inch, 1*inch, 2*inch, 2*inch])
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP')
                    ]))

                    story.append(vuln_table)
                else:
                    no_vuln_text = Paragraph("Уязвимости не найдены", styles['Normal'])
                    story.append(no_vuln_text)

                # Построение PDF
                doc.build(story)

                logger.info(f"Generated PDF report: {filepath}")
                return filepath
            except ImportError:
                logger.error("ReportLab library not available for PDF generation")
                QMessageBox.critical(None, "Ошибка", "Библиотека для генерации PDF не установлена")
                return None
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            return None

    @staticmethod
    def _generate_html_report(scan_details):
        """Генерация HTML отчета"""
        try:
            # Создание HTML содержимого
            html_content = f"""
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Отчет о сканировании #{scan_details['id']}</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        margin: 20px;
                        color: #333;
                    }}
                    h1, h2 {{
                        color: #2c3e50;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-bottom: 20px;
                    }}
                    th, td {{
                        border: 1px solid #ddd;
                        padding: 8px;
                        text-align: left;
                    }}
                    th {{
                        background-color: #f2f2f2;
                    }}
                    .high {{
                        background-color: #ffcccc;
                    }}
                    .medium {{
                        background-color: #ffffcc;
                    }}
                    .low {{
                        background-color: #ccffcc;
                    }}
                </style>
            </head>
            <body>
                <h1>Отчет о сканировании #{scan_details['id']}</h1>

                <h2>Информация о сканировании</h2>
                <table>
                    <tr><th>URL</th><td>{scan_details['url']}</td></tr>
                    <tr><th>Типы сканирования</th><td>{scan_details['scan_types']}</td></tr>
                    <tr><th>Время начала</th><td>{scan_details['start_time'] or 'N/A'}</td></tr>
                    <tr><th>Время окончания</th><td>{scan_details['end_time'] or 'N/A'}</td></tr>
                    <tr><th>Статус</th><td>{scan_details['status']}</td></tr>
                    <tr><th>Найдено уязвимостей</th><td>{scan_details['vulnerabilities_count']}</td></tr>
                </table>
            """

            # Добавление уязвимостей
            if scan_details['vulnerabilities']:
                html_content += """
                <h2>Найденные уязвимости</h2>
                <table>
                    <tr>
                        <th>Тип</th>
                        <th>Серьезность</th>
                        <th>URL</th>
                        <th>Описание</th>
                        <th>Доказательство</th>
                    </tr>
                """

                for vuln in scan_details['vulnerabilities']:
                    severity_class = vuln['severity'].lower()
                    html_content += f"""
                    <tr class="{severity_class}">
                        <td>{vuln['type']}</td>
                        <td>{vuln['severity']}</td>
                        <td>{vuln['url']}</td>
                        <td>{vuln['description']}</td>
                        <td>{vuln.get('evidence', 'N/A')}</td>
                    </tr>
                    """

                html_content += """
                </table>
                """
            else:
                html_content += "<p>Уязвимости не найдены</p>"

            html_content += """
            </body>
            </html>
            """

            # Сохранение HTML файла
            filename = f"scan_report_{scan_details['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            filepath = os.path.join("reports", filename)

            # Убедимся, что директория существует
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"Generated HTML report: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return None

    def open_report(self, filepath):
        """Открытие отчета"""
        try:
            if os.path.exists(filepath):
                import webbrowser
                webbrowser.open(filepath)
                logger.info(f"Opened report: {filepath}")
            else:
                logger.warning(f"Report file not found: {filepath}")
                QMessageBox.warning(None, "Предупреждение", "Файл отчета не найден")
        except Exception as e:
            logger.error(f"Error opening report: {e}")
            QMessageBox.critical(None, "Ошибка", f"Не удалось открыть отчет: {e}")
