import json
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLineEdit, QCheckBox,
                         QSpinBox, QMessageBox,
                         QFileDialog, QComboBox, QGroupBox, QDialog, QApplication,
                         QFormLayout, QTextEdit, QProgressBar)

from utils import error_handler
from utils.database import db
from utils.logger import logger
from utils.security import is_safe_url
from views.managers.stats_manager import StatsManager
from views.dashboard_optimized import DashboardStatsMixin
from views.tabs.stats_tab import StatsTabWidget
from views.mixins.export_mixin import ExportMixin
from views.mixins.scan_mixin import ScanMixin
from views.mixins.log_mixin import LogMixin

# Импорт matplotlib с обработкой ошибок
try:
    import matplotlib
    matplotlib.use('Qt5Agg')
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    matplotlib_available = True
except ImportError as e:
    logger.warning(f"matplotlib not available: {e}")
    matplotlib_available = False
    FigureCanvas = None
    Figure = None

from policies.policy_manager import PolicyManager

# Импортируем оптимизированные компоненты
from views.dashboard_window_optimized import DashboardWindowBase, DashboardWindowUI, DashboardWindowHandlers


class DashboardWindow(DashboardWindowBase, DashboardWindowUI, DashboardWindowHandlers, 
                    DashboardStatsMixin, ExportMixin, ScanMixin, LogMixin, QWidget):
    """
    Основное окно приложения с панелью управления
    Объединяет функциональность из нескольких миксинов и вспомогательных классов
    """

    # Сигналы
    scan_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    _log_loaded_signal = pyqtSignal(str, int)
    _scan_result_signal = pyqtSignal(dict)
    
    def setParent(self, parent: Optional['QWidget'] = None) -> None:
        """Корректная реализация метода setParent для совместимости со всеми базовыми классами"""
        QWidget.setParent(self, parent)

    def __init__(self, user_id: int, username: str, user_model: Any, parent: Optional[QWidget] = None) -> None:
        # Инициализация родительского класса QWidget
        QWidget.__init__(self, parent)
        
        # Инициализация атрибутов с явным указанием типов
        self.stats_tab: Optional[StatsTabWidget] = None

        # Инициализация миксинов
        DashboardStatsMixin.__init__(self)
        ExportMixin.__init__(self, user_id)
        ScanMixin.__init__(self, user_id)
        LogMixin.__init__(self)

        # Базовые настройки
        self.error_handler = error_handler
        self.setWindowTitle("Web Scanner - Control Panel")
        self.user_id = user_id
        self.user_model = user_model
        self.username = username
        self.avatar_path = "default_avatar.png"
        self.tabs_initialized = False

        # Адаптация размера окна под размер экрана
        screen = QApplication.primaryScreen()
        if screen is not None:
            geometry = screen.geometry()
            width = min(geometry.width() - 100, 1200)  # Максимальная ширина 1200px
            height = min(geometry.height() - 100, 800)  # Максимальная высота 800px
            self.resize(width, height)
        else:
            # Значения по умолчанию при ошибке доступа к геометрии экрана
            logger.warning("Primary screen not available, using default window size")
            self.resize(1200, 800)

        # Инициализация атрибутов
        self._init_attributes()

        # Инициализация компонентов
        self.init_components()

        # Настройка UI
        self.setup_ui()

        # Загрузка политик
        self.load_policies_to_combobox()

        # Инициализация оставшихся компонентов
        self._finalize_initialization()

        logger.info(f"Opened control panel for user '{self.username}' (ID: {self.user_id})")

    def load_policies_to_combobox(self):
        """Загрузка политик в выпадающий список"""
        try:
            if hasattr(self, 'policy_combo'):
                policy_manager = PolicyManager()
                policy_names = policy_manager.list_policies()

                self.policy_combo: QComboBox
                self.policy_combo.clear()
                self.policy_combo.addItem("Выберите политику", None)

                for policy_name in policy_names:
                    try:
                        policy = policy_manager.load_policy(policy_name)
                        if policy:
                            # Извлекаем ID из имени политики (формат "policy_123")
                            policy_id = int(policy_name.split('_')[1]) if '_' in policy_name else None
                            self.policy_combo.addItem(policy.get('name', policy_name), policy_id)
                    except Exception as e:
                        logger.warning(f"Error loading policy {policy_name}: {e}")

                logger.info(f"Loaded {len(policy_names)} policies to combobox")
            else:
                logger.warning("Policy combobox not initialized")
        except Exception as e:
            logger.error(f"Error loading policies to combobox: {e}")

    def load_avatar(self):
        """Загрузка аватара пользователя"""
        try:
            # Проверяем наличие аватара в базе данных
            conn = db.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT avatar_path FROM users WHERE id = ?", (self.user_id,))
            result = cursor.fetchone()
            conn.close()

            if result and result[0]:
                avatar_path = result[0]
                if os.path.exists(avatar_path) and hasattr(self, 'avatar_label') and self.avatar_label is not None:
                    pixmap = QPixmap(avatar_path)
                    self.avatar_label.setPixmap(pixmap)
                    self.avatar_path = avatar_path
                    logger.info(f"Loaded avatar from {avatar_path}")
                else:
                    logger.warning(f"Avatar file not found: {avatar_path}")
                    self._load_default_avatar()
            else:
                self._load_default_avatar()
        except Exception as e:
            logger.error(f"Error loading avatar: {e}")
            self._load_default_avatar()

    def _load_default_avatar(self):
        """Загрузка аватара по умолчанию"""
        try:
            # Проверяем наличие файла аватара по умолчанию
            default_avatar_path = "assets/default_avatar.png"
            if os.path.exists(default_avatar_path) and hasattr(self, 'avatar_label') and self.avatar_label is not None:
                pixmap = QPixmap(default_avatar_path)
                self.avatar_label.setPixmap(pixmap)
                self.avatar_path = default_avatar_path
            elif hasattr(self, 'avatar_label') and self.avatar_label is not None:
                # Если файла нет, создаем простой аватар с буквой имени пользователя
                self.avatar_label.setText(self.username[0].upper() if self.username else "U")
                self.avatar_label.setStyleSheet("""
                    background-color: #4a86e8;
                    color: white;
                    font-size: 24px;
                    font-weight: bold;
                    border-radius: 32px;
                """)
        except Exception as e:
            logger.error(f"Error loading default avatar: {e}")
            if hasattr(self, 'avatar_label') and self.avatar_label is not None:
                self.avatar_label.setText("U")

    def logout(self):
        """Выход из системы"""
        try:
            from views.login_window import LoginWindow

            # Закрываем текущее окно
            self.close()

            # Создаем и показываем окно входа
            login_window = LoginWindow(user_model=None)
            login_window.show()

            logger.info(f"User {self.username} logged out")
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            QMessageBox.critical(self, "Error", f"Failed to logout: {e}")

    def start_scan(self):
        """Начало сканирования"""
        try:
            url = self.url_input.text().strip()
            if not url:
                QMessageBox.warning(self, "Предупреждение", "Пожалуйста, введите URL для сканирования")
                return

            if not is_safe_url(url):
                QMessageBox.warning(self, "Предупреждение", "Введенный URL не является безопасным")
                return

            # Получаем тип сканирования
            scan_type_text = self.scan_type_combo.currentText()
            scan_types = []

            if scan_type_text == "SQL-инъекции":
                scan_types = ["sql"]
            elif scan_type_text == "XSS":
                scan_types = ["xss"]
            elif scan_type_text == "CSRF":
                scan_types = ["csrf"]
            else:  # "Все"
                scan_types = ["sql", "xss", "csrf"]

            # Показываем индикатор прогресса
            if hasattr(self, 'scan_progress'):
                self.scan_progress: QProgressBar
                self.scan_progress.setVisible(True)
                self.scan_progress.setRange(0, 0)  # Неопределенный прогресс
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(False)

            # Запускаем сканирование
            # Явно указываем типы для Pylance
            import asyncio
            url_str: str = url
            scan_types_list: List[str] = scan_types

            # Запускаем асинхронное сканирование
            asyncio.create_task(self._run_scan(url_str, scan_types_list))

            logger.info(f"Started scan for URL: {url} with types: {scan_types}")
        except Exception as e:
            logger.error(f"Error starting scan: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось начать сканирование: {e}")
            if hasattr(self, 'scan_progress'):
                self.scan_progress.setVisible(False)
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(True)

    def handle_scan_completed(self, results: Dict[str, Any]):
        """Обработка завершения сканирования"""
        try:
            # Скрываем индикатор прогресса
            if hasattr(self, 'scan_progress'):
                self.scan_progress.setVisible(False)
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(True)

            # Обновляем статистику
            self.update_scan_stats(results)

            # Показываем уведомление
            if results.get('vulnerabilities'):
                count = len(results['vulnerabilities'])
                QMessageBox.information(self, "Сканирование завершено", 
                                      f"Сканирование завершено. Найдено уязвимостей: {count}")
            else:
                QMessageBox.information(self, "Сканирование завершено", 
                                      "Сканирование завершено. Уязвимостей не найдено.")

            logger.info(f"Scan completed for URL: {results.get('url', 'Unknown')}")
        except Exception as e:
            logger.error(f"Error handling scan completion: {e}")

    def update_scan_stats(self, results: Dict[str, Any]):
        """Обновление статистики сканирования"""
        try:
            # Обновляем статистику в миксине
            self._update_scan_statistics(results)

            # Обновляем вкладку статистики, если она инициализирована
            if self.stats_tab is not None:
                self.stats_tab.load_statistics()

            logger.info("Updated scan statistics")
        except Exception as e:
            logger.error(f"Error updating scan statistics: {e}")

    def _update_scan_statistics(self, results: Dict[str, Any]):
        """Внутренний метод для обновления статистики сканирования"""
        try:
            url = results.get('url', '')
            vulnerabilities = results.get('vulnerabilities', [])
            scan_time = results.get('scan_time', 0)

            # Сохраняем результаты в базу данных
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Добавляем запись о сканировании
            cursor.execute("""
                INSERT INTO scans (user_id, url, scan_date, vulnerabilities_count, scan_time)
                VALUES (?, ?, ?, ?, ?)
            """, (self.user_id, url, datetime.now().isoformat(), len(vulnerabilities), scan_time))

            scan_id = cursor.lastrowid

            # Добавляем уязвимости
            for vuln in vulnerabilities:
                cursor.execute("""
                    INSERT INTO vulnerabilities (scan_id, type, url, description, severity)
                    VALUES (?, ?, ?, ?, ?)
                """, (scan_id, vuln.get('type', 'Unknown'), vuln.get('url', url),
                      vuln.get('description', 'No description'), vuln.get('severity', 'Medium')))

            conn.commit()
            conn.close()

            # Обновляем статистику в менеджере
            if hasattr(self, 'scan_manager'):
                self.scan_manager.update_stats(key="scan_results", value=len(results.get("vulnerabilities", [])))

            logger.info(f"Saved scan results for URL: {url}")
        except Exception as e:
            logger.error(f"Error updating scan statistics: {e}")

    def _process_log_content(self, content: str, line_count: int):
        """Обработка загруженного содержимого лога"""
        try:
            # Разбираем содержимое лога
            entries: List[Dict[str, Any]] = []
            for line in content.split('\n'):
                if line.strip():
                    try:
                        entry = json.loads(line)
                        entries.append(entry)
                    except json.JSONDecodeError:
                        continue

            # Фильтруем записи по типу
            if line_count == 0:  # Все логи
                self._log_entries = entries
            elif line_count == 1:  # Только ошибки
                self._log_entries = [e for e in entries if e.get('level') == 'ERROR']
            elif line_count == 2:  # Только предупреждения
                self._log_entries = [e for e in entries if e.get('level') == 'WARNING']

            # Обновляем отображение
            self._update_log_display()

            logger.info(f"Processed {len(self._log_entries)} log entries")
        except Exception as e:
            logger.error(f"Error processing log content: {e}")

    def _update_log_display(self):
        """Обновление отображения логов"""
        try:
            if hasattr(self, 'detailed_log') and self.detailed_log is not None:
                self.detailed_log.clear()

                for entry in self._log_entries:
                    # Форматируем запись для отображения
                    timestamp = entry.get('timestamp', '')
                    level = entry.get('level', 'INFO')
                    message = entry.get('message', '')

                    # Определяем цвет в зависимости от уровня
                    if level == 'ERROR':
                        color = 'red'
                    elif level == 'WARNING':
                        color = 'orange'
                    else:
                        color = 'black'

                    # Добавляем запись в лог
                    self.detailed_log.append(
                        f'<span style="color:{color}">[{timestamp}] [{level}] {message}</span>'
                    )

                # Обновляем статус
                if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                    self.log_status_label.setText(f"Показано записей: {len(self._log_entries)}")

                logger.info(f"Updated log display with {len(self._log_entries)} entries")
        except Exception as e:
            logger.error(f"Error updating log display: {e}")

    def init_stats_manager(self):
        """Инициализация менеджера статистики"""
        try:
            self.stats_manager = StatsManager()
            self.stats_manager.stats_updated.connect(self._handle_stats_updated)
            logger.info("Stats manager initialized")
        except Exception as e:
            logger.error(f"Error initializing stats manager: {e}")

    def _handle_stats_updated(self, stats: Dict[str, Any]):
        """Обработка обновления статистики"""
        try:
            self._stats = stats

            # Обновляем отображение статистики
            if hasattr(self, 'stats_tab') and self.stats_tab is not None:
                self.stats_tab.load_statistics()

            logger.info("Stats updated and displayed")
        except Exception as e:
            logger.error(f"Error handling stats update: {e}")

    def refresh_stats(self):
        """Обновление статистики"""
        try:
            if hasattr(self, 'stats_manager'):
                # Используем существующий метод вместо несуществующего refresh_stats
                self._handle_stats_updated({})
                logger.info("Stats refresh requested")
        except Exception as e:
            logger.error(f"Error refreshing stats: {e}")

    def export_data(self, format_type: str):
        """Экспорт данных в указанном формате"""
        try:
            if format_type == 'csv':
                self.export_to_csv()
            elif format_type == 'json':
                self.export_to_json()
            elif format_type == 'xml':
                self.export_to_xml()
            else:
                QMessageBox.warning(self, "Предупреждение", f"Неподдерживаемый формат экспорта: {format_type}")

            logger.info(f"Data export requested in format: {format_type}")
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать данные: {e}")

    def export_to_csv(self):
        """Экспорт данных в CSV"""
        try:
            # Запрашиваем у пользователя путь для сохранения файла
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Экспорт в CSV", "", "CSV Files (*.csv)"
            )

            if not file_path:
                return

            # Получаем данные для экспорта
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Получаем сканирования
            cursor.execute("""
                SELECT s.id, s.url, s.scan_date, s.vulnerabilities_count, s.scan_time
                FROM scans s
                WHERE s.user_id = ?
                ORDER BY s.scan_date DESC
            """, (self.user_id,))

            scans = cursor.fetchall()

            # Записываем в CSV файл
            import csv

            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)

                # Заголовок
                writer.writerow(['ID', 'URL', 'Дата сканирования', 'Количество уязвимостей', 'Время сканирования (сек)'])

                # Данные
                for scan in scans:
                    writer.writerow(scan)

            conn.close()

            QMessageBox.information(self, "Экспорт завершен", f"Данные успешно экспортированы в {file_path}")
            logger.info(f"Data exported to CSV: {file_path}")
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать данные в CSV: {e}")

    def export_to_json(self):
        """Экспорт данных в JSON"""
        try:
            # Запрашиваем у пользователя путь для сохранения файла
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Экспорт в JSON", "", "JSON Files (*.json)"
            )

            if not file_path:
                return

            # Получаем данные для экспорта
            conn = db.get_db_connection()
            conn.row_factory = sqlite3.Row  # Для доступа к колонкам по имени
            cursor = conn.cursor()

            # Получаем сканирования
            cursor.execute("""
                SELECT s.id, s.url, s.scan_date, s.vulnerabilities_count, s.scan_time
                FROM scans s
                WHERE s.user_id = ?
                ORDER BY s.scan_date DESC
            """, (self.user_id,))

            scans = cursor.fetchall()

            # Получаем уязвимости для каждого сканирования
            data: List[Dict[str, Any]] = []
            for scan in scans:
                scan_dict = dict(scan)

                # Получаем уязвимости
                cursor.execute("""
                    SELECT id, type, url, description, severity
                    FROM vulnerabilities
                    WHERE scan_id = ?
                """, (scan['id'],))

                vulnerabilities = cursor.fetchall()
                scan_dict['vulnerabilities'] = [dict(vuln) for vuln in vulnerabilities]

                data.append(scan_dict)

            conn.close()

            # Записываем в JSON файл
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, ensure_ascii=False, indent=4)

            QMessageBox.information(self, "Экспорт завершен", f"Данные успешно экспортированы в {file_path}")
            logger.info(f"Data exported to JSON: {file_path}")
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать данные в JSON: {e}")

    def export_to_xml(self):
        """Экспорт данных в XML"""
        try:
            # Запрашиваем у пользователя путь для сохранения файла
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Экспорт в XML", "", "XML Files (*.xml)"
            )

            if not file_path:
                return

            # Получаем данные для экспорта
            conn = db.get_db_connection()
            conn.row_factory = sqlite3.Row  # Для доступа к колонкам по имени
            cursor = conn.cursor()

            # Получаем сканирования
            cursor.execute("""
                SELECT s.id, s.url, s.scan_date, s.vulnerabilities_count, s.scan_time
                FROM scans s
                WHERE s.user_id = ?
                ORDER BY s.scan_date DESC
            """, (self.user_id,))

            scans = cursor.fetchall()

            # Формируем XML
            xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
            xml_content += '<scans>\n'

            for scan in scans:
                xml_content += f'  <scan id="{scan["id"]}">\n'
                xml_content += f'    <url>{scan["url"]}</url>\n'
                xml_content += f'    <scan_date>{scan["scan_date"]}</scan_date>\n'
                xml_content += f'    <vulnerabilities_count>{scan["vulnerabilities_count"]}</vulnerabilities_count>\n'
                xml_content += f'    <scan_time>{scan["scan_time"]}</scan_time>\n'

                # Получаем уязвимости
                cursor.execute("""
                    SELECT id, type, url, description, severity
                    FROM vulnerabilities
                    WHERE scan_id = ?
                """, (scan['id'],))

                vulnerabilities = cursor.fetchall()

                if vulnerabilities:
                    xml_content += '    <vulnerabilities>\n'

                    for vuln in vulnerabilities:
                        xml_content += f'      <vulnerability id="{vuln["id"]}">\n'
                        xml_content += f'        <type>{vuln["type"]}</type>\n'
                        xml_content += f'        <url>{vuln["url"]}</url>\n'
                        xml_content += f'        <description>{vuln["description"]}</description>\n'
                        xml_content += f'        <severity>{vuln["severity"]}</severity>\n'
                        xml_content += '      </vulnerability>\n'

                    xml_content += '    </vulnerabilities>\n'

                xml_content += '  </scan>\n'

            xml_content += '</scans>'

            conn.close()

            # Записываем в XML файл
            with open(file_path, 'w', encoding='utf-8') as xmlfile:
                xmlfile.write(xml_content)

            QMessageBox.information(self, "Экспорт завершен", f"Данные успешно экспортированы в {file_path}")
            logger.info(f"Data exported to XML: {file_path}")
        except Exception as e:
            logger.error(f"Error exporting to XML: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать данные в XML: {e}")


class PolicyEditDialog(QDialog):
    """Диалог редактирования политики безопасности"""

    def __init__(self, policy_id: Optional[int] = None, parent: Optional[QDialog] = None):
        super().__init__(parent)
        self.policy_id = policy_id
        self.policy_manager = PolicyManager()
        self.setup_ui()

        if policy_id:
            self.load_policy()

    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        self.setWindowTitle("Редактирование политики безопасности")
        self.setMinimumWidth(500)

        layout = QVBoxLayout()
        self.setLayout(layout)

        # Форма
        form_layout = QFormLayout()
        layout.addLayout(form_layout)

        # Название политики
        self.name_edit = QLineEdit()
        form_layout.addRow("Название:", self.name_edit)

        # Описание политики
        self.description_edit = QTextEdit()
        self.description_edit.setMaximumHeight(100)
        form_layout.addRow("Описание:", self.description_edit)

        # Настройки сканирования
        scan_group = QGroupBox("Настройки сканирования")
        scan_layout = QFormLayout()
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)

        # Максимальная глубина
        self.max_depth_spin = QSpinBox()
        self.max_depth_spin.setRange(1, 10)
        self.max_depth_spin.setValue(3)
        scan_layout.addRow("Максимальная глубина:", self.max_depth_spin)

        # Таймаут
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix(" сек")
        scan_layout.addRow("Таймаут:", self.timeout_spin)

        # Типы сканирования
        self.sql_check = QCheckBox("SQL-инъекции")
        self.sql_check.setChecked(True)
        scan_layout.addRow("", self.sql_check)

        self.xss_check = QCheckBox("XSS")
        self.xss_check.setChecked(True)
        scan_layout.addRow("", self.xss_check)

        self.csrf_check = QCheckBox("CSRF")
        self.csrf_check.setChecked(True)
        scan_layout.addRow("", self.csrf_check)

        # Кнопки
        from PyQt5.QtWidgets import QDialogButtonBox
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def load_policy(self):
        """Загрузка данных политики"""
        try:
            # Формируем имя политики из ID
            policy_name = f"policy_{self.policy_id}"
            policy = self.policy_manager.load_policy(policy_name)
            if policy:
                self.name_edit.setText(policy.get('name', ''))
                self.description_edit.setText(policy.get('description', ''))

                # Загрузка настроек
                settings: Dict[str, Any] = policy.get('settings', {})
                if isinstance(settings, str):
                    try:
                        settings = json.loads(settings)
                    except json.JSONDecodeError:
                        settings = {}
                        
                self.max_depth_spin.setValue(settings.get('max_depth', 3))
                self.timeout_spin.setValue(settings.get('timeout', 30))

                scan_types = settings.get('scan_types', [])
                self.sql_check.setChecked('sql' in scan_types)
                self.xss_check.setChecked('xss' in scan_types)
                self.csrf_check.setChecked('csrf' in scan_types)
        except Exception as e:
            logger.error(f"Error loading policy: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить политику: {e}")

    def accept(self):
        """Сохранение политики"""
        try:
            name = self.name_edit.text().strip()
            if not name:
                QMessageBox.warning(self, "Предупреждение", "Пожалуйста, введите название политики")
                return

            # Формируем настройки
            settings: Dict[str, Any] = {
                'max_depth': self.max_depth_spin.value(),
                'timeout': self.timeout_spin.value(),
                'scan_types': []
            }

            if self.sql_check.isChecked():
                settings['scan_types'].append('sql')
            if self.xss_check.isChecked():
                settings['scan_types'].append('xss')
            if self.csrf_check.isChecked():
                settings['scan_types'].append('csrf')

            # Формируем объект политики
            policy_data: Dict[str, Any] = {
                'name': name,
                'description': self.description_edit.toPlainText(),
                'settings': settings
            }

            # Сохраняем политику
            if self.policy_id:
                # Обновление существующей политики
                policy_name = f"policy_{self.policy_id}"
                self.policy_manager.save_policy(policy_name, policy_data)
            else:
                # Создание новой политики
                import time
                policy_id = int(time.time())  # Генерируем уникальный ID на основе времени
                policy_name = f"policy_{policy_id}"
                self.policy_manager.save_policy(policy_name, policy_data)
                self.policy_id = policy_id

            super().accept()
        except Exception as e:
            logger.error(f"Error saving policy: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить политику: {e}")
