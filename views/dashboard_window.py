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

class DashboardWindow(DashboardStatsMixin, ExportMixin, ScanMixin, LogMixin, QWidget):
    
    # Сигналы
    scan_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    _log_loaded_signal = pyqtSignal(str, int)
    _scan_result_signal = pyqtSignal(dict)

    def __init__(self, user_id: int, username, user_model: Any, parent: Optional[QWidget] = None) -> None:
        # Инициализация родительского класса QWidget
        QWidget.__init__(self, parent)

        # Инициализация миксинов
        DashboardStatsMixin.__init__(self)
        ExportMixin.__init__(self, user_id)
        ScanMixin.__init__(self)
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
            width = min(geometry.width() - 100, 1200)  # Максимальна ширина 1200px
            height = min(geometry.height() - 100, 800)  # Максимальна висота 800px
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

    def _init_attributes(self):
        """Инициализация атрибутов класса"""
        # Системные атрибуты
        self._log_loader_thread = None
        self.edit_window = None
        self._visible_rows_timer = None
        self._filtered_scans_data = None
        self._scan_timer = None

        # Менеджеры
        self.scan_manager = ScanManagerStatsMixin()
        self.init_stats_manager()

        # Инициализация атрибутов для сканирования через миксин
        self._init_scan_attributes()

        # UI компоненты (будут инициализированы в init_components)
        self.main_layout = None
        self.tabs = None
        self.avatar_label = None
        self.username_label = None
        self.scan_button = None

        # Логи и фильтры
        self._log_entries = []
        self._filtered_log_entries = []
        self.detailed_log = None
        self.log_status_label = None

        # Вкладки
        self.scan_tab = None
        self.reports_tab = None
        self.stats_tab = None
        self.profile_tab = None

        # Статистика
        self._stats = None

        # Сигналы
        self._log_loaded_signal.connect(self._process_log_content)

    def _finalize_initialization(self):
        """Завершение инициализации компонентов"""
        try:
            # Инициализация вкладок
            self.initialize_tabs()

            # Инициализация stats_canvas
            self.stats_canvas = None
            if MATPLOTLIB_AVAILABLE and FigureCanvas is not None:
                try:
                    from matplotlib.figure import Figure
                    self.stats_canvas = FigureCanvas(Figure())
                except Exception as matplotlib_error:
                    logger.warning(f"Failed to initialize matplotlib canvas: {matplotlib_error}")
                    self.stats_canvas = None

            # Загружаем аватар после создания всех компонентов
            if hasattr(self, 'avatar_label') and self.avatar_label is not None:
                self.load_avatar()
            else:
                logger.error("Avatar label not initialized after setup_ui")

        except Exception as init_error:
            logger.error(f"Failed to initialize dashboard window: {init_error}")
            QMessageBox.critical(self, "Error", f"Failed to initialize dashboard window: {init_error}")
            raise

    def initialize_tabs(self):
        try:
            if not self.tabs_initialized:
                # Проверка инициализации вкладок
                if not hasattr(self, 'tabs') or self.tabs is None:
                    self.tabs = QTabWidget()
                    if hasattr(self, 'main_layout') and self.main_layout is not None:
                        self.main_layout.addWidget(self.tabs)
                    else:
                        logger.error("Main layout not initialized")
                        return
                
                # Проверка инициализации компонентов
                if not hasattr(self, 'user_id'):
                    logger.error("User ID not initialized")
                    return
                
                self.scan_tab = ScanTabWidget(self.user_id, self)
                self.reports_tab = ReportsTabWidget(self.user_id, self)
                self.stats_tab = StatsTabWidget(self.user_id, self)
                self.profile_tab = ProfileTabWidget(self.user_id, self)

                # Проверка, что все вкладки созданы
                if not all([self.scan_tab, self.reports_tab, self.stats_tab, self.profile_tab]):
                    raise ValueError("Failed to initialize one or more tabs")

                # Добавляем вкладки в QTabWidget
                self.tabs.addTab(self.scan_tab, "Сканирование")
                self.tabs.addTab(self.reports_tab, "Отчёты")
                self.tabs.addTab(self.stats_tab, "Статистика")
                self.tabs.addTab(self.profile_tab, "Профиль")

                self.tabs_initialized = True
                logger.info("Tabs initialized successfully")
        
        except Exception as tabs_error:
            logger.error(f"Error initializing tabs: {tabs_error}")
            error_handler.show_error_message("Ошибка", f"Не удалось инициализировать вкладки: {tabs_error}")

    def init_components(self):
        """Инициализация всех необходимых компонентов"""
        try:
            # Инициализация базовых компонентов
            self.main_layout = QVBoxLayout(self)
            self.tabs = QTabWidget()
            self.avatar_label = QLabel()
            self.username_label = QLabel()
            
            # Инициализация контроллера
            self.scan_controller = ScanController(self.user_id)
            
            # Инициализация состояния
            self._scan_start_time = None
            self._total_urls = 0
            self._completed_urls = 0
            self._total_progress = 0
            self._active_workers = 0
            self._worker_progress = {}
            self._is_paused = False
            
            # Инициализация менеджера политик
            self.policy_manager = PolicyManager()
            self.selected_policy = None

            # Инициализация компонентов лога
            self.detailed_log = QTextEdit()
            self._log_entries = []
            self._filtered_log_entries = []
            self.log_status_label = QLabel()

            # Инициализация статистики
            self._stats = {
                'urls_found': 0,
                'urls_scanned': 0,
                'forms_found': 0,
                'forms_scanned': 0,
                'vulnerabilities': 0,
                'requests_sent': 0,
                'errors': 0,
            }

            # Добавляем инициализацию компонентов сканирования
            self.url_input = QLineEdit()
            self.sql_checkbox = QCheckBox("SQL Injection")
            self.xss_checkbox = QCheckBox("XSS")
            self.csrf_checkbox = QCheckBox("CSRF")
            self.depth_spinbox = QSpinBox()
            self.concurrent_spinbox = QSpinBox()
            self.timeout_spinbox = QSpinBox()
            self.max_coverage_checkbox = QCheckBox("Максимальное покрытие")
            self.turbo_checkbox = QCheckBox("Турбо режим")

            # Инициализация кнопок
            self.scan_button = QPushButton("Начать сканирование")
            self.pause_button = QPushButton("⏸️ Пауза")
            self.stop_button = QPushButton("⏹️ Стоп")
            
            # Инициализация элементов прогресса
            self.scan_progress = QProgressBar()
            self.progress_label = QLabel("0%")
            self.scan_status = QLabel("Готов к сканированию")
            
            # Инициализация фильтров
            self.filter_input = QLineEdit()
            self.filter_sql_cb = QCheckBox("SQL Injection")
            self.filter_xss_cb = QCheckBox("XSS")
            self.filter_csrf_cb = QCheckBox("CSRF")
            self.date_from = QDateTimeEdit()
            self.date_to = QDateTimeEdit()
            
            # Инициализация таблицы и текстовых полей
            self.scans_table = QTableWidget()
            self.reports_text = QTextEdit()
            self.activity_log = QTextEdit()
            self.stats_text = QTextEdit()
            
            # Инициализация компонентов лога
            self.log_search = QLineEdit()
            self.auto_scroll_checkbox = QCheckBox("Автопрокрутка")
            self.clear_log_checkbox = QCheckBox("Очищать лог перед сканированием")

            # Инициализация комбобокса политик
            self.policy_combobox = QComboBox()

            # Инициализация множеств для отслеживания
            self._scanned_urls = set()
            self._scanned_forms = set()
            
            logger.info("Dashboard components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize dashboard components: {e}")
            raise

    @staticmethod
    def format_duration(seconds):
        """Форматирует время в часы, минуты и секунды"""
        if seconds < 60:
            return f"{seconds:.1f} сек"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = seconds % 60
            return f"{minutes} мин {secs:.1f} сек"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            secs = seconds % 60
            return f"{hours} ч {minutes} мин {secs:.1f} сек"

    def setup_ui(self):
        """Настройка основного пользовательского интерфейса"""
        try:
            # Устанавливаем заголовок окна
            self.setWindowTitle("Панель управления")
            self.setMinimumSize(800, 600)

            # Создаем layout для прогресса
            progress_layout = QHBoxLayout()
            progress_layout.addWidget(self.scan_progress)
            progress_layout.addWidget(self.progress_label)

            # Добавляем layout прогресса в основной layout
            if not hasattr(self, 'main_layout') or self.main_layout is None:
                self.main_layout = QVBoxLayout(self)
            
            self.main_layout.addLayout(progress_layout)

            # Создаем основной контейнер с прокруткой
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)

            # Создаем виджет-контейнер для всего содержимого
            content_widget = QWidget()
            content_widget.setMinimumSize(800, 600)

            # Проверка инициализации основного layout
            if not hasattr(self, 'main_layout') or self.main_layout is None:
                self.main_layout = QVBoxLayout(content_widget)
                self.main_layout.addWidget(scroll)
                self.setLayout(self.main_layout)

            # Добавление комбобокса политик
            policy_layout = QHBoxLayout()
            policy_label = QLabel("Политика сканирования:")
            self.policy_combobox = QComboBox()
            policy_layout.addWidget(policy_label)
            policy_layout.addWidget(self.policy_combobox)
            self.main_layout.addLayout(policy_layout)

            # Загрузка политик после создания комбобокса
            self.load_policies_to_combobox()
            
            # Убеждаемся, что tabs инициализирован
            if self.tabs is None:
                self.tabs = QTabWidget()

            # Создаем виджет для аватара и информации о пользователе
            user_info_widget = QWidget()
            user_info_layout = QHBoxLayout(user_info_widget)
            
            # Создаем QLabel для аватара
            self.avatar_label = QLabel()
            self.avatar_label.setFixedSize(200, 200)
            self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.avatar_label.setStyleSheet("border: 1px solid gray; border-radius: 5px;")
            user_info_layout.addWidget(self.avatar_label)
            
            # Добавляем информацию о пользователе
            user_text_layout = QVBoxLayout()
            self.username_label = QLabel(f"Добро пожаловать, {self.username}!")
            self.username_label.setStyleSheet("font-size: 16px; font-weight: bold;")
            user_text_layout.addWidget(self.username_label)
            user_text_layout.addStretch()
            user_info_layout.addLayout(user_text_layout)
            
            # Добавляем виджет информации о пользователе в основной layout
            self.main_layout.addWidget(user_info_widget)
            
            # Отложенная инициализация вкладок
            self.initialize_tabs()
            
            self.main_layout.addWidget(self.tabs)
            self.setLayout(self.main_layout)

            # Проверяем, что все необходимые компоненты инициализированы
            if not all([hasattr(self, 'main_layout'), hasattr(self, 'tabs'), hasattr(self, 'username_label'), hasattr(self, 'avatar_label')]):
                logger.error("Some components are not initialized")
                return
            
            # Загружаем аватар после создания всех компонентов
            self.load_avatar()

            # Загружаем лог сканера
            self.load_scanner_log_to_ui()
            
        except Exception as e:
            logger.exception(f"Error when configuring the interface: {str(e)}")
            QMessageBox.warning(self, "Ошибка", f"Ошибка при настройке интерфейса: {str(e)}")
        
        # Автоматически загружаем лог сканера при запуске (после создания всех атрибутов)
        try:
            self.load_scanner_log_to_ui()
        except Exception as e:
            logger.warning(f"Failed to load scanner log: {e}")

    def update_user(self, user_id, username):
        self.user_id = user_id
        self.username = username
        self.update_profile_info()

    def update_profile_info(self):
        """Обновляет информацию профиля"""
        if hasattr(self, 'username_label') and self.username_label is not None:
            self.username_label.setText(f"Добро пожаловать, {self.username}!")
        else:
            logger.error("Username label is not initialized")

    def load_policies_to_combobox(self):
        """Загружает политики в комбобокс"""
        # Проверяем, что объект инициализирован
        if self.policy_combobox is not None:
            self.policy_combobox.clear()
            policies = self.policy_manager.list_policies()
            if not policies:
                # Если нет политик, создаём и добавляем дефолтную
                default_policy = self.policy_manager.get_default_policy()
                self.policy_manager.save_policy("default", default_policy)
                policies = ["default"]
            self.policy_combobox.addItems(policies)
            self.selected_policy = self.policy_manager.load_policy(policies[0])
        else:
            logger.error("policy_combobox is not initialized")

    def on_policy_selected(self, idx):
        if idx >= 0 and self.policy_combobox is not None:
            name = self.policy_combobox.itemText(idx)
            if name:
                self.selected_policy = self.policy_manager.load_policy(name)
                logger.info(f"Selected policy: {name} - {self.selected_policy}")

                # Применяем настройки политики к UI
                if self.selected_policy:
                    # Обновляем настройки производительности
                    if 'max_depth' in self.selected_policy:
                        self.depth_spinbox.setValue(self.selected_policy['max_depth'])
                    if 'max_concurrent' in self.selected_policy:
                        self.concurrent_spinbox.setValue(self.selected_policy['max_concurrent'])
                    if 'timeout' in self.selected_policy:
                        self.timeout_spinbox.setValue(self.selected_policy['timeout'])

                    # Обновляем типы уязвимостей
                    enabled_vulns = self.selected_policy.get('enabled_vulns', [])
                    self.sql_checkbox.setChecked('sql' in enabled_vulns)
                    self.xss_checkbox.setChecked('xss' in enabled_vulns)
                    self.csrf_checkbox.setChecked('csrf' in enabled_vulns)

                    logger.info(f"Applied policy settings: depth={self.depth_spinbox.value()}, concurrent={self.concurrent_spinbox.value()}, timeout={self.timeout_spinbox.value()}")

    def create_policy_dialog(self):
        dlg = PolicyEditDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            policy = dlg.get_policy()
            name = policy["name"]
            if name in self.policy_manager.list_policies():
                QMessageBox.warning(self, "Ошибка", f"Политика с именем '{name}' уже существует.")
                return
            self.policy_manager.save_policy(name, policy)
            self.load_policies_to_combobox()
            if self.policy_combobox is not None:
                idx = self.policy_combobox.findText(name)
                if idx >= 0:
                    self.policy_combobox.setCurrentIndex(idx)

    def edit_policy_dialog(self):
        if self.policy_combobox is None:
            log_and_notify('error', "policy_combobox is not initialized")
            return
        name = self.policy_combobox.currentText()
        if not name:
            return
        policy = self.policy_manager.load_policy(name)
        dlg = PolicyEditDialog(self, policy)
        if dlg.exec_() == QDialog.Accepted:
            new_policy = dlg.get_policy()
            self.policy_manager.save_policy(name, new_policy)
            self.load_policies_to_combobox()
            if self.policy_combobox is not None:
                idx = self.policy_combobox.findText(name)
                if idx >= 0:
                    self.policy_combobox.setCurrentIndex(idx)

    def delete_policy(self):
        if self.policy_combobox is None:
            log_and_notify('error', "policy_combobox is not initialized")
            return
        name = self.policy_combobox.currentText()
        if name:
            self.policy_manager.delete_policy(name)
            self.load_policies_to_combobox()

    @asyncSlot()
    async def scan_website_sync(self):
        """Асинхронный метод для подключения к кнопке"""
        try:
            if not self.url_input or not self.url_input.text().strip():
                if hasattr(self, 'error_handler'):
                    error_handler.show_error_message("Ошибка", "Введите URL для сканирования")
                return
            
            url = self.url_input.text().strip()
            if not is_safe_url(url):
                if hasattr(self, 'error_handler'):
                    error_handler.show_warning_message("Предупреждение",
                        "URL может быть небезопасным. Убедитесь, что вы сканируете только свои собственные сайты.")
                return
            
            await self.scan_website()
        except Exception as scan_error:
            if hasattr(self, 'error_handler'):
                error_handler.handle_validation_error(scan_error, "scan_website_sync")
            log_and_notify('error', f"Error in scan_website_sync: {scan_error}")

    async def scan_website(self):
        """Запускает сканирование веб-сайта"""
        try:
            url = self.url_input.text().strip()
            
            # Валидация URL с помощью security модуля
            if not url:
                error_handler.show_error_message("Ошибка", "Введите URL для сканирования")
                return
            
            if not is_safe_url(url):
                error_handler.show_warning_message("Предупреждение", 
                    "URL может быть небезопасным. Убедитесь, что вы сканируете только свои собственные сайты.")
            
            # Получаем выбранные типы сканирования
            selected_types = []
            if self.sql_checkbox.isChecked():
                selected_types.append("SQL Injection")
            if self.xss_checkbox.isChecked():
                selected_types.append("XSS")
            if self.csrf_checkbox.isChecked():
                selected_types.append("CSRF")
            
            if not selected_types:
                error_handler.show_error_message("Ошибка", "Выберите хотя бы один тип сканирования")
                return
            
            # Получаем параметры производительности
            max_depth = self.depth_spinbox.value()
            max_concurrent = self.concurrent_spinbox.value()
            timeout = self.timeout_spinbox.value()
            max_coverage_mode = getattr(self, '_max_coverage_mode', False)
            
            # Запускаем сканирование
            await self.start_scan(url, selected_types, max_depth, max_concurrent, timeout, max_coverage_mode)
            
        except Exception as e:
            error_handler.handle_validation_error(e, "scan_website")
            log_and_notify('error', f"Error in scan_website: {e}")

    async def start_scan(self, url: str, types: list, max_depth: int, max_concurrent: int, timeout: int, max_coverage_mode: bool = False):
        """Запускает процесс сканирования"""
        try:
            if self.scan_controller is None:
                raise ValueError("Сканер не инициализирован")

            # Проверка на корректность URL
            if not db.is_valid_url(url):
                error_handler.show_error_message("Ошибка", "Некорректный URL")
                return

            # Проверка на корректность типа сканирования
            if not types:
                error_handler.show_error_message("Ошибка", "Выберите хотя бы один тип сканирования")
                return
            
            # Запуск сканирования через менеджер
            self.scan_manager.start_scan(url)

            # Очистка лога сканера если включено
            if hasattr(self, 'clear_log_checkbox') and self.clear_log_checkbox.isChecked():
                self.scan_manager.clear_scan_log()
            
            # Сброс компонентов интерфейса с проверками на None
            if hasattr(self, 'scan_progress') and self.scan_progress is not None:
                self.scan_progress.setValue(0)
            if hasattr(self, 'scan_status') and self.scan_status is not None:
                self.scan_status.setText("Подготовка к сканированию...")
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(False)
            if hasattr(self, 'pause_button') and self.pause_button is not None:
                self.pause_button.setEnabled(True)
            if hasattr(self, 'stop_button') and self.stop_button is not None:
                self.stop_button.setEnabled(True)
            
            # Сброс состояния паузы
            self._is_paused = False
            if hasattr(self, 'pause_button') and self.pause_button is not None:
                self.pause_button.setText("⏸️ Пауза")
            
            # Очистка древовидного представления и статистики
            if hasattr(self, 'site_tree') and self.site_tree is not None:
                self.site_tree.clear()
            if hasattr(self, '_log_entries') and self._log_entries is not None:
                self._log_entries.clear()
            if hasattr(self, '_filtered_log_entries') and self._filtered_log_entries is not None:
                self._filtered_log_entries.clear()
            
            # Инициализация множеств для отслеживания
            self._scanned_urls = set()
            self._scanned_forms = set()
            
            # Инициализация статистики
            self._stats = {
                'urls_found': 0,
                'urls_scanned': 0,
                'forms_found': 0,
                'forms_scanned': 0,
                'vulnerabilities': 0,
                'requests_sent': 0,
                'errors': 0,
                'scan_start_time': datetime.now()
            }
            
            # Обновление меток статистики
            if hasattr(self, 'stats_labels') and self.stats_labels is not None:
                for key in self.stats_labels:
                    if self.stats_labels[key] is not None:
                        self.stats_labels[key].setText("0")
                if 'scan_time' in self.stats_labels and self.stats_labels['scan_time'] is not None:
                    self.stats_labels['scan_time'].setText("00:00:00")
            
            # Обновление статуса сканирования
            if hasattr(self, 'scan_status') and self.scan_status is not None:
                self.scan_status.setText("Сканирование...")
            if hasattr(self, 'progress_label') and self.progress_label is not None:
                self.progress_label.setText("0%")
            
            # Добавление начальных записей в лог
            self._add_log_entry("INFO", f"🚀 Начало сканирования: {url}")
            self._add_log_entry("INFO", f"📋 Типы сканирования: {', '.join(types)}")
            self._add_log_entry("INFO", f"⚙️ Параметры: глубина={max_depth}, параллельно={max_concurrent}, таймаут={timeout}с")
            
            # Применение настроек политики
            policy = self.selected_policy or self.policy_manager.get_default_policy()
            types = policy.get("enabled_vulns", types)
            max_depth = policy.get("max_depth", max_depth)
            max_concurrent = policy.get("max_concurrent", max_concurrent)
            timeout = policy.get("timeout", timeout)
            
            # Запуск сканирования
            await self.scan_controller.start_scan(
                url=url,
                scan_types=types,
                max_depth=max_depth,
                max_concurrent=max_concurrent,
                timeout=timeout,
                on_progress=self._on_scan_progress,
                on_log=self._on_scan_log,
                on_vulnerability=self._on_vulnerability_found,
                on_result=self._on_scan_result,
                max_coverage_mode=max_coverage_mode
            )
            
            # Запуск мониторинга производительности
            performance_monitor.start_timer("scan_session")
            
        except Exception as e:
            # Обработка ошибок
            if hasattr(self, '_scan_timer') and self._scan_timer is not None:
                self._scan_timer.stop()
            
            error_handler.handle_network_error(e, "start_scan")
            log_and_notify('error', f"Error in start_scan: {e}")
            
            # Сброс интерфейса при ошибке
            if hasattr(self, 'scan_status') and self.scan_status is not None:
                self.scan_status.setText("Ошибка запуска сканирования")
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(True)
            if hasattr(self, 'stop_button') and self.stop_button is not None:
                self.stop_button.setEnabled(False)

    def _clear_scanner_log_file(self):
        """Очищает файл scanner.log для экономии места"""
        try:
            import os
            from utils.logger import get_log_dir
            
            # Получаем путь к директории логов
            log_dir = get_log_dir()
            scanner_log_path = os.path.join(log_dir, 'scanner.log')
            
            # Проверяем существование файла
            if os.path.exists(scanner_log_path):
                # Очищаем файл, сохраняя только заголовок
                with open(scanner_log_path, 'w', encoding='utf-8') as f:
                    f.write(f"=== СКАНИРОВАНИЕ НАЧАТО: {get_local_timestamp()} ===\n")
                    f.write("=" * 80 + "\n\n")
                
                # Добавляем информацию в UI лог
                self._add_log_entry("INFO", "🗑️ Файл scanner.log очищен")
                logger.info("Scanner log file cleared for new scan")
            else:
                # Если файл не существует, создаем его с заголовком
                with open(scanner_log_path, 'w', encoding='utf-8') as f:
                    f.write(f"=== СКАНИРОВАНИЕ НАЧАТО: {get_local_timestamp()} ===\n")
                    f.write("=" * 80 + "\n\n")
                
                self._add_log_entry("INFO", "📝 Создан новый файл scanner.log")
                logger.info("New scanner log file created")
                
        except Exception as e:
            # В случае ошибки логируем, но не прерываем сканирование
            error_msg = f"Не удалось очистить файл scanner.log: {str(e)}"
            self._add_log_entry("ERROR", error_msg)
            logger.warning(f"Failed to clear scanner log file: {e}")

    def _add_log_entry(self, level: str, message: str, url: str = "", details: str = "") -> None:
        """Добавляет запись в детальный лог с цветовой кодировкой"""
        try:
            if not hasattr(self, '_log_entries') or self._log_entries is None:
                self._log_entries = []

            if not hasattr(self, '_filtered_log_entries') or self._filtered_log_entries is None:
                self._filtered_log_entries = []

            # Получаем временную метку и извлекаем только время HH:MM:SS
            timestamp = extract_time_from_timestamp(get_local_timestamp())
            
            # Проверяем, что все необходимые атрибуты инициализированы
            if not hasattr(self, '_stats') or self._stats is None:
                self._stats = {
                    'urls_found': 0,
                    'urls_scanned': 0,
                    'forms_found': 0,
                    'forms_scanned': 0,
                    'vulnerabilities': 0,
                    'requests_sent': 0,
                    'errors': 0,
                }

            # Получаем временную метку и извлекаем только время HH:MM:SS
            timestamp = extract_time_from_timestamp(get_local_timestamp())
            
            # Проверяем, что все необходимые атрибуты инициализированы
            if not hasattr(self, '_stats') or not hasattr(self, '_log_entries'):
                log_and_notify('error', "Required attributes not initialized in _add_log_entry")
                return
            
            # Обновляем счетчик ошибок
            if level == "ERROR":
                self._stats['errors'] += 1
                self._update_stats('errors', self._stats['errors'])
            
            # Определяем цвет для уровня
            color_map = {
                "DEBUG": "#888888",      # Серый
                "INFO": "#00ff00",      # Зеленый
                "WARNING": "#ffff00",   # Желтый
                "ERROR": "#ff0000",     # Красный
                "VULNERABILITY": "#ff6600",  # Оранжевый
                "REQUEST": "#00ffff",   # Голубой
                "RESPONSE": "#ff00ff",  # Пурпурный
                "PROGRESS": "#ffffff",   # Белый
                "SKIP_FILE": "#87ceeb",   # Светло-синий
                "ADD_LINK": "#ffa500"    # Оранжевый (или другой отличимый цвет)
            }
            
            color = color_map.get(level, "#ffffff")
            
            # Формируем HTML для записи c использование шаблона для оптимизации
            html_entry = (
                f'<div style="margin: 2px 0;">'
                f'<span style="color: {color}; font-weight: bold;">{timestamp} [{level}]</span>'
            )
            
            if url:
                html_entry += f' <span style="color: #3498db;">{url}</span>'
            
            html_entry += f' <span style="color: #ffffff;">{message}</span>'
            
            if details:
                html_entry += f'<br><span style="color: #cccccc; margin-left: 20px;">{details}</span>'
            
            html_entry += '</div>'
            
            # Добавляем в список записей
            log_entry = {
                'timestamp': timestamp,
                'level': level,
                'message': message,
                'url': url,
                'details': details,
                'html': html_entry
            }
            
            self._log_entries.append(log_entry)
            
            # Обновляем отфильтрованный список только если фильтры активны
            if hasattr(self, '_current_filter') and self._current_filter != "Все" or \
               hasattr(self, '_search_text') and self._search_text:
                self._apply_filters()
            else:
                # Если фильтры не активны, добавляем запись в отфильтрованный список
                self._filtered_log_entries.append(log_entry)
            
            # Обновляем отображение с ограничением частоты обновлений
            if not hasattr(self, '_last_log_update'):
                self._last_log_update = 0

            current_time = time.time()
            if current_time - self._last_log_update > 0.5: # Обновляем не чаще, чем раз в 0.5 секунды
                self._update_log_display()
                self._last_log_update = current_time
            
            # Автоскролл если включен
            if hasattr(self, 'auto_scroll_checkbox') and self.auto_scroll_checkbox.isChecked():
                if hasattr(self, 'detailed_log') and self.detailed_log is not None:
                    vbar = self.detailed_log.verticalScrollBar()
                    if vbar is not None:
                        vbar.setValue(vbar.maximum())
                    
        except Exception as e:
            log_and_notify('error', f"Error in _add_log_entry: {e}")
            # Не прерываем выполнение, просто логируем ошибку

    def _apply_filters(self):
        """Применяет фильтры к логу"""
        try:
            # Проверяем инициализацию компонентов
            if not hasattr(self, '_log_entries') or self._log_entries is None:
                self._log_entries = []
            if not hasattr(self, '_filtered_log_entries') or self._filtered_log_entries is None:
                self._filtered_log_entries = []
                
            self._filtered_log_entries = []
            
            for entry in self._log_entries:
                # Фильтр по уровню
                if self._current_filter != "Все" and entry['level'] != self._current_filter:
                    continue
                
                # Фильтр по поиску
                if self._search_text:
                    search_lower = self._search_text.lower()
                    if (search_lower not in entry['message'].lower() and 
                        search_lower not in entry['url'].lower() and
                        search_lower not in entry['details'].lower()):
                        continue
                
                self._filtered_log_entries.append(entry)
                
            self._update_log_display()
        except Exception as e:
            log_and_notify('error', f"Error in _apply_filters: {e}")

    def _update_log_display(self):
        """Обновляет отображение лога"""
        try:
            if not hasattr(self, 'detailed_log') or not hasattr(self, '_filtered_log_entries'):
                return
            
            if self._filtered_log_entries is None:
                self._filtered_log_entries = []
                
            html_content = ""
            for entry in self._filtered_log_entries:
                html_content += entry['html']
            
            if self.detailed_log is not None:
                self.detailed_log.setHtml(html_content)
        except Exception as update_error:
            log_and_notify('error', f"Error in _update_log_display: {update_error}")

    def _filter_log(self, filter_text: str):
        """Обработчик изменения фильтра"""
        self._current_filter = filter_text
        self._apply_filters()
        self._update_log_display()

    def _search_in_log(self, search_text: str):
        """Обработчик поиска в логе"""
        self._search_text = search_text.lower()
        self._apply_filters()
        self._update_log_display()

    def _clear_search(self):
        """Очищает поиск"""
        self.log_search.clear()
        self._search_text = ""
        self._apply_filters()
        self._update_log_display()

    def _update_stats(self, key: str, value: int) -> None:
        """Обновляет статистику"""
        try:
            if not hasattr(self, '_stats') or self._stats is None:
                self._stats = {
                    'urls_found': 0,
                    'urls_scanned': 0,
                    'forms_found': 0,
                    'forms_scanned': 0,
                    'vulnerabilities': 0,
                    'requests_sent': 0,
                    'errors': 0,
                }
            
            if key in self._stats:
                self._stats[key] = value
                
            # Используем пакетное обновление UI
            if not hasattr(self, '_pending_stats_updates'):
                self._pending_stats_updates = {}

            self._pending_stats_updates[key] = value

            # Запланируем обновление UI, если ещё не заплпанировано
            if not hasattr(self, '_stats_update_timer') or self._stats_update_timer is None or not self._stats_update_timer.isActive():
                self._stats_update_timer = QTimer(self)
                self._stats_update_timer.setSingleShot(True)
                self._stats_update_timer.timeout.connect(self._flush_stats_updates)
                self._stats_update_timer.start(100)  # Обновляем не чаще чем раз в 100 мс
        except Exception as e:
            log_and_notify('error', f"Error in _update_stats: {e}")

    def _flush_stats_updates(self):
        """Применяет накопленные обновления статистики к UI"""
        try:
            # Проверяем наличие и инициализируем _pending_stats_updates
            if not hasattr(self, '_pending_stats_updates'):
                self._pending_stats_updates = {}
                
            # Проверяем наличие и инициализируем stats_labels
            if not hasattr(self, 'stats_labels') or self.stats_labels is None:
                self.stats_labels = {}
            
            # Применяем накопленные обновления к UI
            for key, value in self._pending_stats_updates.items():
                if key in self.stats_labels and self.stats_labels[key] is not None:
                    self.stats_labels[key].setText(str(value))
            
            # Очищаем накопленные обновления
            self._pending_stats_updates = {}
        except Exception as e:
            log_and_notify('error', f"Error in _flush_stats_updates: {e}")

    def update_forms_counters(self, forms_found: int = 0, forms_scanned: int = 0):
        """Принудительно обновляет счетчики форм"""
        if not hasattr(self, '_stats') or self._stats is None:
            self._stats = {
                'urls_found': 0,
                'urls_scanned': 0,
                'forms_found': 0,
                'forms_scanned': 0,
                'vulnerabilities': 0,
                'requests_sent': 0,
                'errors': 0,
            }

        if forms_found > self._stats['forms_found']:
            self._stats['forms_found'] = forms_found
            self._update_stats('forms_found', self._stats['forms_found'])
        if forms_scanned > self._stats['forms_scanned']:
            self._stats['forms_scanned'] = forms_scanned
            self._update_stats('forms_scanned', self._stats['forms_scanned'])

    def update_all_counters(self):
        """Принудительно обновляет все счетчики статистики из текущего состояния"""
        try:
            # Инициализация статистики, если она отсутствует
            if not hasattr(self, '_stats') or self._stats is None:
                self._stats = {
                    'urls_found': 0,
                    'urls_scanned': 0,
                    'forms_found': 0,
                    'forms_scanned': 0,
                    'vulnerabilities': 0,
                    'requests_sent': 0,
                    'errors': 0,
                }
            
            # Обновляем счетчик найденных URL из дерева
            total_urls_in_tree = 0
            if hasattr(self, 'site_tree') and self.site_tree is not None:
                for i in range(self.site_tree.topLevelItemCount()):
                    root_item = self.site_tree.topLevelItem(i)
                    if root_item is not None:
                        total_urls_in_tree += root_item.childCount()
            
            if total_urls_in_tree > self._stats['urls_found']:
                self._stats['urls_found'] = total_urls_in_tree
                self._update_stats('urls_found', self._stats['urls_found'])
            
            # Обновляем счетчик просканированных URL
            scanned_urls_count = len(getattr(self, '_scanned_urls', set()))
            if scanned_urls_count > self._stats['urls_scanned']:
                self._stats['urls_scanned'] = scanned_urls_count
                self._update_stats('urls_scanned', self._stats['urls_scanned'])
            
            # Обновляем счетчик найденных форм из дерева
            forms_in_tree = 0
            if hasattr(self, 'site_tree') and self.site_tree is not None:
                for i in range(self.site_tree.topLevelItemCount()):
                    root_item = self.site_tree.topLevelItem(i)
                    if root_item is not None:
                        for j in range(root_item.childCount()):
                            child = root_item.child(j)
                            if child is not None and child.text(1) == "Форма":
                                forms_in_tree += 1
            
            if forms_in_tree > self._stats['forms_found']:
                self._stats['forms_found'] = forms_in_tree
                self._update_stats('forms_found', self._stats['forms_found'])
            
            # Обновляем счетчик просканированных форм
            scanned_forms_count = len(getattr(self, '_scanned_forms', set()))
            if scanned_forms_count > self._stats['forms_scanned']:
                self._stats['forms_scanned'] = scanned_forms_count
                self._update_stats('forms_scanned', self._stats['forms_scanned'])
            
            # Обновляем счетчик ошибок из лога
            error_count = 0
            if hasattr(self, '_log_entries') and self._log_entries is not None:
                error_count = sum(1 for entry in self._log_entries if entry['level'] == 'ERROR')
            
            if error_count != self._stats['errors']:
                self._stats['errors'] = error_count
                self._update_stats('errors', self._stats['errors'])
            
            logger.debug(f"Counters updated: URLs found={self._stats['urls_found']}, "
                        f"URLs scanned={self._stats['urls_scanned']}, "
                        f"Forms found={self._stats['forms_found']}, "
                        f"Forms scanned={self._stats['forms_scanned']}, "
                        f"Errors={self._stats['errors']}")
                        
        except Exception as e:
            log_and_notify('error', f"Error updating all counters: {e}")

    def _update_scan_time(self):
        """Обновляет время сканирования через менеджер"""
        # Делегируем обновление времени сканирования менеджеру
        self.scan_manager._update_scan_time()

        # Проверяем, что сканирование активно и таймер существует
        if not hasattr(self, '_scan_timer') or self._scan_timer is None or not self._scan_timer.isActive():
                return
            
            # Проверяем, что статистика существует и имеет нужную структуру
        if not hasattr(self, '_stats') or self._stats is None:
            self._stats = {
                'urls_found': 0,
                'urls_scanned': 0,
                    'forms_found': 0,
                    'forms_scanned': 0,
                    'vulnerabilities': 0,
                    'requests_sent': 0,
                    'errors': 0,
                    'scan_start_time': datetime.now()
                }
            
            # Проверяем наличие времени начала сканирования
            if 'scan_start_time' not in self._stats or self._stats['scan_start_time'] is None:
                return
            
            # Вычисляем прошедшее время
            scan_start = self._stats['scan_start_time']
            if not isinstance(scan_start, datetime):
                return
                
            elapsed = datetime.now() - scan_start
            time_str = str(elapsed).split('.')[0]  # Убираем микросекунды
            
            # Обновляем отображение времени
            if hasattr(self, 'stats_labels') and 'scan_time' in self.stats_labels:
                self.stats_labels['scan_time'].setText(time_str)
            
            # Периодически обновляем все счетчики для синхронизации
            if not hasattr(self, '_timer_counter'):
                self._timer_counter = 0
            self._timer_counter += 1
            
            if self._timer_counter % 5 == 0:  # Каждые 5 секунд
                self.update_all_counters()


    def _on_vulnerability_found(self, url: str, vuln_type: str, details: str, target: str):
        """Обработчик обнаружения уязвимости"""
        try:
            # Проверяем и инициализируем статистику при необходимости
            if not hasattr(self, '_stats') or self._stats is None:
                self._stats = {
                    'urls_found': 0,
                    'urls_scanned': 0,
                    'forms_found': 0,
                    'forms_scanned': 0,
                    'vulnerabilities': 0,
                    'requests_sent': 0,
                    'errors': 0,
                }
            
            # Формируем сообщение
            message = f"Обнаружена уязвимость {vuln_type}"
            
            # Добавляем запись в лог
            self._add_log_entry("VULNERABILITY", message, url, details)
            
            # Обновляем статистику
            self._stats['vulnerabilities'] += 1
            self._update_stats('vulnerabilities', self._stats['vulnerabilities'])
            
            # Обновляем статус в дереве с проверкой на None
            if hasattr(self, 'site_tree') and self.site_tree is not None:
                self._update_url_status(url, "Уязвимость")
                
        except Exception as e:
            log_and_notify('error', f"Error in _on_vulnerability_found: {e}")

    def _update_url_status(self, url: str, status: str) -> None:
        """Обновляет статус URL в дереве"""
        # Проверяем инициализацию дерева сайта
        if not hasattr(self, 'site_tree') or self.site_tree is None:
            logger.error("Site tree is not initialized")
            return
            
        for i in range(self.site_tree.topLevelItemCount()):
            root_item = self.site_tree.topLevelItem(i)
            if root_item is None:
                continue
            for j in range(root_item.childCount()):
                child = root_item.child(j)
                if child is None:
                    continue
                if child.text(0) == url:
                    child.setText(2, status)
                    # Обновляем счетчик просканированных форм
                    if status == "Просканирован" and child.text(1) == "Форма":
                        # Инициализация множества при необходимости
                        if not hasattr(self, '_scanned_forms') or self._scanned_forms is None:
                            self._scanned_forms = set()
                        
                        if url not in self._scanned_forms:
                            self._scanned_forms.add(url)
                            
                            # Инициализация статистики при необходимости
                            if not hasattr(self, '_stats') or self._stats is None:
                                self._stats = {
                                    'urls_found': 0,
                                    'urls_scanned': 0,
                                    'forms_found': 0,
                                    'forms_scanned': 0,
                                    'vulnerabilities': 0,
                                    'requests_sent': 0,
                                    'errors': 0,
                                }
                                
                            self._stats['forms_scanned'] += 1
                            self._update_stats('forms_scanned', self._stats['forms_scanned'])
                    
                    # Устанавливаем цвет в зависимости от статуса
                    if status == "Уязвимость":
                        child.setBackground(2, QColor("#ffcccc"))
                    elif status == "Просканирован":
                        child.setBackground(2, QColor("#ccffcc"))
                    elif status == "Ошибка":
                        child.setBackground(2, QColor("#ffcc99"))
                    break


    async def _on_scan_result(self, result: Dict[str, Any]) -> None:
        """Обработка результата сканирования"""
        try:
            self._scan_result_signal.emit(result)
            # Останавливаем таймер
            if hasattr(self, '_scan_timer') and self._scan_timer is not None:
                self._scan_timer.stop()
            
            # Проверяем и инициализируем статистику при необходимости
            if not hasattr(self, '_stats') or self._stats is None:
                self._stats = {
                    'urls_found': 0,
                    'urls_scanned': 0,
                    'forms_found': 0,
                    'forms_scanned': 0,
                    'vulnerabilities': 0,
                    'requests_sent': 0,
                    'errors': 0,
                }
            
            # Обновляем интерфейс
            if self.scan_progress is not None:
                self.scan_progress.setValue(100)
            if hasattr(self, 'progress_label') and self.progress_label is not None:
                self.progress_label.setText("100%")
            if hasattr(self, 'scan_status') and self.scan_status is not None:
                self.scan_status.setText("Сканирование завершено")
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(True)
            if hasattr(self, 'pause_button') and self.pause_button is not None:
                self.pause_button.setEnabled(False)
            if hasattr(self, 'stop_button') and self.stop_button is not None:
                self.stop_button.setEnabled(False)
            
            # Сбрасываем состояние паузы
            self._is_paused = False
            self.pause_button.setText("⏸️ Пауза")
            
            # Извлекаем данные из результата
            scan_duration = result.get('scan_duration', 0)
            total_urls = result.get('total_urls_scanned', 0)
            total_vulnerabilities = result.get('total_vulnerabilities', 0)
            total_forms_scanned = result.get('total_forms_scanned', 0)
            
            # Добавляем финальную запись в лог
            self._add_log_entry("INFO", f"✅ Сканирование завершено за {scan_duration:.2f} секунд")
            self._add_log_entry("INFO", f"📊 Результаты: {total_urls} URL просканировано, {total_vulnerabilities} уязвимостей найдено")
            
            # Обновляем статистику в интерфейсе
            if 'urls_scanned' in self._stats:
                self._stats['urls_scanned'] = total_urls
            if 'vulnerabilities' in self._stats:
                self._stats['vulnerabilities'] = total_vulnerabilities
            if 'forms_scanned' in self._stats:
                self._stats['forms_scanned'] = total_forms_scanned
            
            # Обновляем отображение статистики
            self._update_stats('urls_scanned', total_urls)
            self._update_stats('vulnerabilities', total_vulnerabilities)
            self._update_stats('forms_scanned', total_forms_scanned)
            
            # Финальное обновление всех счетчиков для синхронизации
            self.update_all_counters()
            
            # Завершаем метрики производительности
            performance_monitor.end_timer("scan_session", performance_monitor.start_timer("scan_session"))
            
            # Сохраняем результат в базу данных с проверкой на None
            if self.scan_controller is not None:
                await self.scan_controller.save_scan_result(result)
            else:
                log_and_notify('error', "Scan controller is None when trying to save result")
            
            # Показываем результат пользователю
            if total_vulnerabilities > 0:
                # Если найдены уязвимости
                msg = (
                    f"Сканирование завершено!\n\n"
                    f"🔴 Найдено {total_vulnerabilities} уязвимостей!\n\n"
                    f"📊 Статистика:\n"
                    f"• Просканировано URL: {total_urls}\n"
                    f"• Просканировано форм: {total_forms_scanned}\n\n"
                    f"📋 Проверьте вкладку 'Отчёты' для подробной информации."
                )
            else:
                # Если уязвимостей не найдено
                msg = (
                    f"Сканирование завершено!\n\n"
                    f"🟢 Уязвимостей не найдено.\n\n"
                    f"📊 Статистика:\n"
                    f"• Просканировано URL: {total_urls}\n"
                    f"• Просканировано форм: {total_forms_scanned}"
                )
            
            # Добавляем информацию о покрытии сайта
            coverage_percent = result.get('coverage_percent', 100)
            unscanned_urls = result.get('unscanned_urls', [])
            msg += f"\n\n🌐 Покрытие сайта: {coverage_percent}%"
            
            if unscanned_urls:
                msg += f"\n\n⚠️ Не удалось просканировать следующие URL (ошибки/таймауты):\n"
                msg += '\n'.join(unscanned_urls[:10])  # Показываем только первые 10
                if len(unscanned_urls) > 10:
                    msg += f"\n... и еще {len(unscanned_urls) - 10} URL. См. отчет."
            else:
                msg += "\n✅ Все найденные страницы были просканированы."
            
            # Показываем одно уведомление с полной информацией
            error_handler.show_info_message("Сканирование завершено", msg)
            
            # Обновляем таблицу отчётов
            self.refresh_reports()
            
            # Обновляем статистику
            self.refresh_stats()
            
        except Exception as e:
            log_and_notify('error', f"Error in _on_scan_result: {e}")
            error_handler.handle_database_error(e, "_on_scan_result")


    def _on_scan_progress(self, progress: int, url: str) -> None:
        """Обработчик прогресса сканирования"""
        try:
            # Проверяем, что сканирование все еще активно
            if not hasattr(self, '_scan_timer') or self._scan_timer is None:
                self._scan_timer = QTimer()
                self._scan_timer.timeout.connect(self._update_scan_time)
                self._scan_timer.start(1000)

            if not self._scan_timer.isActive():
                return

            # Проверка инициализации дерева сайта
            if not hasattr(self, 'site_tree') or self.site_tree is None:
                self.site_tree = QTreeWidget()

            # Инициализация множеств при необходимости
            if not hasattr(self, '_scanned_urls') or self._scanned_urls is None:
                self._scanned_urls = set()
            if not hasattr(self, '_scanned_forms') or self._scanned_forms is None:
                self._scanned_forms = set()
            
            # Инициализируем статистику при необходимости
            if not hasattr(self, '_stats') or self._stats is None:
                self._stats = {
                    'urls_found': 0,
                    'urls_scanned': 0,
                    'forms_found': 0,
                    'forms_scanned': 0,
                    'vulnerabilities': 0,
                    'requests_sent': 0,
                    'errors': 0,
                }
            
            # Проверяем и обновляем прогресс-бар
            if hasattr(self, 'scan_progress_widget') and self.scan_progress_widget is not None:
                self.scan_progress_widget.setValue(progress)
            
            # Проверяем и обновляем метку прогресса
            if hasattr(self, 'progress_label') and self.progress_label is not None:
                self.progress_label.setText(f"{progress}%")
            
            # Добавляем URL в дерево если он новый
            if url:
                # Проверяем, есть ли уже такой URL в дереве
                existing_urls = []
                if hasattr(self, 'site_tree') and self.site_tree is not None:
                    for i in range(self.site_tree.topLevelItemCount()):
                        root_item = self.site_tree.topLevelItem(i)
                        if root_item is not None:
                            for j in range(root_item.childCount()):
                                child = root_item.child(j)
                                if child is not None:
                                    existing_urls.append(child.text(0))
                
                if url not in existing_urls:
                    # Проверяем, что метод _add_url_to_tree существует
                    if hasattr(self, '_add_url_to_tree') and callable(self._add_url_to_tree):
                        self._add_url_to_tree(url, "URL", "Сканируется")
                    # Увеличиваем счетчик найденных URL только для новых URL
                    if self._stats is not None:
                        self._stats['urls_found'] = self._stats.get('urls_found', 0) + 1
                        self._update_stats('urls_found', self._stats['urls_found'])
                
                # Обновляем статус URL в дереве
                if hasattr(self, '_update_url_status') and callable(self._update_url_status):
                    self._update_url_status(url, "Просканирован")
                
                # Обновляем счетчик просканированных URL только если это новый URL
                if url not in getattr(self, '_scanned_urls', set()):
                    if not hasattr(self, '_scanned_urls'):
                        self._scanned_urls = set()
                    self._scanned_urls.add(url)
                    if self._stats is not None:
                        self._stats['urls_scanned'] = self._stats.get('urls_scanned', 0) + 1
                        self._update_stats('urls_scanned', self._stats['urls_scanned'])
            
            # Добавляем запись о прогрессе
            if progress % 10 == 0:  # Логируем каждые 10%
                # Проверяем, что метод _add_log_entry существует
                if hasattr(self, '_add_log_entry') and callable(self._add_log_entry):
                    self._add_log_entry("PROGRESS", f"Прогресс: {progress}%", url)
            
        except Exception as e:
            log_and_notify('error', f"Error in _on_scan_progress: {e}")

    def _on_scan_progress_with_forms(self, progress: int, url: str, forms_found: int | None = None, forms_scanned: int | None = None):
        """Обработчик прогресса сканирования с информацией о формах"""
        try:
            # Проверяем, что сканирование все еще активно
            if (not hasattr(self, '_scan_timer') or 
                self._scan_timer is None or 
                not self._scan_timer.isActive()):
                return
            
            # Вызываем основной обработчик прогресса
            self._on_scan_progress(progress, url)
            
            # Обновляем счетчики форм если они переданы
            if forms_found is not None or forms_scanned is not None:
                # Передаем только не-None значения, используя значения по умолчанию для None
                found_count = forms_found if forms_found is not None else 0
                scanned_count = forms_scanned if forms_scanned is not None else 0
                self.update_forms_counters(found_count, scanned_count)
            
        except Exception as e:
            log_and_notify('error', f"Error in _on_scan_progress_with_forms: {e}")
            
    def load_avatar(self):
        """Загрузка аватара пользователя"""
        try:
            # Проверка инициализации компонентов
            if not hasattr(self, 'avatar_label') or self.avatar_label is None:
                logger.error("Avatar label not initialized")
                return
            
            if not hasattr(self, 'user_id'):
                logger.error("User ID not initialized")
                return
            
            # Получение пути к аватару из базы данных
            user_data = db.get_user_by_id(self.user_id)
            logger.info(f"User data from DB: {user_data}")
            if user_data:
                avatar_path = user_data.get('avatar_path', '')
                logger.info(f"Avatar path from DB: {avatar_path}")
                if avatar_path and os.path.exists(avatar_path):
                    logger.info(f"Avatar path exists: {avatar_path}")
                    pixmap = QPixmap(avatar_path)
                    if not pixmap.isNull():
                        if self.avatar_label is not None:
                            self.avatar_label.setPixmap(pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
                        else:
                            logger.error("Avatar label is None when trying to set avatar")
                    else:
                        logger.warning(f"Failed to load pixmap from path: {avatar_path}")
                        # Устанавливаем аватар по умолчанию
                        default_avatar_path = "default_avatar.png"
                        self._set_default_avatar()
                else:
                    logger.info(f"Avatar path not found or empty: {avatar_path}")
                    self._set_default_avatar()
        except Exception as e:
            logger.error(f"Error loading avatar: {e}")
            error_handler.show_error_message("Ошибка", f"Не удалось загрузить аватар: {e}")

    def _set_default_avatar(self):
        """Установка аватара по умолчанию"""
        default_avatar_path = "default_avatar.png"
        if os.path.exists(default_avatar_path):
            default_pixmap = QPixmap(default_avatar_path)
            if self.avatar_label:
                self.avatar_label.setPixmap(default_pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
                logger.info(f"Default avatar loaded")
            else:
                logger.error("Avatar label is None when trying to set default avatar")
        else:
            logger.warning("Default avatar file not found")

    def handle_scan(self):
        if not self.url_input or not self.scan_controller:
            return
        url = self.url_input.text()
        scan_types = []
        if self.sql_checkbox.isChecked():
            scan_types.append('SQL Injection')
        if self.xss_checkbox.isChecked():
            scan_types.append('XSS')
        if self.csrf_checkbox.isChecked():
            scan_types.append('CSRF')

        if url and scan_types and self.scan_controller is not None:
            asyncio.create_task(self.scan_controller.start_scan(url, scan_types))

    # ----------------------- Отчёты -----------------------

    def reset_filters(self):
        self.filter_input.clear()
        self.filter_sql_cb.setChecked(False)
        self.filter_xss_cb.setChecked(False)
        self.filter_csrf_cb.setChecked(False)
        self.date_from.setDateTime(QDateTime.currentDateTime().addDays(-30))
        self.date_to.setDateTime(QDateTime.currentDateTime())
        self.refresh_reports()

    def refresh_reports(self):
        try:
            scans = db.get_scans_by_user(self.user_id)
            if not scans:
                if self.reports_text is not None:
                    self.reports_text.setText("Нет данных для отображения.")
            url_filter = self.filter_input.text().strip().lower()
            selected_types = [
                t for cb, t in [
                    (self.filter_sql_cb, "SQL Injection"),
                    (self.filter_xss_cb, "XSS"),
                    (self.filter_csrf_cb, "CSRF"),
                ] if cb.isChecked()
            ]
            from_dt = self.date_from.dateTime().toPyDateTime()
            to_dt = self.date_to.dateTime().toPyDateTime()

            # Заполняем таблицу
            self.populate_scans_table(scans, url_filter, selected_types, from_dt, to_dt)

            # Обновляем текстовый отчет
            report_lines = ["=" * 80, "ОТЧЕТ О СКАНИРОВАНИИ УЯЗВИМОСТЕЙ", "=" * 80, f"Период: {from_dt} - {to_dt}",
                            f"Фильтр URL: {url_filter if url_filter else 'Все'}",
                            f"Типы уязвимостей: {', '.join(selected_types) if selected_types else 'Все'}", "=" * 80, ""]
            
            # Добавляем заголовок отчета

            filtered_scans = []
            total_vulnerabilities = 0
            high_risk_scans = 0
            
            # Статистика по типам уязвимостей
            vuln_type_stats = {
                'SQL Injection': 0,
                'XSS': 0,
                'CSRF': 0
            }

            for scan in scans:
                # Преобразуем дату сканирования
                scan_dt = datetime.strptime(scan["timestamp"], "%Y-%m-%d %H:%M:%S")

                # Фильтр по дате
                if not (from_dt <= scan_dt <= to_dt):
                    continue

                # Фильтр по URL
                if url_filter and url_filter not in scan["url"].lower():
                    continue

                # Фильтр по типу уязвимости
                scan_results = scan.get("result", scan.get("results", []))
                if isinstance(scan_results, str):
                    try:
                        scan_results = json.loads(scan_results)
                    except (json.JSONDecodeError, TypeError):
                        scan_results = []
                
                if selected_types:
                    has_selected_type = False
                    for result in scan_results:
                        if result.get("type") in selected_types:
                            has_selected_type = True
                            break
                    if not has_selected_type:
                        continue

                filtered_scans.append(scan)
                
                # Подсчитываем статистику для этого сканирования
                scan_vulnerabilities = 0
                scan_vuln_types = {
                    'SQL Injection': 0,
                    'XSS': 0,
                    'CSRF': 0
                }
                
                for result in scan_results:
                    if isinstance(result, dict):
                        # Проверяем vulnerabilities в новой структуре
                        if 'vulnerabilities' in result:
                            for vuln_cat, vulns in result['vulnerabilities'].items():
                                if isinstance(vulns, list) and vulns:
                                    scan_vulnerabilities += len(vulns)
                                    # Маппинг категорий к типам
                                    if vuln_cat == 'sql':
                                        scan_vuln_types['SQL Injection'] += len(vulns)
                                    elif vuln_cat == 'xss':
                                        scan_vuln_types['XSS'] += len(vulns)
                                    elif vuln_cat == 'csrf':
                                        scan_vuln_types['CSRF'] += len(vulns)
                        # Проверяем старую структуру
                        elif result.get('type') or result.get('vuln_type'):
                            vuln_type = result.get('type', result.get('vuln_type', ''))
                            if vuln_type in scan_vuln_types:
                                scan_vuln_types[vuln_type] += 1
                            scan_vulnerabilities += 1
                
                # Обновляем общую статистику
                total_vulnerabilities += scan_vulnerabilities
                for vuln_type, count in scan_vuln_types.items():
                    vuln_type_stats[vuln_type] += count
                
                if scan_vulnerabilities > 0:
                    high_risk_scans += 1

            # Добавляем общую статистику
            report_lines.append("📊 ОБЩАЯ СТАТИСТИКА")
            report_lines.append("-" * 40)
            report_lines.append(f"Всего сканирований: {len(filtered_scans)}")
            report_lines.append(f"Обнаружено уязвимостей: {total_vulnerabilities}")
            report_lines.append(f"Целей с высоким риском: {high_risk_scans}")
            report_lines.append(f"Средний риск: {'ВЫСОКИЙ' if high_risk_scans > len(filtered_scans) / 2 else 'СРЕДНИЙ' if high_risk_scans > 0 else 'НИЗКИЙ'}")
            report_lines.append("")
            
            # Добавляем статистику по типам уязвимостей
            report_lines.append("🎯 СТАТИСТИКА ПО ТИПАМ УЯЗВИМОСТЕЙ")
            report_lines.append("-" * 40)
            for vuln_type, count in vuln_type_stats.items():
                if count > 0:
                    percentage = (count / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0
                    report_lines.append(f"• {vuln_type}: {count} ({percentage:.1f}%)")
                else:
                    report_lines.append(f"• {vuln_type}: 0 (0.0%)")
            report_lines.append("")

            if not filtered_scans:
                report_lines.append("❌ Нет данных, соответствующих фильтрам.")
            else:
                # Группируем результаты по датам
                scans_by_date = {}
                for scan in filtered_scans:
                    scan_date = datetime.strptime(scan["timestamp"], "%Y-%m-%d %H:%M:%S").date()
                    if scan_date not in scans_by_date:
                        scans_by_date[scan_date] = []
                    scans_by_date[scan_date].append(scan)

                # Сортируем даты
                sorted_dates = sorted(scans_by_date.keys(), reverse=True)

                for date in sorted_dates:
                    report_lines.append(f"📅 ДАТА: {date.strftime('%d.%m.%Y')}")
                    report_lines.append("-" * 40)
                    
                    for scan in scans_by_date[date]:
                        scan_results = scan.get("result", scan.get("results", []))
                        if isinstance(scan_results, str):
                            try:
                                scan_results = json.loads(scan_results)
                            except (json.JSONDecodeError, TypeError):
                                scan_results = []
                        
                        # Подсчитываем статистику для этого сканирования
                        # Получаем количество отсканированных URL
                        total_urls_scanned = scan.get('total_urls_scanned', 0)
                        total_forms_scanned = scan.get('total_forms_scanned', 0)
                        total_checks = total_urls_scanned + total_forms_scanned
                        
                        # Если нет данных о URL, используем количество результатов как fallback
                        if total_checks == 0:
                            total_checks = len(scan_results)
                        
                        # Подсчитываем уязвимости по типам
                        scan_vuln_types = {
                            'SQL Injection': 0,
                            'XSS': 0,
                            'CSRF': 0
                        }
                        
                        for result in scan_results:
                            if isinstance(result, dict):
                                # Проверяем vulnerabilities в новой структуре
                                if 'vulnerabilities' in result:
                                    for vuln_cat, vulns in result['vulnerabilities'].items():
                                        if isinstance(vulns, list) and vulns:
                                            if vuln_cat == 'sql':
                                                scan_vuln_types['SQL Injection'] += len(vulns)
                                            elif vuln_cat == 'xss':
                                                scan_vuln_types['XSS'] += len(vulns)
                                            elif vuln_cat == 'csrf':
                                                scan_vuln_types['CSRF'] += len(vulns)
                                # Проверяем старую структуру
                                elif result.get('type') or result.get('vuln_type'):
                                    vuln_type = result.get('type', result.get('vuln_type', ''))
                                    if vuln_type in scan_vuln_types:
                                        scan_vuln_types[vuln_type] += 1
                        
                        vulnerable_count = sum(scan_vuln_types.values())
                        safe_count = total_checks - vulnerable_count
                        risk_level = "🔴 ВЫСОКИЙ" if vulnerable_count > 0 else "🟢 НИЗКИЙ"
                        
                        # Формируем отчет для этого сканирования
                        report_lines.append(f"🔍 Сканирование #{scan['id']}")
                        report_lines.append(f"   URL: {scan['url']}")
                        report_lines.append(f"   Тип: {scan['scan_type']}")
                        report_lines.append(f"   Время: {scan['timestamp']}")
                        report_lines.append(f"   Длительность: {self.format_duration(scan.get('scan_duration', 0))}")
                        report_lines.append(f"   Всего проверок: {total_checks}")
                        report_lines.append(f"   Уязвимостей: {vulnerable_count}")
                        report_lines.append(f"   Безопасных: {safe_count}")
                        report_lines.append(f"   Уровень риска: {risk_level}")
                        
                        # Детали по типам уязвимостей
                        if vulnerable_count > 0:
                            report_lines.append("   Детали по типам:")
                            for vuln_type, count in scan_vuln_types.items():
                                if count > 0:
                                    report_lines.append(f"     • {vuln_type}: {count}")
                        else:
                            report_lines.append("   Уязвимостей не обнаружено")
                        
                        report_lines.append("")

            report_lines.extend([
                "=" * 80,
                "✅ Отчет завершен",
                "=" * 80
                ])
            
            self.reports_text.setText("\n".join(report_lines))
        except sqlite3.Error as e:
            if hasattr(self, 'error_handler'):
                error_handler.handle_database_error(e, "refresh_reports")
            log_and_notify('error', f"Database error in refresh_reports: {e}")
        except Exception as e:
            log_and_notify('error', f"Error in refresh_reports: {e}")
            if hasattr(self, 'error_handler'):
                error_handler.handle_validation_error(e, "refresh_reports")

    def populate_scans_table(self, scans, url_filter, selected_types, from_dt, to_dt):
        """Заполняет таблицу сканирований с учетом фильтров"""
        try:
            if not hasattr(self, 'scans_table') or not self.scans_table is None:
                logger.error("Scans table is not initialized")
                return
            # Сохраняем отфильтрованные данные, но не загружаем все в таблицу сразу
            self._filtered_scans_data = []

            for scan in scans:
                scan_dt = datetime.strptime(scan["timestamp"], "%Y-%m-%d %H:%M:%S")
                if not (from_dt <= scan_dt <= to_dt):
                    continue
                if url_filter and url_filter not in scan["url"].lower():
                    continue
                scan_results = scan.get("result", scan.get("results", []))
                if isinstance(scan_results, str):
                    try:
                        scan_results = json.loads(scan_results)
                    except (json.JSONDecodeError, TypeError):
                        scan_results = []
                if selected_types:
                    has_selected_type = False
                    for result in scan_results:
                        if result.get("type") in selected_types:
                            has_selected_type = True
                            break
                    if not has_selected_type:
                        continue

                # Предварительно обрабатываем данные для отображения
                processed_scan = self._process_scan_for_display(scan)
                self._filtered_scans_data.append(processed_scan)
            
            # Устанавливаем общее количество строк
            self.scans_table.setRowCount(len(self._filtered_scans_data))

            # Создаем таймер для отложенной загрузки видимых строк
            self._visible_rows_timer = QTimer()
            self._visible_rows_timer.setSingleShot(True)
            self._visible_rows_timer.timeout.connect(self._load_visible_rows)
            self._visible_rows_timer.start(50)  # Задержка 50 мс перед загрузкой видимых строк

            # Подключаем обработчик прокрутки
            self.scans_table.verticalScrollBar().valueChanged.connect(self._on_table_scroll)

        except Exception as e:
            error_handler.handle_database_error(e, "populate_scans_table")

    def _load_visible_rows(self):
        """Загружает только видимые в данный момент строки таблицы"""
        try:
            # Проверяем наличие необходимых атрибутов
            if not hasattr(self, '_filtered_scans_data') or not self._filtered_scans_data:
                return
            if not hasattr(self, 'scans_table') or self.scans_table is None:
                return
                
            # Определяем видимый диапазон строк
            viewport = self.scans_table.viewport()
            scroll_bar = self.scans_table.verticalScrollBar()
            
            if viewport is None or scroll_bar is None:
                return
                
            row_height = self.scans_table.rowHeight(0) if self.scans_table.rowCount() > 0 else 25

            visible_start = scroll_bar.value() // row_height
            visible_end = visible_start + viewport.height() // row_height + 1

            # Добавляем небольшой запас строк для плавной прокрутки
            buffer = 10
            visible_start = max(0, visible_start - buffer)
            visible_end = min(len(self._filtered_scans_data) - 1, visible_end + buffer)

            # Загружаем только видимые строки
            for row in range(visible_start, visible_end + 1):
                if row < len(self._filtered_scans_data):
                    scan_data = self._filtered_scans_data[row]

                    # Проверяем, не загружена ли уже эта строка
                    item = self.scans_table.item(row, 0)
                    if item is None or item.text() == "":
                        # Загружаем данные для строки
                        self._load_scan_row(row, scan_data)
            
        except Exception as e:
            log_and_notify('error', f"Error loading visible rows: {e}")


    def _on_table_scroll(self):
        """Обработчик события прокрутки таблицы"""
        try:
            # Проверяем инициализацию таймера
            if not hasattr(self, '_visible_rows_timer') or self._visible_rows_timer is None:
                self._visible_rows_timer = QTimer()
                self._visible_rows_timer.setSingleShot(True)
                self._visible_rows_timer.timeout.connect(self._load_visible_rows)
            
            # Перезапускаем таймер загрузки видимых строк
            if self._visible_rows_timer.isActive():
                self._visible_rows_timer.stop()
            
            self._visible_rows_timer.start(50)  # Задержка 50 мс перед загрузкой видимых строк
            
        except Exception as e:
            log_and_notify('error', f"Error in _on_table_scroll: {e}")


    def _process_scan_for_display(self, scan):
        """Предварительно обрабатывает данные сканирования для отображения"""
        scan_results = scan.get("result", scan.get("results", []))
        if isinstance(scan_results, str):
            try:
                scan_results = json.loads(scan_results)
            except (json.JSONDecodeError, TypeError):
                scan_results = []
        
        # Подсчитываем уязвимости по типам
        vulnerability_counts = {
            'SQL Injection': 0,
            'XSS': 0,
            'CSRF': 0
        }
        
        for result in scan_results:
            vuln_type = result.get('type', '')
            if vuln_type in vulnerability_counts:
                vulnerability_counts[vuln_type] += 1

        # Формируем строку с детальной информацией об уязвимостях
        vuln_details = []
        total_vulns = 0
        for vuln_type, count in vulnerability_counts.items():
            if count > 0:
                vuln_details.append(f"{vuln_type}: {count}")
                total_vulns += count

        if vuln_details:
            vuln_text = " | ".join(vuln_details)
        else:
            vuln_text = "Нет уязвимостей"

        # Возвращаем отфильтрованные данные
        return {
            'id': str(scan['id']),
            'url': scan['url'],
            'timestamp': scan['timestamp'],
            'scan_type': scan['scan_type'],
            'status': scan['status'],
            'duration': self.format_duration(scan.get('scan_duration', 0)),
            'vuln_text': vuln_text,
            'total_vulns': total_vulns,
            'vuln_details': vulnerability_counts
        }
    
    def _load_scan_row(self, row: int, scan_data: Dict[str, Any]) -> None:
        """Загружает данные в указанную строку таблицы"""
        self.scans_table.setItem(row, 0, QTableWidgetItem(scan_data['id']))
        self.scans_table.setItem(row, 1, QTableWidgetItem(scan_data['url']))
        self.scans_table.setItem(row, 2, QTableWidgetItem(scan_data['timestamp']))
        self.scans_table.setItem(row, 3, QTableWidgetItem(scan_data['scan_type']))
        self.scans_table.setItem(row, 4, QTableWidgetItem(scan_data['status']))
        self.scans_table.setItem(row, 5, QTableWidgetItem(scan_data['duration']))
        
        # Создаем элемент с детальной информацией об уязвимостях
        vuln_item = QTableWidgetItem(scan_data['vuln_text'])
        self.scans_table.setItem(row, 6, vuln_item)
        
        # Устанавливаем цвет фона в зависимости от наличия уязвимостей
        if scan_data['total_vulns'] > 0:
            vuln_item.setBackground(QColor("red"))
            vuln_item.setForeground(QColor("white"))
        else:
            vuln_item.setBackground(QColor("green"))
            vuln_item.setForeground(QColor("black"))
        
        # Устанавливаем подсказку с дополнительной информацией
        if scan_data['total_vulns'] > 0:
            tooltip_text = f"Всего уязвимостей: {scan_data['total_vulns']}\n"
            for vuln_type, count in scan_data['vuln_details'].items():
                if count > 0:
                    tooltip_text += f"• {vuln_type}: {count}\n"
            vuln_item.setToolTip(tooltip_text.strip())
        else:
            vuln_item.setToolTip("Уязвимостей не обнаружено")

    def on_scan_selected(self):
        """Обработчик выбора сканирования в таблице"""
        current_row = self.scans_table.currentRow()
        logger.info(f"Scan selected: row={current_row}, has_filtered_scans={hasattr(self, 'filtered_scans')}, filtered_count={len(self.filtered_scans) if hasattr(self, 'filtered_scans') else 0}")

    def get_selected_scan(self):
        """Получает выбранное сканирование"""
        current_row = self.scans_table.currentRow()
        if 0 <= current_row < len(self.filtered_scans) and hasattr(self, 'filtered_scans'):
            selected_scan = self.filtered_scans[current_row]
            logger.info(f"Selected scan: ID={selected_scan.get('id')}, URL={selected_scan.get('url')}")
            return selected_scan
        logger.warning("No scan selected or invalid selection")
        return None

    def export_selected_scan_json(self):
        """Экспорт выбранного сканирования в JSON"""
        scan = self.get_selected_scan()
        if not scan:
            error_handler.show_error_message("Нет выбора", "Пожалуйста, выберите хотя бы один отчет из таблицы.")
            return
        
        # Валидация имени файла
        default_filename = f"scan_{scan['id']}_{get_local_timestamp().replace(':', '').replace(' ', '_')}.json"
        safe_filename = sanitize_filename(default_filename)
        
        path, _ = QFileDialog.getSaveFileName(
            self, 
            "Сохранить отчет", 
            safe_filename,
            "JSON Files (*.json)"
        )
        if path:
            try:
                from export.export import export_single_scan_to_json
                if export_single_scan_to_json(scan, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл JSON успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл JSON.")
            except Exception as e:
                error_handler.handle_file_error(e, "export_selected_scan_json")

    def export_selected_scan_csv(self):
        """Экспорт выбранного сканирования в CSV"""
        scan = self.get_selected_scan()
        if not scan:
            error_handler.show_error_message("Нет выбора", "Пожалуйста, выберите хотя бы один отчет из таблицы.")
            return
        
        default_filename = f"scan_{scan['id']}_{get_local_timestamp().replace(':', '').replace(' ', '_')}.csv"
        safe_filename = sanitize_filename(default_filename)
        
        path, _ = QFileDialog.getSaveFileName(
            self, 
            "Сохранить отчет", 
            safe_filename,
            "CSV Files (*.csv)"
        )
        if path:
            try:
                from export.export import export_single_scan_to_csv
                if export_single_scan_to_csv(scan, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл CSV успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл CSV.")
            except Exception as e:
                error_handler.handle_file_error(e, "export_selected_scan_csv")

    def export_selected_scan_pdf(self):
        """Экспорт выбранного сканирования в PDF"""
        scan = self.get_selected_scan()
        if not scan:
            error_handler.show_error_message("Нет выбора", "Пожалуйста, выберите хотя бы один отчет из таблицы.")
            return
        
        default_filename = f"scan_{scan['id']}_{get_local_timestamp().replace(':', '').replace(' ', '_')}.pdf"
        safe_filename = sanitize_filename(default_filename)
        
        path, _ = QFileDialog.getSaveFileName(
            self, 
            "Сохранить отчет", 
            safe_filename,
            "PDF Files (*.pdf)"
        )
        if path:
            try:
                from export.export import export_single_scan_to_pdf
                if export_single_scan_to_pdf(scan, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл PDF успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл PDF.")
            except Exception as e:
                error_handler.handle_file_error(e, "export_selected_scan_pdf")

    def export_selected_scan_html(self):
        """Экспорт выбранного сканирования в HTML"""
        scan = self.get_selected_scan()
        if not scan:
            error_handler.show_error_message("Нет выбора", "Пожалуйста, выберите хотя бы один отчет из таблицы.")
            return
        
        default_filename = f"scan_{scan['id']}_{get_local_timestamp().replace(':', '').replace(' ', '_')}.html"
        safe_filename = sanitize_filename(default_filename)
        
        path, _ = QFileDialog.getSaveFileName(
            self, 
            "Сохранить отчет", 
            safe_filename,
            "HTML Files (*.html)"
        )
        if path:
            try:
                from export.export import export_single_scan_to_html
                if export_single_scan_to_html(scan, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл HTML успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл HTML.")
            except Exception as e:
                error_handler.handle_file_error(e, "export_selected_scan_html")

    def export_selected_scan_txt(self):
        """Экспорт выбранного сканирования в TXT"""
        scan = self.get_selected_scan()
        if not scan:
            error_handler.show_error_message("Нет выбора", "Пожалуйста, выберите хотя бы один отчет из таблицы.")
            return
        
        default_filename = f"scan_{scan['id']}_{get_local_timestamp().replace(':', '').replace(' ', '_')}.txt"
        safe_filename = sanitize_filename(default_filename)
        
        path, _ = QFileDialog.getSaveFileName(
            self, 
            "Сохранить отчет", 
            safe_filename,
            "TXT Files (*.txt)"
        )
        if path:
            try:
                from export.export import export_single_scan_to_txt
                if export_single_scan_to_txt(scan, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл TXT успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл TXT.")
            except Exception as e:
                error_handler.handle_file_error(e, "export_selected_scan_txt")

    def generate_detailed_report(self):
        try:
            scans = db.get_scans_by_user(self.user_id)
            if not scans:
                QMessageBox.warning(self, "Нет данных", "Нет данных для создания отчета")
                return
            
            # Создаем расширенный диалог настройки отчета
            dialog = QDialog(self)
            dialog.setWindowTitle("Создать детальный отчет")
            dialog.setModal(True)
            dialog.setMinimumWidth(500)
            
            layout = QVBoxLayout()
            
            # === СЕКЦИЯ 1: Основные настройки ===
            main_group = QGroupBox("Основные настройки")
            main_layout = QVBoxLayout()
            
            # Выбор формата
            format_layout = QHBoxLayout()
            format_layout.addWidget(QLabel("Формат отчета:"))
            format_combo = QComboBox()
            format_combo.addItems(["JSON", "CSV", "TXT", "HTML", "PDF"])
            format_layout.addWidget(format_combo)
            main_layout.addLayout(format_layout)
            
            # Период отчета
            period_layout = QHBoxLayout()
            period_layout.addWidget(QLabel("Период отчета:"))
            period_combo = QComboBox()
            period_combo.addItems(["Все время", "Последние 7 дней", "Последние 30 дней", "Последние 90 дней", "Произвольный период"])
            period_combo.currentTextChanged.connect(lambda: self._on_period_changed(period_combo, custom_period_widget))
            period_layout.addWidget(period_combo)
            main_layout.addLayout(period_layout)
            
            # Произвольный период
            custom_period_widget = QWidget()
            custom_period_layout = QHBoxLayout()
            custom_period_layout.addWidget(QLabel("С:"))
            date_from = QDateTimeEdit()
            date_from.setDateTime(QDateTime.currentDateTime().addDays(-30))
            date_from.setCalendarPopup(True)
            date_from.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
            custom_period_layout.addWidget(date_from)
            
            # Кнопки быстрого выбора времени для "С"
            from_time_buttons = QHBoxLayout()
            from_time_buttons.addWidget(QLabel("Быстро:"))
            from_start_day_btn = QPushButton("00:00")
            from_start_day_btn.clicked.connect(lambda: self._set_time_to_start_of_day(date_from))
            from_time_buttons.addWidget(from_start_day_btn)
            from_midnight_btn = QPushButton("00:00")
            from_midnight_btn.clicked.connect(lambda: self._set_time_to_midnight(date_from))
            from_time_buttons.addWidget(from_midnight_btn)
            custom_period_layout.addLayout(from_time_buttons)
            
            custom_period_layout.addWidget(QLabel("По:"))
            date_to = QDateTimeEdit()
            date_to.setDateTime(QDateTime.currentDateTime())
            date_to.setCalendarPopup(True)
            date_to.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
            custom_period_layout.addWidget(date_to)
            
            # Кнопки быстрого выбора времени для "По"
            to_time_buttons = QHBoxLayout()
            to_time_buttons.addWidget(QLabel("Быстро:"))
            to_end_day_btn = QPushButton("23:59")
            to_end_day_btn.clicked.connect(lambda: self._set_time_to_end_of_day(date_to))
            to_time_buttons.addWidget(to_end_day_btn)
            to_now_btn = QPushButton("Сейчас")
            to_now_btn.clicked.connect(lambda: self._set_time_to_now(date_to))
            to_time_buttons.addWidget(to_now_btn)
            custom_period_layout.addLayout(to_time_buttons)
            
            custom_period_widget.setLayout(custom_period_layout)
            custom_period_widget.setVisible(False)
            main_layout.addWidget(custom_period_widget)
            
            main_group.setLayout(main_layout)
            layout.addWidget(main_group)
            
            # === СЕКЦИЯ 2: Фильтры уязвимостей ===
            filter_group = QGroupBox("Фильтры уязвимостей")
            filter_layout = QVBoxLayout()
            
            # Типы уязвимостей
            vuln_types_layout = QHBoxLayout()
            vuln_types_layout.addWidget(QLabel("Типы уязвимостей:"))
            sql_cb = QCheckBox("SQL Injection")
            sql_cb.setChecked(True)
            xss_cb = QCheckBox("XSS")
            xss_cb.setChecked(True)
            csrf_cb = QCheckBox("CSRF")
            csrf_cb.setChecked(True)
            vuln_types_layout.addWidget(sql_cb)
            vuln_types_layout.addWidget(xss_cb)
            vuln_types_layout.addWidget(csrf_cb)
            filter_layout.addLayout(vuln_types_layout)
            
            # Уровни риска
            risk_layout = QHBoxLayout()
            risk_layout.addWidget(QLabel("Уровни риска:"))
            high_cb = QCheckBox("Высокий")
            high_cb.setChecked(True)
            medium_cb = QCheckBox("Средний")
            medium_cb.setChecked(True)
            low_cb = QCheckBox("Низкий")
            low_cb.setChecked(True)
            risk_layout.addWidget(high_cb)
            risk_layout.addWidget(medium_cb)
            risk_layout.addWidget(low_cb)
            filter_layout.addLayout(risk_layout)
            
            # Фильтр по URL
            url_layout = QHBoxLayout()
            url_layout.addWidget(QLabel("Фильтр URL:"))
            url_filter = QLineEdit()
            url_filter.setPlaceholderText("Оставьте пустым для всех URL")
            url_layout.addWidget(url_filter)
            filter_layout.addLayout(url_layout)
            
            filter_group.setLayout(filter_layout)
            layout.addWidget(filter_group)
            
            # === СЕКЦИЯ 3: Содержание отчета ===
            content_group = QGroupBox("Содержание отчета")
            content_layout = QVBoxLayout()
            
            # Разделы отчета
            sections = [
                ("executive_summary", "Краткое резюме", True),
                ("statistics", "Статистика", True),
                ("vulnerability_details", "Детали уязвимостей", True),
                ("scan_settings", "Настройки сканирования", False),
                ("performance_metrics", "Метрики производительности", False),
                ("recommendations", "Рекомендации", True),
                ("technical_details", "Технические детали", False),
                ("payloads_used", "Использованные пэйлоады", False)
            ]
            
            section_checkboxes = {}
            for section_id, section_name, default_checked in sections:
                cb = QCheckBox(section_name)
                cb.setChecked(default_checked)
                section_checkboxes[section_id] = cb
                content_layout.addWidget(cb)
            
            content_group.setLayout(content_layout)
            layout.addWidget(content_group)
            
            # === СЕКЦИЯ 4: Дополнительные опции ===
            options_group = QGroupBox("Дополнительные опции")
            options_layout = QVBoxLayout()
            
            # Включить графики (для HTML/PDF)
            include_charts = QCheckBox("Включить графики и диаграммы")
            include_charts.setChecked(True)
            options_layout.addWidget(include_charts)
            
            # Включить цветовое кодирование
            include_colors = QCheckBox("Включить цветовое кодирование")
            include_colors.setChecked(True)
            options_layout.addWidget(include_colors)
            
            # Сортировка результатов
            sort_layout = QHBoxLayout()
            sort_layout.addWidget(QLabel("Сортировка:"))
            sort_combo = QComboBox()
            sort_combo.addItems(["По дате (новые первыми)", "По дате (старые первыми)", "По количеству уязвимостей", "По уровню риска", "По URL"])
            sort_layout.addWidget(sort_combo)
            options_layout.addLayout(sort_layout)
            
            options_group.setLayout(options_layout)
            layout.addWidget(options_group)
            
            # Кнопки
            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            button_box.accepted.connect(dialog.accept)
            button_box.rejected.connect(dialog.reject)
            layout.addWidget(button_box)
            
            dialog.setLayout(layout)
            
            if dialog.exec_() == QDialog.Accepted:
                # Собираем настройки
                selected_format = format_combo.currentText().lower()
                period = period_combo.currentText()
                
                # Определяем период
                if period == "Все время":
                    from_date = None
                    to_date = None
                elif period == "Последние 7 дней":
                    from_date = QDateTime.currentDateTime().addDays(-7).toPyDateTime()
                    to_date = QDateTime.currentDateTime().toPyDateTime()
                elif period == "Последние 30 дней":
                    from_date = QDateTime.currentDateTime().addDays(-30).toPyDateTime()
                    to_date = QDateTime.currentDateTime().toPyDateTime()
                elif period == "Последние 90 дней":
                    from_date = QDateTime.currentDateTime().addDays(-90).toPyDateTime()
                    to_date = QDateTime.currentDateTime().toPyDateTime()
                else:  # Произвольный период
                    from_date = date_from.dateTime().toPyDateTime()
                    to_date = date_to.dateTime().toPyDateTime()
                
                # Фильтры уязвимостей
                selected_vuln_types = []
                if sql_cb.isChecked(): selected_vuln_types.append("SQL Injection")
                if xss_cb.isChecked(): selected_vuln_types.append("XSS")
                if csrf_cb.isChecked(): selected_vuln_types.append("CSRF")
                
                selected_risk_levels = []
                if high_cb.isChecked(): selected_risk_levels.append("HIGH")
                if medium_cb.isChecked(): selected_risk_levels.append("MEDIUM")
                if low_cb.isChecked(): selected_risk_levels.append("LOW")
                
                url_filter_text = url_filter.text().strip()
                
                # Содержание отчета
                report_sections = {section_id: cb.isChecked() for section_id, cb in section_checkboxes.items()}
                
                # Дополнительные опции
                include_charts_flag = include_charts.isChecked()
                include_colors_flag = include_colors.isChecked()
                sort_option = sort_combo.currentText()
                
                # Фильтруем данные согласно настройкам
                filtered_scans = self._filter_scans_for_report(
                    scans, from_date, to_date, selected_vuln_types, 
                    selected_risk_levels, url_filter_text
                )
                
                if not filtered_scans:
                    QMessageBox.warning(self, "Нет данных", "Нет данных, соответствующих выбранным фильтрам")
                    return
                
                # Определяем расширение файла
                extensions = {
                    'json': 'JSON Files (*.json)',
                    'csv': 'CSV Files (*.csv)',
                    'txt': 'TXT Files (*.txt)',
                    'html': 'HTML Files (*.html)',
                    'pdf': 'PDF Files (*.pdf)'
                }
                
                # Генерируем имя файла с информацией о фильтрах
                filename_parts = ["detailed_security_report"]
                if from_date and to_date:
                    filename_parts.append(f"{from_date.strftime('%Y%m%d')}-{to_date.strftime('%Y%m%d')}")
                if selected_vuln_types:
                    filename_parts.append("-".join(selected_vuln_types).replace(" ", ""))
                filename_parts.append(get_local_timestamp().replace(':', '').replace(' ', '_'))
                
                default_filename = "_".join(filename_parts) + f".{selected_format}"
                
                path, _ = QFileDialog.getSaveFileName(
                    self, 
                    "Сохранить детальный отчет", 
                    default_filename,
                    extensions.get(selected_format, "All Files (*.*)")
                )
                
                if path:
                    # Создаем расширенный отчет с настройками
                    success = self._generate_enhanced_report(
                        filtered_scans, selected_format, path, report_sections,
                        include_charts_flag, include_colors_flag, sort_option
                    )
                    
                    if success:
                        QMessageBox.information(
                            self, 
                            "Отчет создан", 
                            f"Детальный отчет успешно создан в формате {selected_format.upper()}\n"
                            f"Обработано сканирований: {len(filtered_scans)}"
                        )
                    else:
                        QMessageBox.critical(
                            self, 
                            "Ошибка", 
                            f"Не удалось создать отчет в формате {selected_format.upper()}"
                        )
        except (ValueError, sqlite3.Error, KeyError, AttributeError) as e:
            log_and_notify('error', f"Error in generate_detailed_report: {e}")
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка при создании отчета: {str(e)}")

    @staticmethod
    def _on_period_changed(period_combo, custom_period_widget):
        """Обработчик изменения периода"""
        custom_period_widget.setVisible(period_combo.currentText() == "Произвольный период")

    @staticmethod
    def _filter_scans_for_report(scans, from_date, to_date, vuln_types, risk_levels, url_filter):
        """Фильтрует сканирования согласно настройкам отчета"""
        filtered_scans = []
        
        for scan in scans:
            # Фильтр по дате
            scan_date = datetime.strptime(scan['timestamp'], "%Y-%m-%d %H:%M:%S")
            if from_date and scan_date < from_date:
                continue
            if to_date and scan_date > to_date:
                continue
            
            # Фильтр по URL
            if url_filter and url_filter.lower() not in scan['url'].lower():
                continue
            
            # Фильтр по типам уязвимостей и уровням риска
            scan_has_selected_vulns = False
            try:
                results = json.loads(scan['result']) if isinstance(scan['result'], str) else scan['result']
                
                for result in results:
                    if isinstance(result, dict):
                        vuln_type = result.get('type') or result.get('vuln_type')
                        severity = result.get('severity', 'MEDIUM')
                        
                        # Проверяем тип уязвимости
                        if vuln_types and vuln_type not in vuln_types:
                            continue
                        
                        # Проверяем уровень риска
                        if risk_levels and severity not in risk_levels:
                            continue
                        
                        scan_has_selected_vulns = True
                        break
                
                # Если нет выбранных типов уязвимостей, включаем все сканирования
                if not vuln_types:
                    scan_has_selected_vulns = True
                
                if scan_has_selected_vulns:
                    filtered_scans.append(scan)
                    
            except (json.JSONDecodeError, TypeError):
                # Если не можем распарсить результаты, включаем сканирование
                filtered_scans.append(scan)
        
        return filtered_scans

    @staticmethod
    def _generate_enhanced_report(scans, format_type, filename, sections, include_charts, include_colors, sort_option):
        """Генерирует расширенный отчет с дополнительными настройками"""
        try:
            # Сортируем сканирования
            if sort_option == "По дате (новые первыми)":
                scans.sort(key=lambda x: x['timestamp'], reverse=True)
            elif sort_option == "По дате (старые первыми)":
                scans.sort(key=lambda x: x['timestamp'])
            elif sort_option == "По количеству уязвимостей":
                scans.sort(key=lambda x: len(json.loads(x['result']) if isinstance(x['result'], str) else x['result']), reverse=True)
            elif sort_option == "По URL":
                scans.sort(key=lambda x: x['url'])
            
            # Добавляем метаданные отчета
            report_metadata = {
                'report_info': {
                    'generated_at': datetime.now().isoformat(),
                    'total_scans': len(scans),
                    'report_version': '3.0',
                    'sections_included': sections,
                    'options': {
                        'include_charts': include_charts,
                        'include_colors': include_colors,
                        'sort_option': sort_option
                    }
                }
            }
            
            # Используем существующую функцию экспорта с дополнительными данными
            from export.export import generate_detailed_report
            return generate_detailed_report(scans, format_type, filename)
            
        except Exception as e:
            log_and_notify('error', f"Error generating enhanced report: {e}")
            return False

    # ----------------------- Статистика -----------------------

    def refresh_stats(self) -> None:
        try:
            scans = db.get_scans_by_user(self.user_id)
            if not scans:
                if MATPLOTLIB_AVAILABLE and FigureCanvas is not None and self.stats_canvas is not None:
                    self.stats_canvas.figure.clear()
                    ax = self.stats_canvas.figure.add_subplot(111)
                    ax.text(0.5, 0.5, "Нет данных для отображения", 
                        horizontalalignment='center', verticalalignment='center')
                    self.stats_canvas.draw()
                else:
                    if hasattr(self, 'stats_text') and self.stats_text is not None:
                        self.stats_text.setText("Нет данных для отображения")
                    else:
                        logger.error("stats_text is not initialized")
                return

            if MATPLOTLIB_AVAILABLE and FigureCanvas is not None:
                self._refresh_stats_with_matplotlib(scans)
            else:
                self._refresh_stats_text_only(scans)
        except Exception as e:
            logger.error(f"Error in refresh_stats: {e}")

    def _refresh_stats_with_matplotlib(self, scans: List[Dict[str, Any]]):
        """Обновление статистики с использованием matplotlib с оптимизацией"""
        try:
            if not scans:
                logger.warning("No scan data available")
                return
            
            # Проверяем, нужно ли вообще обновлять график
            if hasattr(self, '_last_stats_update') and hasattr(self, '_last_stats_count'):
                current_time = time.time()
                # Если прошло меньше 5 секунд и количество сканирований не изменилось, пропускаем обновление
                if current_time - self._last_stats_update < 5 and len(scans) == self._last_stats_count:
                    return
            
            self._last_stats_update = time.time()
            self._last_stats_count = len(scans)

            # Проверяем доступность matplotlib
            if not MATPLOTLIB_AVAILABLE or FigureCanvas is None:
                logger.warning("Matplotlib not available, cannot display statistics graph")
                return
            
            # Проверяем и инициализируем stats_canvas при необходимости
            if not hasattr(self, 'stats_canvas') or self.stats_canvas is None:
                from matplotlib.figure import Figure
                self.stats_canvas = FigureCanvas(Figure())
                # Добавляем canvas в layout, если он еще не добавлен
                if hasattr(self, 'stats_layout') and self.stats_layout is not None:
                    self.stats_layout.addWidget(self.stats_canvas)

            # Используем существующий FigureCanvas
            self.stats_canvas.figure.clear()
            ax = self.stats_canvas.figure.add_subplot(111)
            
            # Подготовка данных с оптимизацией
            dates = []
            vulnerability_counts = {"SQL Injection": 0, "XSS": 0, "CSRF": 0}
            date_vulnerability_counts = {}

            for scan in scans:
                date = datetime.strptime(scan['timestamp'], "%Y-%m-%d %H:%M:%S").date()
                dates.append(date)

                scan_result = scan.get('result', {})
                if not scan_result:
                    continue
                
                # Парсим результаты сканирования с обработкой ошибок
                try:
                    results = json.loads(scan_result) if isinstance(scan_result, str) else scan_result
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse scan result: {e}")
                    continue
                
                # Оптимизированная обработка результатов
                if isinstance(results, list):
                    for result in results:
                        if not isinstance(result, dict):
                            continue
                            
                        vuln_type = result.get('type') or result.get('vuln_type')
                        
                        # Проверяем vulnerabilities в новой структуре
                        if not vuln_type and 'vulnerabilities' in result:
                            for vuln_cat, vulns in result['vulnerabilities'].items():
                                if isinstance(vulns, list) and vulns:
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
                            if date not in date_vulnerability_counts:
                                date_vulnerability_counts[date] = {"SQL Injection": 0, "XSS": 0, "CSRF": 0}

                            if vuln_type in date_vulnerability_counts[date]:
                                date_vulnerability_counts[date][vuln_type] += 1
                elif isinstance(results, dict) and 'vulnerabilities' in results:
                    # Оптимизированная обработка словаря с vulnerabilities
                    for vuln_cat, vulns in results['vulnerabilities'].items():
                        if isinstance(vulns, list) and vulns:
                            vuln_type = None
                            if vuln_cat == 'sql':
                                vuln_type = 'SQL Injection'
                            elif vuln_cat == 'xss':
                                vuln_type = 'XSS'
                            elif vuln_cat == 'csrf':
                                vuln_type = 'CSRF'
                            
                            if vuln_type and vuln_type in vulnerability_counts:
                                vulnerability_counts[vuln_type] += len(vulns)
                                
                                # Обновляем счетчики по датам
                                if date not in date_vulnerability_counts:
                                    date_vulnerability_counts[date] = {"SQL Injection": 0, "XSS": 0, "CSRF": 0}
                                date_vulnerability_counts[date][vuln_type] += len(vulns)

            # Сортируем даты
            sorted_dates = sorted(set(dates))
            
            # Очищаем график перед построением нового
            ax.clear()
            
            # Линейный график по датам с оптимизацией
            for vuln_type in vulnerability_counts.keys():
                counts = [date_vulnerability_counts.get(date, {}).get(vuln_type, 0) for date in sorted_dates]
                ax.plot(sorted_dates, counts, marker='o', linestyle='-', label=vuln_type)

            ax.set_title("Статистика сканирований по типам уязвимостей")
            ax.set_xlabel("Дата")
            ax.set_ylabel("Количество обнаружений")
            ax.grid(True)
            ax.legend()

            # Оптимизированное обновление холста
            self.stats_canvas.figure.tight_layout()
            self.stats_canvas.draw_idle()  # Используем draw_idle вместо draw для оптимизации
            
        except (ValueError, sqlite3.Error, KeyError, AttributeError) as e:
            log_and_notify('error', f"Error updating matplotlib stats: {e}")
            if self.stats_canvas is not None:
                self.stats_canvas.figure.clear()
                ax = self.stats_canvas.figure.add_subplot(111)
                ax.text(0.5, 0.5, f"Ошибка отображения статистики: {str(e)}", 
                    horizontalalignment='center', verticalalignment='center')
                self.stats_canvas.draw_idle()


    def _refresh_stats_text_only(self, scans):
        """Обновление статистики в текстовом виде (без matplotlib)"""
        if not scans:
            if hasattr(self, 'stats_text') and self.stats_text is not None:
                self.stats_text.setText("Нет данных для отображения")
            else:
                logger.error("stats_text is not initialized")
            return

        stats_lines = ["=" * 60, "СТАТИСТИКА СКАНИРОВАНИЙ", "=" * 60, ""]

        # Общая статистика
        total_scans = len(scans)
        total_vulnerabilities = 0
        high_risk_scans = 0
        scan_dates = []
        total_scan_time = 0.0
        avg_scan_time = 0.0
        
        # Анализ по типам уязвимостей
        vuln_by_type = {"SQL Injection": 0, "XSS": 0, "CSRF": 0}
        vuln_by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for scan in scans:
            results = json.loads(scan['result']) if isinstance(scan['result'], str) else scan['result']
            
            # Подсчитываем уязвимости из новой структуры данных
            scan_vulnerabilities = 0
            for result in results:
                if isinstance(result, dict):
                    # Проверяем vulnerabilities в новой структуре
                    if 'vulnerabilities' in result:
                        for vuln_cat, vulns in result['vulnerabilities'].items():
                            if isinstance(vulns, list) and vulns:
                                scan_vulnerabilities += len(vulns)
                                # Обновляем счетчики по типам уязвимостей
                                if vuln_cat == 'sql':
                                    vuln_by_type['SQL Injection'] += len(vulns)
                                elif vuln_cat == 'xss':
                                    vuln_by_type['XSS'] += len(vulns)
                                elif vuln_cat == 'csrf':
                                    vuln_by_type['CSRF'] += len(vulns)
                    # Проверяем старую структуру
                    elif result.get('type') or result.get('vuln_type'):
                        vuln_type = result.get('type', result.get('vuln_type', ''))
                        if vuln_type in vuln_by_type:
                            vuln_by_type[vuln_type] += 1
                        scan_vulnerabilities += 1
            
            total_vulnerabilities += scan_vulnerabilities
            
            if scan_vulnerabilities > 0:
                high_risk_scans += 1
            
            # Собираем даты и время сканирования
            if scan.get('timestamp'):
                try:
                    scan_date = datetime.strptime(scan['timestamp'], "%Y-%m-%d %H:%M:%S")
                    scan_dates.append(scan_date)
                except ValueError as e:
                    logger.warning(f"Invalid scan date format: {scan.get('timestamp', 'N/A')} - {e}")
                    continue
            
            # Собираем время сканирования
            if scan.get('scan_duration'):
                total_scan_time += scan['scan_duration']
            
            # Анализируем по типам
            for result in results:
                if isinstance(result, dict):
                    if 'vulnerabilities' in result:
                        # Новая структура
                        for vuln_cat, vulns in result['vulnerabilities'].items():
                            if isinstance(vulns, list) and vulns:
                                if vuln_cat == 'sql':
                                    vuln_by_severity["HIGH"] += len(vulns)
                                elif vuln_cat == 'xss':
                                    vuln_by_severity["HIGH"] += len(vulns)
                                elif vuln_cat == 'csrf':
                                    vuln_by_severity["HIGH"] += len(vulns)
                    else:
                        # Старая структура
                        vuln_type = result.get('type', 'Unknown')
                        if vuln_type in vuln_by_type:
                            if 'SQL Injection' in vuln_type or 'XSS' in vuln_type:
                                vuln_by_severity["HIGH"] += 1
                        elif 'CSRF' in vuln_type:
                            vuln_by_severity["MEDIUM"] += 1
                        else:
                            vuln_by_severity["LOW"] += 1

        # Вычисляем среднее время сканирования
        scans_with_duration = sum(1 for scan in scans if scan.get('scan_duration'))
        if scans_with_duration > 0:
            avg_scan_time = total_scan_time / scans_with_duration

        # Определяем период сканирования
        if scan_dates:
            earliest_date = min(scan_dates)
            latest_date = max(scan_dates)
            scan_period = f"{earliest_date.strftime('%d.%m.%Y')} - {latest_date.strftime('%d.%m.%Y')}"
        else:
            scan_period = "N/A"

        # Общий уровень риска
        if high_risk_scans == 0:
            overall_risk = "НИЗКИЙ"
        elif high_risk_scans <= total_scans * 0.3:
            overall_risk = "СРЕДНИЙ"
        else:
            overall_risk = "ВЫСОКИЙ"

        # Выводим общую статистику
        stats_lines.append("📊 ОБЩАЯ СТАТИСТИКА")
        stats_lines.append("-" * 40)
        stats_lines.append(f"Всего сканирований: {total_scans}")
        stats_lines.append(f"Обнаружено уязвимостей: {total_vulnerabilities}")
        stats_lines.append(f"Целей с высоким риском: {high_risk_scans}")
        stats_lines.append(f"Общий уровень риска: {overall_risk}")
        stats_lines.append(f"Период сканирования: {scan_period}")
        if scans_with_duration > 0:
            stats_lines.append(f"Общее время сканирования: {self.format_duration(total_scan_time)}")
            stats_lines.append(f"Среднее время сканирования: {self.format_duration(avg_scan_time)}")
        stats_lines.append("")

        # Статистика по типам уязвимостей
        stats_lines.append("🔍 АНАЛИЗ ПО ТИПАМ УЯЗВИМОСТЕЙ")
        stats_lines.append("-" * 40)
        for vuln_type, count in vuln_by_type.items():
            percentage = (count / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0
            stats_lines.append(f"{vuln_type}: {count} ({percentage:.1f}%)")
        stats_lines.append("")

        # Статистика по серьезности
        stats_lines.append("⚠️ АНАЛИЗ ПО СЕРЬЕЗНОСТИ")
        stats_lines.append("-" * 40)
        for severity, count in vuln_by_severity.items():
            percentage = (count / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0
            stats_lines.append(f"{severity}: {count} ({percentage:.1f}%)")
        stats_lines.append("")

        # Топ-5 наиболее сканируемых целей
        target_counts = {}
        for scan in scans:
            url = scan.get('url', 'Unknown')
            target_counts[url] = target_counts.get(url, 0) + 1
        
        if target_counts:
            stats_lines.append("🎯 ТОП-5 СКАНИРУЕМЫХ ЦЕЛЕЙ")
            stats_lines.append("-" * 40)
            sorted_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            for i, (url, count) in enumerate(sorted_targets, 1):
                stats_lines.append(f"{i}. {url}: {count} сканирований")
            stats_lines.append("")

        # Рекомендации
        stats_lines.append("💡 РЕКОМЕНДАЦИИ")
        stats_lines.append("-" * 40)
        if overall_risk == "ВЫСОКИЙ":
            stats_lines.append("🔴 КРИТИЧЕСКИЕ РЕКОМЕНДАЦИИ:")
            stats_lines.append("• Немедленно исправить все обнаруженные уязвимости")
            stats_lines.append("• Провести полный аудит безопасности")
            stats_lines.append("• Обновить все компоненты системы")
            stats_lines.append("• Настроить WAF и системы мониторинга")
        elif overall_risk == "СРЕДНИЙ":
            stats_lines.append("🟡 РЕКОМЕНДАЦИИ:")
            stats_lines.append("• Исправить критические уязвимости в приоритетном порядке")
            stats_lines.append("• Провести дополнительное тестирование безопасности")
            stats_lines.append("• Улучшить процессы разработки с учетом безопасности")
        else:
            stats_lines.append("🟢 РЕКОМЕНДАЦИИ:")
            stats_lines.append("• Продолжить регулярные проверки безопасности")
            stats_lines.append("• Следить за обновлениями компонентов")
            stats_lines.append("• Поддерживать текущий уровень безопасности")

        stats_lines.append("")
        stats_lines.append("=" * 60)

        self.stats_text.setText("\n".join(stats_lines))

    # ----------------------- Профиль -----------------------

    def refresh_activity_log(self) -> None:
        try:
            if not hasattr(self, 'activity_log') or self.activity_log is None:
                return
            scans = db.get_scans_by_user(self.user_id)
            if not scans:
                self.activity_log.setText("История активности пуста.")
                return

            log_text = ""
            for scan in scans:
                log_text += f"[{scan['timestamp']}] URL: {scan['url']}\n"
            self.activity_log.setText(log_text)
        except sqlite3.Error as e:
            logger.error(f"Database error in refresh_activity_log: {e}")

    def edit_profile(self):
        self.edit_window = EditProfileWindow(self.user_id, self.username, self)
        self.edit_window.show()

    def change_avatar(self):
        """Изменение аватара пользователя"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Выберите аватар", "", "Image Files (*.png *.jpg *.jpeg *.bmp)"
            )
            if file_path:
                # Создаем директорию для аватаров, если она не существует
                avatar_dir = os.path.join("data", "avatars", str(self.user_id))
                os.makedirs(avatar_dir, exist_ok=True)
                
                # Генерируем уникальное имя файла
                import uuid
                file_ext = os.path.splitext(file_path)[1]
                avatar_name = f"avatar_{uuid.uuid4().hex}{file_ext}"
                avatar_path = os.path.join(avatar_dir, avatar_name)
                
                # Копируем файл
                import shutil
                shutil.copy2(file_path, avatar_path)
                
                # Обновляем базу данных
                with db.get_db_connection_cm() as conn:
                    conn.execute(
                        "UPDATE users SET avatar_path = ? WHERE id = ?",
                        (avatar_path, self.user_id)
                    )
                
                # Обновляем интерфейс
                self.load_avatar()
                
                log_and_notify('info', "Avatar updated successfully")
                logger.info(f"Avatar updated for user {self.username}: {avatar_path}")
        except Exception as e:
            error_handler.handle_file_error(e, "change_avatar")
            log_and_notify('error', f"Error changing avatar: {e}")

    def logout(self):
        logger.info(f"User '{self.username}' has logged out of the account")
        
        # Останавливаем сканирование без показа уведомлений
        self._stop_scan_silent()
        
        # Сначала скрываем текущее окно
        self.hide()
        
        # Затем переключаемся на окно авторизации через родительское окно
        parent_widget = self.parent()
        if parent_widget is not None:
            try:
                # Пытаемся вызвать go_to_login если метод существует
                go_to_login_method = getattr(parent_widget, 'go_to_login', None)
                if go_to_login_method is not None and callable(go_to_login_method):
                    go_to_login_method()
                else:
                    # Если нет метода go_to_login, просто закрываем приложение
                    close_method = getattr(parent_widget, 'close', None)
                    if close_method is not None and callable(close_method):
                        close_method()
            except Exception as logout_error:
                log_and_notify('error', f"Error in logout: {logout_error}")
                # В случае ошибки закрываем текущее окно
                self.close()
        else:
            # Если нет родительского окна, закрываем текущее окно
            self.close()

    def _stop_scan_silent(self):
        """Останавливает текущее сканирование без показа уведомлений (для logout)."""
        try:
            # Инициализируем все необходимые атрибуты
            if not hasattr(self, '_scan_timer'):
                self._scan_timer = None
                
            if not hasattr(self, 'scan_controller'):
                self.scan_controller = None
                
            if not hasattr(self, '_is_paused'):
                self._is_paused = False
                
            if not hasattr(self, 'scan_status'):
                self.scan_status = None
                
            if not hasattr(self, 'scan_progress'):
                self.scan_progress = None
                
            if not hasattr(self, 'progress_label'):
                self.progress_label = None
                
            # Останавливаем таймер если он существует
            if self._scan_timer is not None:
                self._scan_timer.stop()
                
            # Останавливаем сканирование если контроллер существует
            if self.scan_controller is not None:
                self.scan_controller.stop_scan()
                
            # Сбрасываем состояние интерфейса с проверкой на None
            if self.scan_status is not None:
                self.scan_status.setText("Сканирование остановлено")
                
            if self.scan_progress is not None:
                self.scan_progress.setValue(0)
                
            if self.progress_label is not None:
                self.progress_label.setText("0%")
                
            # Включаем кнопку "Начать сканирование" и отключаем остальные
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(True)
                
            if hasattr(self, 'pause_button') and self.pause_button is not None:
                self.pause_button.setEnabled(False)
                
            if hasattr(self, 'stop_button') and self.stop_button is not None:
                self.stop_button.setEnabled(False)
                
            # Сбрасываем состояние паузы
            self._is_paused = False
            if hasattr(self, 'pause_button') and self.pause_button is not None:
                self.pause_button.setText("⏸️ Пауза")
                
            # Сбрасываем счетчики прогресса
            self._scan_start_time = None
            self._total_urls = 0
            self._completed_urls = 0
            self._total_progress = 0
            self._active_workers = 0
            self._worker_progress = {}
                
            logger.info("Scan stopped silently during logout")
                
        except Exception as e:
            log_and_notify('error', f"Error stopping scan silently: {e}")
            
            # В случае ошибки все равно сбрасываем интерфейс
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(True)
                
            if hasattr(self, 'pause_button') and self.pause_button is not None:
                self.pause_button.setEnabled(False)
                
            if hasattr(self, 'stop_button') and self.stop_button is not None:
                self.stop_button.setEnabled(False)
                
            if hasattr(self, 'scan_status') and self.scan_status is not None:
                self.scan_status.setText("Ошибка остановки сканирования")



    def pause_scan(self):
        """Приостанавливает или возобновляет сканирование."""
        try:
            if not self._is_paused:
                # Приостанавливаем сканирование
                self._is_paused = True
                if hasattr(self, 'pause_button') and self.pause_button is not None:
                    self.pause_button.setText("▶️ Продолжить")
                if hasattr(self, 'scan_status') and self.scan_status is not None:
                    self.scan_status.setText("Сканирование приостановлено")
                
                # Останавливаем таймер обновления времени
                if hasattr(self, '_scan_timer') and self._scan_timer is not None:
                    self._scan_timer.stop()
                
                # Приостанавливаем сканирование в контроллере
                if self.scan_controller is not None:
                    self.scan_controller.pause_scan()
                
                # Добавляем запись в лог
                self._add_log_entry("WARNING", "⏸️ Сканирование приостановлено пользователем")
                
                logger.info("Scan paused by user")
                
            else:
                # Возобновляем сканирование
                self._is_paused = False
                if hasattr(self, 'pause_button') and self.pause_button is not None:
                    self.pause_button.setText("⏸️ Пауза")
                if hasattr(self, 'scan_status') and self.scan_status is not None:
                    self.scan_status.setText("Сканирование...")
                
                # Возобновляем таймер обновления времени
                if hasattr(self, '_scan_timer') and self._scan_timer is not None:
                    self._scan_timer.start(1000)
                
                # Возобновляем сканирование в контроллере
                if self.scan_controller is not None:
                    self.scan_controller.resume_scan()
                
                # Добавляем запись в лог
                self._add_log_entry("INFO", "▶️ Сканирование возобновлено")
                
                logger.info("Scan resumed by user")
                
        except Exception as e:
            log_and_notify('error', f"Error pausing/resuming scan: {e}")
            self._add_log_entry("ERROR", f"Ошибка при управлении паузой: {str(e)}")
            
            # В случае ошибки возвращаем кнопку в исходное состояние
            if self._is_paused:
                self._is_paused = False
                self.pause_button.setText("⏸️ Пауза")
            else:
                self._is_paused = True
                self.pause_button.setText("▶️ Продолжить")

    def closeEvent(self, a0):
        """Обработчик закрытия окна: останавливает сканирование перед выходом."""
        if hasattr(self, '_scan_timer') and self._scan_timer is not None:
            self._scan_timer.stop()

        if hasattr(self, 'scan_button') and self.scan_button is not None:
            self.scan_button.setEnabled(False)

        if hasattr(self, 'pause_button') and self.pause_button is not None:
            self.pause_button.setEnabled(False)

        if hasattr(self, 'stop_button') and self.stop_button is not None:
            self.stop_button.setEnabled(False)
        super().closeEvent(a0)
        self.stop_scan()
        if a0 is not None:
            a0.accept()

    def clear_reports_text(self):
        reply = QMessageBox.question(
            self, "Подтверждение", "Вы уверены, что хотите удалить все отчёты?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                db.delete_scans_by_user(self.user_id)
                logger.warning(f"User '{self.username}' deleted all reports")
                self.reports_text.clear()
                self.scans_table.setRowCount(0)
                self.refresh_stats()  # Обновляем статистику после очистки
                error_handler.show_info_message("Удалено", "Все отчёты успешно удалены.")
            except Exception as e:
                error_handler.handle_database_error(e, "clear_reports_text")

    def export_to_json(self):
        try:
            scans = db.get_scans_by_user(self.user_id)
            if not scans:
                error_handler.show_warning_message("Нет данных", "Нет данных для экспорта")
                return
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить отчет", f"security_report_{get_local_timestamp().replace(':', '').replace(' ', '_')}.json",
                "JSON Files (*.json)"
            )
            if path:
                from export.export import export_to_json as export_json
                if export_json(scans, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл JSON успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл JSON.")
        except Exception as e:
            error_handler.handle_file_error(e, "export_to_json")

    def export_to_csv(self):
        try:
            scans = db.get_scans_by_user(self.user_id)
            if not scans:
                error_handler.show_warning_message("Нет данных", "Нет данных для экспорта")
                return
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить отчет", f"security_report_{get_local_timestamp().replace(':', '').replace(' ', '_')}.csv",
                "CSV Files (*.csv)"
            )
            if path:
                from export.export import export_to_csv as export_csv
                if export_csv(scans, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл CSV успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл CSV.")
        except Exception as e:
            error_handler.handle_file_error(e, "export_to_csv")

    def export_to_pdf(self):
        try:
            scans = db.get_scans_by_user(self.user_id)
            if not scans:
                error_handler.show_warning_message("Нет данных", "Нет данных для экспорта")
                return
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить отчет", f"security_report_{get_local_timestamp().replace(':', '').replace(' ', '_')}.pdf",
                "PDF Files (*.pdf)"
            )
            if path:
                from export.export import export_to_pdf as export_pdf
                if export_pdf(scans, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл PDF успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл PDF.")
        except Exception as e:
            error_handler.handle_file_error(e, "export_to_pdf")

    def export_to_html(self):
        try:
            scans = db.get_scans_by_user(self.user_id)
            if not scans:
                error_handler.show_warning_message("Нет данных", "Нет данных для экспорта")
                return
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить отчет", f"security_report_{get_local_timestamp().replace(':', '').replace(' ', '_')}.html",
                "HTML Files (*.html)"
            )
            if path:
                from export.export import export_to_html as export_html
                if export_html(scans, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл HTML успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл HTML.")
        except Exception as e:
            error_handler.handle_file_error(e, "export_to_html")

    def export_to_txt(self):
        try:
            scans = db.get_scans_by_user(self.user_id)
            if not scans:
                error_handler.show_warning_message("Нет данных", "Нет данных для экспорта")
                return
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить отчет", f"security_report_{get_local_timestamp().replace(':', '').replace(' ', '_')}.txt",
                "TXT Files (*.txt)"
            )
            if path:
                from export.export import export_to_txt as export_txt
                if export_txt(scans, path, self.user_id):
                    error_handler.show_info_message("Экспорт завершён", "Файл TXT успешно сохранён.")
                else:
                    error_handler.show_error_message("Ошибка экспорта", "Не удалось сохранить файл TXT.")
        except Exception as e:
            error_handler.handle_file_error(e, "export_to_txt")

    def clear_scan_log(self):
        """Очищает лог сканирования"""
        try:
            # Проверяем и инициализируем атрибуты при необходимости
            if not hasattr(self, '_log_entries'):
                self._log_entries = []
            if not hasattr(self, '_filtered_log_entries'):
                self._filtered_log_entries = []

            # Очищаем списки записей
            if hasattr(self, '_log_entries') and self._log_entries is not None:
                self._log_entries.clear()
            
            if hasattr(self, '_filtered_log_entries') and self._filtered_log_entries is not None:
                self._filtered_log_entries.clear()
            
            # Проверяем и очищаем detailed_log с проверкой на None
            if hasattr(self, 'detailed_log') and self.detailed_log is not None:
                self.detailed_log.clear()
                
            # Проверяем и очищаем site_tree с проверкой на None
            if hasattr(self, 'site_tree') and self.site_tree is not None:
                self.site_tree.clear()
            
            # Проверяем и сбрасываем статистику с проверкой на None
            if hasattr(self, 'stats_labels') and self.stats_labels is not None:
                for key in self.stats_labels:
                    if self.stats_labels[key] is not None:
                        self.stats_labels[key].setText("0")
                        
        except Exception as e:
            log_and_notify('error', f"Error clearing scan log: {e}")


    def export_scan_log(self):
        """Экспортирует лог сканирования"""
        try:
            # Проверяем наличие атрибута и инициализируем при необходимости
            if not hasattr(self, '_log_entries') or self._log_entries is None:
                self._log_entries = []
                
            filename, _ = QFileDialog.getSaveFileName(
                self, "Сохранить лог сканирования", 
                f"scan_log_{get_local_timestamp().replace(':', '').replace(' ', '_')}.txt",
                "Text Files (*.txt);;HTML Files (*.html);;All Files (*)"
            )
            
            if not filename:  # Проверяем, что имя файла не пустое
                return
                
            if filename.endswith('.html'):
                # Экспорт в HTML
                html_content = "<html><head><title>Лог сканирования</title></head><body>"
                html_content += "<h1>Лог сканирования</h1>"
                html_content += f"<p>Дата: {get_local_timestamp()}</p>"
                html_content += "<hr>"
                
                for entry in self._log_entries:
                    if entry and 'html' in entry:  # Проверяем валидность записи
                        html_content += entry['html']
                
                html_content += "</body></html>"
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            else:
                # Экспорт в текстовый формат
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Лог сканирования - {get_local_timestamp()}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for entry in self._log_entries:
                        if entry:  # Проверяем валидность записи
                            f.write(f"[{entry.get('timestamp', '')}] {entry.get('level', '')}: {entry.get('message', '')}\n")
                            if entry.get('url'):
                                f.write(f"  URL: {entry['url']}\n")
                            if entry.get('details'):
                                f.write(f"  Детали: {entry['details']}\n")
                            f.write("\n")
            
            error_handler.show_info_message("Экспорт", f"Лог успешно экспортирован в файл:\n{filename}")
            
        except Exception as e:
            error_handler.handle_file_error(e, "export_scan_log")
            log_and_notify('error', f"Error exporting scan log: {e}")

    def _add_url_to_tree(self, url: str, url_type: str = "URL", status: str = "Найден"):
        """Добавляет URL в древовидное представление"""
        # Проверяем инициализацию дерева сайта
        if not hasattr(self, 'site_tree') or self.site_tree is None:
            logger.error("Site tree is not initialized")
            return
        
        # Проверяем и инициализируем статистику при необходимости
        if not hasattr(self, '_stats') or self._stats is None:
            self._stats = {
                'urls_found': 0,
                'urls_scanned': 0,
                'forms_found': 0,
                'forms_scanned': 0,
                'vulnerabilities': 0,
                'requests_sent': 0,
                'errors': 0,
            }

        # Создаем корневой элемент для домена
        domain = url.split('/')[2] if len(url.split('/')) > 2 else url
        
        # Ищем существующий корневой элемент
        root_item = None
        for i in range(self.site_tree.topLevelItemCount()):
            item = self.site_tree.topLevelItem(i)
            if item is not None and item.text(0) == domain:
                root_item = item
                break
        
        if not root_item:
            root_item = QTreeWidgetItem(self.site_tree)
            root_item.setText(0, domain)
            root_item.setText(1, "Домен")
            root_item.setText(2, "Активен")
            root_item.setExpanded(True)
        
        # Добавляем URL как дочерний элемент
        url_item = QTreeWidgetItem(root_item)
        url_item.setText(0, url)
        url_item.setText(1, url_type)
        url_item.setText(2, status)
        
        # Устанавливаем иконки в зависимости от типа
        if url_type == "Форма":
            url_item.setIcon(0, QIcon("📝"))
            # Обновляем счетчик найденных форм
            self._stats['forms_found'] += 1
            self._update_stats('forms_found', self._stats['forms_found'])
        elif url_type == "API":
            url_item.setIcon(0, QIcon("🔌"))
        else:
            url_item.setIcon(0, QIcon("🌐"))

    def _on_scan_log(self, message: str):
        """Добавляет сообщение в лог сканирования с правильным определением уровня"""
        try:
            # Определяем message_lower в начале метода
            message_lower = message.lower()
            
            # Определяем уровень сообщения
            level = "INFO"  # По умолчанию
            
            # Проверяем, есть ли в сообщении указание уровня в формате "LEVEL - message"
            if " - " in message:
                parts = message.split(" - ", 1)
                if len(parts) == 2:
                    potential_level = parts[0].strip().upper()
                    # Проверяем, является ли первая часть валидным уровнем
                    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "VULNERABILITY", "REQUEST", "RESPONSE", "PROGRESS", "SKIP_FILE", "ADD_LINK"]
                    if potential_level in valid_levels:
                        level = potential_level
                        message = parts[1].strip()  # Берем только текст сообщения
            
            # Если уровень не найден в начале, определяем по ключевым словам
            if level == "INFO":
                # Определяем уровень по ключевым словам в сообщении
                if any(keyword in message_lower for keyword in [
                    "add_link", "add link", "добавлен url", "добавлена ссылка"
                ]):
                    level = "ADD_LINK"
                elif any(keyword in message_lower for keyword in [
                    "skip_file", "skip file", "файл пропущен", "пропущен файл"
                ]):
                    level = "SKIP_FILE"
                elif any(keyword in message_lower for keyword in [
                    "debug", "отладка", "debugging", "debug info"
                ]):
                    level = "DEBUG"
                elif any(keyword in message_lower for keyword in [
                    "error", "ошибка", "failed", "неудачно", "exception", "исключение"
                ]):
                    level = "ERROR"
                elif any(keyword in message_lower for keyword in [
                    "warning", "предупреждение", "внимание", "caution"
                ]):
                    level = "WARNING"
                elif any(keyword in message_lower for keyword in [
                    "vulnerability", "уязвимость", "vuln", "found", "найдено"
                ]):
                    level = "VULNERABILITY"
                elif any(keyword in message_lower for keyword in [
                    "request", "запрос", "making request", "отправлен запрос"
                ]):
                    level = "REQUEST"
                elif any(keyword in message_lower for keyword in [
                    "response", "ответ", "received", "получен ответ"
                ]):
                    level = "RESPONSE"
                elif any(keyword in message_lower for keyword in [
                    "progress", "прогресс", "completed", "завершено", "scanned", "просканировано"
                ]):
                    level = "PROGRESS"
            
            # Добавляем сообщение с правильным уровнем
            self._add_log_entry(level, message)
            
            # Проверяем, что сканирование все еще активно
            if not hasattr(self, '_scan_timer') or self._scan_timer is None or not self._scan_timer.isActive():
                return
            
            # Обновляем счетчик запросов
            if any(keyword in message.lower() for keyword in [
                "запрос", "request", "get request", "post request", 
                "making request", "отправлен запрос", "получен ответ"
            ]):
                if hasattr(self, '_stats') and self._stats is not None:
                    self._stats['requests_sent'] = self._stats.get('requests_sent', 0) + 1
                    self._update_stats('requests_sent', self._stats['requests_sent'])
            
            # Обновляем счетчики форм из сообщений сканера
            if "forms:" in message_lower or "формы:" in message_lower:
                # Извлекаем информацию о формах из сообщения
                if "found" in message_lower or "найдено" in message_lower:
                    # Ищем числа в сообщении
                    import re
                    numbers = re.findall(r'\d+', message)
                    if numbers:
                        forms_found = int(numbers[0])
                        if hasattr(self, '_stats') and self._stats is not None:
                            if forms_found > self._stats['forms_found']:
                                self._stats['forms_found'] = forms_found
                                self._update_stats('forms_found', self._stats['forms_found'])
                
                # Обновляем счетчик просканированных форм
                if "scanned" in message_lower or "просканировано" in message_lower:
                    import re
                    numbers = re.findall(r'\d+', message)
                    if len(numbers) >= 2:
                        forms_scanned = int(numbers[1])  # Второе число обычно просканированные формы
                        if hasattr(self, '_stats') and self._stats is not None:
                            if forms_scanned > self._stats['forms_scanned']:
                                self._stats['forms_scanned'] = forms_scanned
                                self._update_stats('forms_scanned', self._stats['forms_scanned'])
            
            # Обновляем счетчики из прогресс-сообщений
            if "progress:" in message_lower or "прогресс:" in message_lower:
                # Извлекаем информацию о формах из прогресс-сообщений
                if "forms:" in message_lower:
                    import re
                    forms_match = re.search(r'forms:\s*(\d+)/(\d+)', message_lower)
                    if forms_match:
                        forms_scanned = int(forms_match.group(1))
                        forms_total = int(forms_match.group(2))
                        
                        # Обновляем счетчики форм
                        if hasattr(self, '_stats') and self._stats is not None:
                            if forms_total > self._stats['forms_found']:
                                self._stats['forms_found'] = forms_total
                                self._update_stats('forms_found', self._stats['forms_found'])
                            
                            if forms_scanned > self._stats['forms_scanned']:
                                self._stats['forms_scanned'] = forms_scanned
                                self._update_stats('forms_scanned', self._stats['forms_scanned'])
            
            # Обновляем счетчики URL из сообщений
            if "url" in message_lower and any(keyword in message_lower for keyword in [
                "found", "найден", "discovered", "обнаружен"
            ]):
                if hasattr(self, '_stats') and self._stats is not None:
                    # Увеличиваем счетчик найденных URL
                    self._stats['urls_found'] = self._stats.get('urls_found', 0) + 1
                    self._update_stats('urls_found', self._stats['urls_found'])
            
            # Обновляем счетчики из сообщений о завершении сканирования URL
            if "scanned" in message_lower and "url" in message_lower:
                if hasattr(self, '_stats') and self._stats is not None:
                    # Увеличиваем счетчик просканированных URL
                    self._stats['urls_scanned'] = self._stats.get('urls_scanned', 0) + 1
                    self._update_stats('urls_scanned', self._stats['urls_scanned'])
                    
        except Exception as e:
            logger.error(f"Error processing scan log: {e}")
            if hasattr(self, '_add_log_entry'):
                self._add_log_entry("ERROR", f"Ошибка обработки лога сканирования: {e}")


    # Методы для работы с временем в отчетах
    @staticmethod
    def _set_time_to_start_of_day(datetime_edit):
        """Устанавливает время на начало дня (00:00:00)"""
        current_datetime = datetime_edit.dateTime()
        new_datetime = QDateTime(current_datetime.date(), QTime(0, 0, 0))
        datetime_edit.setDateTime(new_datetime)

    def _set_time_to_midnight(self, datetime_edit):
        """Устанавливает время на полночь (00:00:00)"""
        self._set_time_to_start_of_day(datetime_edit)

    @staticmethod
    def _set_time_to_end_of_day(datetime_edit):
        """Устанавливает время на конец дня (23:59:59)"""
        current_datetime = datetime_edit.dateTime()
        new_datetime = QDateTime(current_datetime.date(), QTime(23, 59, 59))
        datetime_edit.setDateTime(new_datetime)

    @staticmethod
    def _set_time_to_now(datetime_edit):
        """Устанавливает время на текущий момент"""
        datetime_edit.setDateTime(QDateTime.currentDateTime())

    def load_scanner_log_to_ui(self, full: bool = False):
        """
        Загружает scanner.log в детальный лог UI с оптимизацией.
        По умолчанию загружает только последние 500 строк.
        """
        try:
            # Проверяем, что все необходимые атрибуты инициализированы
            if not hasattr(self, 'detailed_log') or not hasattr(self, '_log_entries') or not hasattr(self, 'log_status_label'):
                log_and_notify('error', "Required UI components not initialized")
                return
                
            log_path = os.path.join("logs", "scanner.log")
            if not os.path.exists(log_path):
                self._on_scan_log("Файл scanner.log не найден.")
                if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                    self.log_status_label.setText("Файл лога отсутствует.")
                return

            # Используем отложенную загрузку для больших файлов
            if full:
                if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                    self.log_status_label.setText("Идет загрузка полного лога...")
                QApplication.processEvents()
                
                # Запускаем загрузку в отдельном потоке для больших файлов
                self._log_loader_thread = threading.Thread(target=self._load_full_log, args=(log_path,))
                self._log_loader_thread.daemon = True
                self._log_loader_thread.start()
            else:
                # Для частичной загрузки используем оптимизированный метод
                if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                    self.log_status_label.setText("Загрузка последних строк...")
                QApplication.processEvents()
                
                log_content = self._read_log_tail(log_path, lines=500)
                self._process_log_content(log_content, 500)
                
        except Exception as e:
            log_and_notify('error', f"Failed to load scanner.log: {e}")
            if hasattr(self, '_on_scan_log'):
                self._on_scan_log(f"Ошибка загрузки scanner.log: {e}")
            if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                self.log_status_label.setText("Ошибка загрузки лога.")

    def get_avatar_path(self):
        """Получить путь к аватару пользователя"""
        try:
            if hasattr(self, 'avatar_path') and self.avatar_path != "default_avatar.png":
                avatar_path = Path(self.avatar_path)
                if avatar_path.exists():
                    return avatar_path
                
            # Проверяем существование аватара по умолчанию
            default_path = Path("default_avatar.png")
            if default_path.exists():
                return default_path
            
            # Если аватар не найден, создаем пустой файл
            default_path.touch()
            return default_path

        except Exception as e:
            logger.error(f"Error getting avatar path: {e}")
            return Path("default_avatar.png")


    def _load_full_log(self, log_path: str) -> None:
        """Загружает полный лог в отдельном потоке"""
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                log_content = f.read()
                
            # Вариант 1: Использование сигнала (предпочтительный)
            if hasattr(self, '_log_loaded_signal'):
                self._log_loaded_signal.emit(log_content, len(log_content.splitlines()))
                
            # Вариант 2: Использование QMetaObject.invokeMethod
            else:
                QMetaObject.invokeMethod(
                    self, 
                    "_process_log_content",
                    Qt.ConnectionType.QueuedConnection,  # Указываем тип соединения
                    Q_ARG(str, log_content),
                    Q_ARG(str, f"Полный лог загружен ({len(log_content.splitlines())} строк).")
                )
                
        except Exception as e:
            error_message = f"Ошибка загрузки полного лога: {e}"
            log_and_notify('error', error_message)
            
            # Используем invokeMethod для безопасного вызова из другого потока
            QMetaObject.invokeMethod(
                self,
                "_on_scan_log",
                Qt.ConnectionType.QueuedConnection,  # Указываем тип соединения
                Q_ARG(str, error_message)
            )

    def _process_log_content(self, content: str, line_count: int) -> None:
        """Обрабатывает загруженный контент лога и обновляет UI"""
        try:
            # Очищаем старые записи
            if hasattr(self, 'detailed_log') and self.detailed_log is not None:
                self.detailed_log.clear()
                self.detailed_log.append(content)
            
            # Добавляем запись в лог
            if hasattr(self, '_add_log_entry'):
                self._add_log_entry("INFO", f"Загружено {line_count} записей лога")

            if hasattr(self, '_log_entries') and self._log_entries is not None:
                self._log_entries.clear()

            if hasattr(self, '_filtered_log_entries') and self._filtered_log_entries is not None:
                self._filtered_log_entries.clear()
            
            # Обрабатываем строки пакетами для оптимизации
            batch_size = 100
            lines = content.splitlines()
            total_lines = len(lines)
            
            for i in range(0, total_lines, batch_size):
                batch = lines[i:i+batch_size]
                
                for line in batch:
                    if not line.strip():  # Пропускаем пустые строки
                        continue
                        
                    # Простая эвристика для разбора уровня лога
                    level = "INFO"  # По умолчанию
                    if "ERROR" in line: 
                        level = "ERROR"
                    elif "WARNING" in line: 
                        level = "WARNING"
                    elif "DEBUG" in line: 
                        level = "DEBUG"
                    elif "VULNERABILITY" in line: 
                        level = "VULNERABILITY"
                    
                    try:
                        self._add_log_entry(level, line)
                    except Exception as e:
                        logger.warning(f"Failed to add log entry: {e}")
                        continue
                
                # Обновляем UI после каждой партии для отзывчивости
                QApplication.processEvents()
            
            # Обновляем статус
            if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                self.log_status_label.setText(f"Обработано {total_lines} записей")
            
        except Exception as e:
            log_and_notify('error', f"Error processing log content: {e}")
            if hasattr(self, '_on_scan_log') and self._on_scan_log is not None:
                self._on_scan_log(f"Ошибка обработки лога: {e}")
            if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                self.log_status_label.setText("Ошибка обработки лога.")

    @staticmethod
    def _read_log_tail(filepath: str, lines: int = 500, buffer_size: int = 4096) -> str:
        """Эффективно читает последние N строк из файла."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                # Переходим в конец файла
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                
                if file_size == 0:
                    return ""

                lines_found = 0
                block_end_byte = file_size
                content = []
                
                while lines_found < lines and block_end_byte > 0:
                    read_size = min(buffer_size, block_end_byte)
                    f.seek(block_end_byte - read_size)
                    block = f.read(read_size)
                    
                    lines_in_block = block.split('\n')
                    content.extend(reversed(lines_in_block))
                    
                    lines_found += block.count('\n')
                    block_end_byte -= read_size
                
                # Собираем последние N строк
                return "\n".join(reversed(content[:lines]))
        except FileNotFoundError:
            return ""
        except Exception as e:
            log_and_notify('error', f"Error reading log tail from {filepath}: {e}")
            return f"Ошибка чтения файла лога: {e}"

    def _on_turbo_mode_changed(self, state):
        if self.turbo_checkbox.isChecked():
            if self.concurrent_spinbox is not None:
                self.concurrent_spinbox.setValue(self.concurrent_spinbox.maximum())
                self.concurrent_spinbox.setEnabled(False)
            if self.timeout_spinbox is not None:
                self.timeout_spinbox.setValue(self.timeout_spinbox.minimum())
                self.timeout_spinbox.setEnabled(False)
            # Отключаем подробный лог (оставляем только WARNING/ERROR)
            from utils.logger import set_log_level
            set_log_level('scanner', 'WARNING')
            set_log_level('scan_controller', 'WARNING')
            set_log_level('main', 'WARNING')
            set_log_level('performance', 'WARNING')
        else:
            if self.concurrent_spinbox is not None:
                self.concurrent_spinbox.setEnabled(True)
                self.concurrent_spinbox.setValue(10)
            if self.timeout_spinbox is not None:
                self.timeout_spinbox.setEnabled(True)
                self.timeout_spinbox.setValue(30)
            # Восстанавливаем подробный лог (INFO)
            from utils.logger import set_log_level
            set_log_level('scanner', 'INFO')
            set_log_level('scan_controller', 'INFO')
            set_log_level('main', 'INFO')
            set_log_level('performance', 'INFO')

    def _on_max_coverage_mode_changed(self, state):
        if self.max_coverage_checkbox.isChecked():
            self.depth_spinbox.setValue(self.depth_spinbox.maximum())
            self.depth_spinbox.setEnabled(False)
            self.concurrent_spinbox.setValue(self.concurrent_spinbox.maximum())
            self.concurrent_spinbox.setEnabled(False)
            self.timeout_spinbox.setValue(self.timeout_spinbox.maximum())
            self.timeout_spinbox.setEnabled(False)
            # Включить повторные попытки для ошибок (флаг для передачи в ScanWorker)
            self._max_coverage_mode = True
        else:
            self.depth_spinbox.setEnabled(True)
            self.concurrent_spinbox.setEnabled(True)
            self.timeout_spinbox.setEnabled(True)
            self.depth_spinbox.setValue(3)
            self.concurrent_spinbox.setValue(10)
            self.timeout_spinbox.setValue(30)
            self._max_coverage_mode = False
            
    def stop_scan(self):
        """Останавливает текущее сканирование через ScanController с уведомлениями."""
        try:
            # Останавливаем таймер
            if hasattr(self, '_scan_timer') and self._scan_timer is not None:
                self._scan_timer.stop()
            
            # Останавливаем сканирование
            if hasattr(self, 'scan_controller') and self.scan_controller is not None:
                self.scan_controller.stop_scan()
            
            # Сбрасываем состояние интерфейса
            if hasattr(self, 'scan_status') and self.scan_status is not None:
                self.scan_status.setText("Сканирование остановлено")
            if hasattr(self, 'scan_progress') and self.scan_progress is not None:
                self.scan_progress.setValue(0)
            if hasattr(self, 'progress_label') and self.progress_label is not None:
                self.progress_label.setText("0%")
            
            # Включаем кнопку "Начать сканирование" и отключаем остальные
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(True)
            if hasattr(self, 'pause_button') and self.pause_button is not None:
                self.pause_button.setEnabled(False)
            if hasattr(self, 'stop_button') and self.stop_button is not None:
                self.stop_button.setEnabled(False)
            
            # Сбрасываем состояние паузы
            self._is_paused = False
            self.pause_button.setText("⏸️ Пауза")
            
            # Добавляем запись в лог
            self._add_log_entry("WARNING", "⏹️ Сканирование остановлено пользователем")
            
            # Показываем информацию о частичных результатах
            if hasattr(self, '_stats') and self._stats is not None:
                urls_scanned = self._stats.get('urls_scanned', 0)
                forms_scanned = self._stats.get('forms_scanned', 0)
                vulnerabilities = self._stats.get('vulnerabilities', 0)
                
                if urls_scanned > 0 or forms_scanned > 0:
                    partial_info = f"Частичные результаты: {urls_scanned} URL, {forms_scanned} форм просканировано"
                    if vulnerabilities > 0:
                        partial_info += f", {vulnerabilities} уязвимостей найдено"
                    self._add_log_entry("INFO", partial_info)
                    
                    # Показываем уведомление пользователю
                    error_handler.show_info_message(
                        "Сканирование остановлено", 
                        f"Сканирование остановлено пользователем.\n\n"
                        f"Частичные результаты:\n"
                        f"• Просканировано URL: {urls_scanned}\n"
                        f"• Просканировано форм: {forms_scanned}\n"
                        f"• Найдено уязвимостей: {vulnerabilities}\n\n"
                        f"Результаты будут сохранены в базу данных."
                    )
            
            # Сбрасываем счетчики прогресса
            self._scan_start_time = None
            self._total_urls = 0
            self._completed_urls = 0
            self._total_progress = 0
            self._active_workers = 0
            self._worker_progress = {}
            
            logger.info("Scan stopped by user")
            
        except Exception as e:
            log_and_notify('error', f"Error stopping scan: {e}")
            self._add_log_entry("ERROR", f"Ошибка при остановке сканирования: {str(e)}")
            
            # В случае ошибки все равно сбрасываем интерфейс
            if hasattr(self, 'scan_button') and self.scan_button is not None:
                self.scan_button.setEnabled(True)
            if hasattr(self, 'pause_button') and self.pause_button is not None:
                self.pause_button.setEnabled(False)
            if hasattr(self, 'stop_button') and self.stop_button is not None:
                self.stop_button.setEnabled(False)
            if hasattr(self, 'scan_status') and self.scan_status is not None:
                self.scan_status.setText("Ошибка остановки сканирования")

class PolicyEditDialog(QDialog):
    def __init__(self, parent=None, policy=None):
        super().__init__(parent)
        self.setWindowTitle("Редактировать политику" if policy else "Создать политику")
        self.policy = policy or {}
        layout = QFormLayout(self)
        self.name_edit = QLineEdit(self.policy.get("name", ""))
        layout.addRow("Название:", self.name_edit)
        self.sql_cb = QCheckBox("SQL Injection")
        self.sql_cb.setChecked("sql" in self.policy.get("enabled_vulns", []))
        self.xss_cb = QCheckBox("XSS")
        self.xss_cb.setChecked("xss" in self.policy.get("enabled_vulns", []))
        self.csrf_cb = QCheckBox("CSRF")
        self.csrf_cb.setChecked("csrf" in self.policy.get("enabled_vulns", []))
        layout.addRow(self.sql_cb)
        layout.addRow(self.xss_cb)
        layout.addRow(self.csrf_cb)
        self.max_depth_spin = QSpinBox()
        self.max_depth_spin.setRange(1, 10)
        self.max_depth_spin.setValue(self.policy.get("max_depth", 3))
        layout.addRow("Глубина:", self.max_depth_spin)
        self.max_conc_spin = QSpinBox()
        self.max_conc_spin.setRange(1, 50)
        self.max_conc_spin.setValue(self.policy.get("max_concurrent", 5))
        layout.addRow("Параллельно:", self.max_conc_spin)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        self.timeout_spin.setValue(self.policy.get("timeout", 30))
        layout.addRow("Таймаут:", self.timeout_spin)
        self.stop_on_first_cb = QCheckBox("Остановить при первой уязвимости")
        self.stop_on_first_cb.setChecked(self.policy.get("stop_on_first_vuln", False))
        layout.addRow(self.stop_on_first_cb)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
    
    def get_policy(self):
        return {
            "name": self.name_edit.text().strip() or "Безымянная",
            "enabled_vulns": [v for v, cb in zip(["sql", "xss", "csrf"], [self.sql_cb, self.xss_cb, self.csrf_cb]) if cb.isChecked()],
            "max_depth": self.max_depth_spin.value(),
            "max_concurrent": self.max_conc_spin.value(),
            "timeout": self.timeout_spin.value(),
            "stop_on_first_vuln": self.stop_on_first_cb.isChecked(),
            # Можно добавить другие поля
        }
