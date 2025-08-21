import time
import asyncio
from datetime import datetime
from typing import Optional
import json
import csv
import os
import sys
import matplotlib.pyplot as plt
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QLineEdit, QCheckBox, 
                             QTabWidget, QProgressBar, QSpinBox, QMessageBox,
                             QFileDialog, QComboBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QSplitter, QFrame, QGroupBox, QGridLayout,
                             QScrollArea, QTextBrowser, QListWidget, QListWidgetItem,
                             QDateEdit, QDateTimeEdit, QDialog, QDialogButtonBox, QTreeWidget, QTreeWidgetItem, QApplication,
                             QFormLayout)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QDate, QDateTime, QTime
from PyQt5.QtGui import QPixmap, QFont, QIcon, QColor
from controllers.scan_controller import ScanController
from controllers.auth_controller import AuthController
from views.edit_profile_window import EditProfileWindow
from utils.database import db
from utils.logger import logger, log_and_notify
from utils.vulnerability_scanner import scan_sql_injection, scan_xss, scan_csrf
import sqlite3
from utils.performance import measure_time, performance_monitor, get_local_timestamp, extract_time_from_timestamp
from utils.security import validate_password_strength, is_safe_url, sanitize_filename
from utils.error_handler import error_handler
from views.tabs.scan_tab import ScanTabWidget
from views.tabs.reports_tab import ReportsTabWidget
from views.tabs.stats_tab import StatsTabWidget
from views.tabs.profile_tab import ProfileTabWidget
import matplotlib
matplotlib.use('Qt5Agg')

# Импорт matplotlib с обработкой ошибок
try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    MATPLOTLIB_AVAILABLE = True
except ImportError as e:
    logger.warning(f"matplotlib not available: {e}")
    MATPLOTLIB_AVAILABLE = False
    FigureCanvas = None
    Figure = None

from qasync import asyncSlot
from policies.policy_manager import PolicyManager

class DashboardWindow(QWidget):
    def __init__(self, user_id, username, parent=None):
        super().__init__(parent)
        self.scan_tab: Optional[QWidget] = None
        self.tabs: Optional[QTabWidget] = None
        self.scan_button: Optional[QPushButton] = None
        self.setWindowTitle("Web Scanner - Control Panel")
        self.user_id = user_id
        self.username = username
        self.avatar_path = "default_avatar.png"
        self.scan_controller = ScanController(user_id)
        self._scan_start_time = None
        self._total_urls = 0
        self._completed_urls = 0
        self._total_progress = 0
        self._active_workers = 0
        self._estimated_total_time = 0
        self._worker_progress = {}  # Словарь для отслеживания прогресса каждого воркера
        self.policy_manager = PolicyManager()
        self.selected_policy = None
        self.setup_ui()
        self.load_policies_to_combobox()
        logger.info(f"Opened control panel for user '{self.username}' (ID: {self.user_id})")

    def format_duration(self, seconds):
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
            self.setWindowTitle("Панель управления")
            self.setMinimumSize(800, 600)

            self.main_layout = QVBoxLayout(self)
            self.tabs = QTabWidget()

            # Создаем все вкладки
            self.scan_tab = QWidget()
            self.reports_tab = QWidget()
            self.stats_tab = QWidget()
            self.profile_tab = QWidget()

            # Настраиваем содержимое вкладок
            self.scan_tab = ScanTabWidget(self.user_id, self)
            self.reports_tab = ReportsTabWidget(self.user_id, self)
            self.stats_tab = StatsTabWidget(self.user_id, self)
            self.profile_tab = ProfileTabWidget(self.user_id, self)

            # Добавляем вкладки в нужном порядке
            self.tabs.addTab(self.scan_tab, "Сканирование")
            self.tabs.addTab(self.reports_tab, "Отчёты")
            self.tabs.addTab(self.stats_tab, "Статистика")
            self.tabs.addTab(self.profile_tab, "Профиль")

            self.main_layout.addWidget(self.tabs)
            self.setLayout(self.main_layout)
            
            # Загружаем аватар после создания всех виджетов
            self.load_avatar()
            
        except (ValueError, sqlite3.Error, KeyError, AttributeError) as e:
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
        self.username_label.setText(f"Добро пожаловать, {self.username}!")

    def setup_scan_tab(self):
        """Настраивает вкладку сканирования"""
        layout = QVBoxLayout(self.scan_tab)

        # 1) Ввод URL
        url_group = QGroupBox("URL для сканирования")
        url_layout = QVBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Введите URL (например: https://example.com)")
        url_layout.addWidget(self.url_input)
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)

        # 2) Выбор типов уязвимостей
        vuln_group = QGroupBox("Типы уязвимостей")
        vuln_layout = QHBoxLayout()
        self.sql_checkbox = QCheckBox("SQL Injection")
        self.xss_checkbox = QCheckBox("XSS")
        self.csrf_checkbox = QCheckBox("CSRF")
        for cb in (self.sql_checkbox, self.xss_checkbox, self.csrf_checkbox):
            vuln_layout.addWidget(cb)
        vuln_group.setLayout(vuln_layout)
        layout.addWidget(vuln_group)

        # 3) Настройки производительности
        perf_group = QGroupBox("Настройки производительности")
        perf_layout = QVBoxLayout()
        
        # Глубина обхода
        depth_layout = QHBoxLayout()
        depth_layout.addWidget(QLabel("Глубина обхода:"))
        self.depth_spinbox = QSpinBox()
        self.depth_spinbox.setRange(0, 10)
        self.depth_spinbox.setValue(3)
        self.depth_spinbox.setToolTip("Количество уровней вложенности для обхода ссылок")
        depth_layout.addWidget(self.depth_spinbox)
        depth_layout.addStretch()
        perf_layout.addLayout(depth_layout)
        
        # Параллельные запросы
        concurrent_layout = QHBoxLayout()
        concurrent_layout.addWidget(QLabel("Параллельные запросы:"))
        self.concurrent_spinbox = QSpinBox()
        self.concurrent_spinbox.setRange(1, 20)
        self.concurrent_spinbox.setValue(5)
        self.concurrent_spinbox.setToolTip("Максимальное количество одновременных запросов")
        concurrent_layout.addWidget(self.concurrent_spinbox)
        concurrent_layout.addStretch()
        perf_layout.addLayout(concurrent_layout)
        
        # Таймаут
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Таймаут (сек):"))
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(5, 60)
        self.timeout_spinbox.setValue(30)
        self.timeout_spinbox.setToolTip("Время ожидания ответа от сервера")
        timeout_layout.addWidget(self.timeout_spinbox)
        timeout_layout.addStretch()
        perf_layout.addLayout(timeout_layout)
        
        # Настройки логирования
        logging_layout = QHBoxLayout()
        self.clear_log_checkbox = QCheckBox("Очищать лог при старте")
        self.clear_log_checkbox.setChecked(True)
        self.clear_log_checkbox.setToolTip("Автоматически очищает файл scanner.log для экономии места на диске")
        logging_layout.addWidget(self.clear_log_checkbox)
        logging_layout.addStretch()
        perf_layout.addLayout(logging_layout)
        
        # Настройки очистки кэшей
        cache_layout = QHBoxLayout()
        self.clear_cache_checkbox = QCheckBox("Очищать кэши при выходе из программы")
        self.clear_cache_checkbox.setChecked(True)
        self.clear_cache_checkbox.setToolTip("Автоматически очищает все кэши приложения для освобождения памяти")
        cache_layout.addWidget(self.clear_cache_checkbox)
        cache_layout.addStretch()
        perf_layout.addLayout(cache_layout)
        
        # Турбо-режим
        turbo_layout = QHBoxLayout()
        self.turbo_checkbox = QCheckBox("Турбо-режим (максимальная скорость)")
        self.turbo_checkbox.setToolTip("Включает максимальную скорость сканирования: максимум параллельных запросов, минимальный таймаут, отключение подробного лога. Не рекомендуется для слабых ПК или при сканировании нестабильных сайтов.")
        self.turbo_checkbox.stateChanged.connect(self._on_turbo_mode_changed)
        turbo_layout.addWidget(self.turbo_checkbox)
        turbo_layout.addStretch()
        perf_layout.addLayout(turbo_layout)
        
        # Максимальное покрытие
        maxcov_layout = QHBoxLayout()
        self.max_coverage_checkbox = QCheckBox("Максимальное покрытие (все страницы)")
        self.max_coverage_checkbox.setToolTip("Пытается просканировать все возможные страницы сайта: максимальная глубина, максимальное количество параллельных запросов, максимальный таймаут, повторные попытки для ошибок. Может занять много времени и создать большую нагрузку на сайт.")
        self.max_coverage_checkbox.stateChanged.connect(self._on_max_coverage_mode_changed)
        maxcov_layout.addWidget(self.max_coverage_checkbox)
        maxcov_layout.addStretch()
        perf_layout.addLayout(maxcov_layout)
        
        perf_group.setLayout(perf_layout)
        layout.addWidget(perf_group)

        # 4) Кнопки управления
        control_group = QGroupBox("Управление")
        control_layout = QHBoxLayout()

        self.scan_button = QPushButton("Начать сканирование")
        self.scan_button.clicked.connect(self.scan_website_sync) # type: ignore
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        
        self.pause_button = QPushButton("⏸️ Пауза")
        self.pause_button.clicked.connect(self.pause_scan)
        self.pause_button.setEnabled(False)
        self.pause_button.setStyleSheet("""
            QPushButton {
                background-color: #ff9800;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #f57c00;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        
        self.stop_button = QPushButton("Остановить")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        
        control_layout.addWidget(self.scan_button)
        control_layout.addWidget(self.pause_button)
        control_layout.addWidget(self.stop_button)
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

        # 5) Прогресс-бар
        progress_group = QGroupBox("Прогресс")
        progress_layout = QVBoxLayout()
        
        # Статус
        self.scan_status = QLabel("Готов к сканированию")
        self.scan_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scan_status.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #333;
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 3px;
                background-color: #f9f9f9;
            }
        """)
        progress_layout.addWidget(self.scan_status)
        
        # Прогресс-бар
        progress_bar_layout = QHBoxLayout()
        self.scan_progress = QProgressBar()
        self.scan_progress.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scan_progress.setTextVisible(False)
        self.scan_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 5px;
                text-align: center;
                color: black;
                background-color: #f0f0f0;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
                margin: 0.5px;
            }
        """)
        progress_bar_layout.addWidget(self.scan_progress)
        
        # Метка прогресса
        self.progress_label = QLabel("0%")
        self.progress_label.setMinimumWidth(50)
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #333;
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 3px;
                background-color: #f9f9f9;
            }
        """)
        progress_bar_layout.addWidget(self.progress_label)
        
        progress_layout.addLayout(progress_bar_layout)
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        # 6) Расширенный лог сканирования (OWASP ZAP стиль)
        log_group = QGroupBox("🔍 Детальный просмотр сканирования")
        log_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 11pt;
                color: #2c3e50;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                background-color: #ecf0f1;
            }
        """)
        
        # Создаем разделенный вид (splitter) для древовидного представления и лога
        log_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Левая панель: Древовидное представление
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Заголовок для дерева
        tree_header = QLabel("🌐 Структура сайта")
        tree_header.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #2c3e50;
                padding: 5px;
                background-color: #ecf0f1;
                border-radius: 3px;
            }
        """)
        left_layout.addWidget(tree_header)
        
        # Древовидное представление URL и форм
        self.site_tree = QTreeWidget()
        self.site_tree.setHeaderLabels(["Ресурс", "Тип", "Статус"])
        self.site_tree.setColumnWidth(0, 300)
        self.site_tree.setColumnWidth(1, 80)
        self.site_tree.setColumnWidth(2, 100)
        self.site_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #000000;
                color: #00ffcc;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                font-size: 9pt;
            }
            QTreeWidget::item {
                padding: 3px;
                border-bottom: 1px solid #222222;
                color: #00ffcc;
            }
            QTreeWidget::item:selected {
                background-color: #3498db;
                color: #000000;
            }
            QTreeWidget::item:hover {
                background-color: #222222;
            }
        """)
        left_layout.addWidget(self.site_tree)
        
        # Статистика в реальном времени
        stats_group = QGroupBox("📊 Статистика")
        stats_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 10pt;
                color: #2c3e50;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 5px;
                padding-top: 5px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                background-color: #ffffff;
            }
        """)
        stats_layout = QVBoxLayout(stats_group)
        
        # Метки статистики
        self.stats_labels = {}
        stats_items = [
            ("urls_found", "Найдено URL:", "0"),
            ("urls_scanned", "Просканировано URL:", "0"),
            ("forms_found", "Найдено форм:", "0"),
            ("forms_scanned", "Просканировано форм:", "0"),
            ("vulnerabilities", "Уязвимостей:", "0"),
            ("requests_sent", "Запросов отправлено:", "0"),
            ("errors", "Ошибок:", "0"),
            ("scan_time", "Время сканирования:", "00:00:00")
        ]
        
        for key, label_text, default_value in stats_items:
            label_layout = QHBoxLayout()
            label = QLabel(label_text)
            label.setStyleSheet("font-weight: bold; color: #2c3e50;")
            value = QLabel(default_value)
            value.setStyleSheet("color: #3498db; font-weight: bold;")
            label_layout.addWidget(label)
            label_layout.addWidget(value)
            label_layout.addStretch()
            stats_layout.addLayout(label_layout)
            self.stats_labels[key] = value
        
        left_layout.addWidget(stats_group)
        
        # Правая панель: Детальный лог
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Заголовок для лога
        log_header = QLabel("📋 Детальный лог")
        log_header.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #2c3e50;
                padding: 5px;
                background-color: #ecf0f1;
                border-radius: 3px;
            }
        """)
        right_layout.addWidget(log_header)
        
        # Панель фильтров
        filter_panel = QWidget()
        filter_layout = QHBoxLayout(filter_panel)
        
        # Фильтр по уровню
        filter_layout.addWidget(QLabel("Фильтр:"))
        self.log_filter = QComboBox()
        self.log_filter.addItems(["Все", "DEBUG", "INFO", "WARNING", "ERROR", "VULNERABILITY", "REQUEST", "RESPONSE", "PROGRESS", "SKIP_FILE", "ADD_LINK"])
        self.log_filter.setCurrentText("Все")  # Устанавливаем значение по умолчанию
        self.log_filter.currentTextChanged.connect(self._filter_log)
        filter_layout.addWidget(self.log_filter)
        
        
        # Поиск в логе
        filter_layout.addWidget(QLabel("Поиск:"))
        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText("Введите текст для поиска...")
        self.log_search.textChanged.connect(self._search_in_log)
        filter_layout.addWidget(self.log_search)
        
        # Кнопка очистки поиска
        self.clear_search_button = QPushButton("🗑️")
        self.clear_search_button.setToolTip("Очистить поиск")
        self.clear_search_button.clicked.connect(self._clear_search)
        self.clear_search_button.setMaximumWidth(30)
        filter_layout.addWidget(self.clear_search_button)
        
        filter_layout.addStretch()
        right_layout.addWidget(filter_panel)
        
        # Детальный лог с цветовой кодировкой
        self.detailed_log = QTextEdit()
        self.detailed_log.setReadOnly(True)
        self.detailed_log.setMinimumHeight(400)
        self.detailed_log.setMaximumHeight(800)
        
        # Устанавливаем моноширинный шрифт для лучшей читаемости
        font = self.detailed_log.font()
        font.setFamily("Consolas")
        font.setPointSize(9)
        self.detailed_log.setFont(font)
        
        # Стилизация лога с темной темой
        self.detailed_log.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 2px solid #3c3c3c;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 9pt;
                line-height: 1.4;
            }
            QTextEdit:focus {
                border: 2px solid #0078d4;
            }
        """)
        right_layout.addWidget(self.detailed_log)
        
        # --- КНОПКИ УПРАВЛЕНИЯ ЛОГОМ ---
        self.clear_log_button = QPushButton("🗑️ Очистить лог")
        self.clear_log_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:pressed {
                background-color: #a93226;
            }
        """)
        self.clear_log_button.clicked.connect(self.clear_scan_log)

        self.export_log_button = QPushButton("📤 Экспорт лога")
        self.export_log_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
        """)
        self.export_log_button.clicked.connect(self.export_scan_log)

        self.auto_scroll_checkbox = QCheckBox("Автоскролл")
        self.auto_scroll_checkbox.setChecked(True)
        self.auto_scroll_checkbox.setStyleSheet("""
            QCheckBox {
                color: #2c3e50;
                font-weight: bold;
            }
        """)

        self.load_full_log_button = QPushButton("🔄 Загрузить полный лог")
        self.load_full_log_button.setToolTip("Загружает весь файл scanner.log. Может занять время.")
        self.load_full_log_button.clicked.connect(lambda: self.load_scanner_log_to_ui(full=True))

        # --- ДОБАВЛЯЕМ КНОПКИ В filter_layout ---
        filter_layout.addWidget(self.clear_log_button)
        filter_layout.addWidget(self.export_log_button)
        filter_layout.addWidget(self.load_full_log_button)
        filter_layout.addWidget(self.auto_scroll_checkbox)

        # --- ОСТАЛЬНОЕ ОСТАВЛЯЕМ БЕЗ ИЗМЕНЕНИЙ ---
        filter_layout.addStretch()
        right_layout.addWidget(filter_panel)
        
        # Детальный лог с цветовой кодировкой
        self.detailed_log = QTextEdit()
        self.detailed_log.setReadOnly(True)
        self.detailed_log.setMinimumHeight(400)
        self.detailed_log.setMaximumHeight(800)
        
        # Устанавливаем моноширинный шрифт для лучшей читаемости
        font = self.detailed_log.font()
        font.setFamily("Consolas")
        font.setPointSize(9)
        self.detailed_log.setFont(font)
        
        # Стилизация лога с темной темой
        self.detailed_log.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 2px solid #3c3c3c;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 9pt;
                line-height: 1.4;
            }
            QTextEdit:focus {
                border: 2px solid #0078d4;
            }
        """)
        right_layout.addWidget(self.detailed_log)
        
        # Кнопки управления логом
        log_buttons_layout = QHBoxLayout()
        
        # Кнопка экспорта лога
        self.export_log_button = QPushButton("📤 Экспорт лога")
        self.export_log_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
        """)
        self.export_log_button.clicked.connect(self.export_scan_log)
        
        # Кнопка автоскролла
        self.auto_scroll_checkbox = QCheckBox("Автоскролл")
        self.auto_scroll_checkbox.setChecked(True)
        self.auto_scroll_checkbox.setStyleSheet("""
            QCheckBox {
                color: #2c3e50;
                font-weight: bold;
            }
        """)
        
        # --- Новые элементы для управления загрузкой лога ---
        self.load_full_log_button = QPushButton("🔄 Загрузить полный лог")
        self.load_full_log_button.setToolTip("Загружает весь файл scanner.log. Может занять время.")
        self.load_full_log_button.clicked.connect(lambda: self.load_scanner_log_to_ui(full=True))
        
        self.log_status_label = QLabel("Отображены последние 500 строк")
        self.log_status_label.setStyleSheet("color: #7f8c8d; font-style: italic;")

        log_buttons_layout.addWidget(self.clear_log_button)
        log_buttons_layout.addWidget(self.export_log_button)
        log_buttons_layout.addWidget(self.load_full_log_button) # Добавляем новую кнопку
        log_buttons_layout.addWidget(self.auto_scroll_checkbox)
        log_buttons_layout.addStretch()

        right_layout.addLayout(log_buttons_layout)
        right_layout.addWidget(self.log_status_label) # Добавляем новую метку
        
        # Добавляем панели в splitter
        log_splitter.addWidget(left_panel)
        log_splitter.addWidget(right_panel)
        log_splitter.setSizes([400, 600])  # Начальные размеры панелей
        
        log_layout = QVBoxLayout()
        log_layout.addWidget(log_splitter)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        # Инициализируем переменные для отслеживания прогресса
        self._scan_start_time = None
        self._total_urls = 0
        self._completed_urls = 0
        self._total_progress = 0
        self._active_workers = 0
        self._worker_progress = {}
        
        # Переменные для детального лога
        self._log_entries = []
        self._filtered_log_entries = []
        self._current_filter = "Все"
        self._search_text = ""
        
        # Переменные для статистики
        self._stats = {
            'urls_found': 0,
            'urls_scanned': 0,
            'forms_found': 0,
            'forms_scanned': 0,
            'vulnerabilities': 0,
            'requests_sent': 0,
            'errors': 0,
        }
        
        # Переменные для управления сканированием
        self._scan_start_time = None
        self._total_urls = 0
        self._completed_urls = 0
        self._total_progress = 0
        self._active_workers = 0
        self._worker_progress = {}
        self._is_paused = False  # Состояние паузы

        # === Политики сканирования ===
        policy_group = QGroupBox("Политика сканирования")
        policy_layout = QHBoxLayout()
        self.policy_combobox = QComboBox()
        self.policy_combobox.setToolTip("Выберите политику сканирования (набор параметров)")
        self.policy_combobox.currentIndexChanged.connect(self.on_policy_selected)
        policy_layout.addWidget(QLabel("Профиль:"))
        policy_layout.addWidget(self.policy_combobox)
        self.add_policy_btn = QPushButton("+")
        self.add_policy_btn.setToolTip("Создать новую политику")
        self.add_policy_btn.clicked.connect(self.create_policy_dialog)
        self.edit_policy_btn = QPushButton("✎")
        self.edit_policy_btn.setToolTip("Редактировать выбранную политику")
        self.edit_policy_btn.clicked.connect(self.edit_policy_dialog)
        self.delete_policy_btn = QPushButton("🗑")
        self.delete_policy_btn.setToolTip("Удалить выбранную политику")
        self.delete_policy_btn.clicked.connect(self.delete_policy)
        policy_layout.addWidget(self.add_policy_btn)
        policy_layout.addWidget(self.edit_policy_btn)
        policy_layout.addWidget(self.delete_policy_btn)
        policy_group.setLayout(policy_layout)
        layout.addWidget(policy_group)

    def load_policies_to_combobox(self):
        self.policy_combobox.clear()
        policies = self.policy_manager.list_policies()
        if not policies:
            # Если нет политик, создаём и добавляем дефолтную
            default_policy = self.policy_manager.get_default_policy()
            self.policy_manager.save_policy("default", default_policy)
            policies = ["default"]
        self.policy_combobox.addItems(policies)
        self.selected_policy = self.policy_manager.load_policy(policies[0])

    def on_policy_selected(self, idx):
        name = self.policy_combobox.currentText()
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
            idx = self.policy_combobox.findText(name)
            if idx >= 0:
                self.policy_combobox.setCurrentIndex(idx)

    def edit_policy_dialog(self):
        name = self.policy_combobox.currentText()
        if not name:
            return
        policy = self.policy_manager.load_policy(name)
        dlg = PolicyEditDialog(self, policy)
        if dlg.exec_() == QDialog.Accepted:
            new_policy = dlg.get_policy()
            self.policy_manager.save_policy(name, new_policy)
            self.load_policies_to_combobox()
            idx = self.policy_combobox.findText(name)
            if idx >= 0:
                self.policy_combobox.setCurrentIndex(idx)

    def delete_policy(self):
        name = self.policy_combobox.currentText()
        if name:
            self.policy_manager.delete_policy(name)
            self.load_policies_to_combobox()

    @asyncSlot()
    async def scan_website_sync(self):
        """Асинхронный метод для подключения к кнопке"""
        try:
            await self.scan_website()
        except Exception as e:
            error_handler.handle_validation_error(e, "scan_website_sync")
            log_and_notify('error', f"Error in scan_website_sync: {e}")

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
            # Очищаем файл scanner.log при начале нового сканирования (если включено)
            if hasattr(self, 'clear_log_checkbox') and self.clear_log_checkbox.isChecked():
                self._clear_scanner_log_file()
            
            # Сбрасываем интерфейс
            if self.scan_progress:
                self.scan_progress.setValue(0)
            if self.scan_status:
                self.scan_status.setText("Подготовка к сканированию...")
            if self.scan_button:
                self.scan_button.setEnabled(False)
            if self.pause_button:
                self.pause_button.setEnabled(True)
            if self.stop_button:
                self.stop_button.setEnabled(True)
            
            # Сбрасываем состояние паузы
            self._is_paused = False
            self.pause_button.setText("⏸️ Пауза")
            
            # Очищаем древовидное представление и статистику
            self.site_tree.clear()
            self._log_entries.clear()
            self._filtered_log_entries.clear()
            self._scanned_urls = set()  # Множество для отслеживания уникальных просканированных URL
            self._scanned_forms = set()  # Множество для отслеживания уникальных просканированных форм
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
            
            # Обновляем все метки статистики
            for key in self.stats_labels:
                self.stats_labels[key].setText("0")
            self.stats_labels['scan_time'].setText("00:00:00")
            
            # Запускаем таймер для обновления времени сканирования
            self._scan_timer = QTimer()
            self._scan_timer.timeout.connect(self._update_scan_time)
            self._scan_timer.start(1000)  # Обновляем каждую секунду
            
            # Немедленно обновляем статус на начало сканирования
            self.scan_status.setText("Сканирование...")
            self.progress_label.setText("0%")
            
            # Добавляем начальную запись в лог
            self._add_log_entry("INFO", f"🚀 Начало сканирования: {url}")
            self._add_log_entry("INFO", f"📋 Типы сканирования: {', '.join(types)}")
            self._add_log_entry("INFO", f"⚙️ Параметры: глубина={max_depth}, параллельно={max_concurrent}, таймаут={timeout}с")
            
            # Заменяем параметры на параметры из политики
            policy = self.selected_policy or self.policy_manager.get_default_policy()
            types = policy.get("enabled_vulns", types)
            max_depth = policy.get("max_depth", max_depth)
            max_concurrent = policy.get("max_concurrent", max_concurrent)
            timeout = policy.get("timeout", timeout)
            # Можно добавить другие параметры политики
            # ... остальной код start_scan ...
            
            # Запускаем асинхронное сканирование
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
                max_coverage_mode=max_coverage_mode,
                # username=self.username  # если потребуется, добавить в ScanController
            )
            
            # Записываем метрики производительности
            performance_monitor.start_timer("scan_session")
            
        except Exception as e:
            # Останавливаем таймер при ошибке
            if hasattr(self, '_scan_timer'):
                self._scan_timer.stop()
            
            error_handler.handle_network_error(e, "start_scan")
            log_and_notify('error', f"Error in start_scan: {e}")
            self.scan_status.setText("Ошибка запуска сканирования")
            if self.scan_button:
                self.scan_button.setEnabled(True)
            if self.stop_button:
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

    def _add_log_entry(self, level: str, message: str, url: str = "", details: str = ""):
        """Добавляет запись в детальный лог с цветовой кодировкой"""
        try:
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
            
            # Формируем HTML для записи
            html_entry = f'<div style="margin: 2px 0;"><span style="color: {color}; font-weight: bold;">[{timestamp}] {level}</span>'
            
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
            
            # Обновляем отфильтрованный список
            self._apply_filters()
            
            # Обновляем отображение
            self._update_log_display()
            
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
            if not hasattr(self, '_log_entries') or not hasattr(self, '_filtered_log_entries'):
                return
                
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
        except Exception as e:
            log_and_notify('error', f"Error in _apply_filters: {e}")

    def _update_log_display(self):
        """Обновляет отображение лога"""
        try:
            if not hasattr(self, 'detailed_log') or not hasattr(self, '_filtered_log_entries'):
                return
                
            html_content = ""
            for entry in self._filtered_log_entries:
                html_content += entry['html']
            
            self.detailed_log.setHtml(html_content)
        except Exception as e:
            log_and_notify('error', f"Error in _update_log_display: {e}")

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

    def _update_stats(self, key: str, value):
        """Обновляет статистику"""
        if key in self._stats:
            self._stats[key] = value
            if key in self.stats_labels:
                self.stats_labels[key].setText(str(value))

    def update_forms_counters(self, forms_found: int = 0, forms_scanned: int = 0):
        """Принудительно обновляет счетчики форм"""
        if forms_found > self._stats['forms_found']:
            self._stats['forms_found'] = forms_found
            self._update_stats('forms_found', self._stats['forms_found'])
        if forms_scanned > self._stats['forms_scanned']:
            self._stats['forms_scanned'] = forms_scanned
            self._update_stats('forms_scanned', self._stats['forms_scanned'])

    def update_all_counters(self):
        """Принудительно обновляет все счетчики статистики из текущего состояния"""
        try:
            # Обновляем счетчик найденных URL из дерева
            total_urls_in_tree = 0
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
        """Обновляет время сканирования"""
        try:
            # Проверяем, что сканирование активно
            if not hasattr(self, '_scan_timer') or not self._scan_timer.isActive():
                return
            
            # Проверяем, что время начала сканирования установлено
            if not hasattr(self, '_stats') or 'scan_start_time' not in self._stats or not self._stats['scan_start_time']:
                return
            
            # Вычисляем прошедшее время
            scan_start = self._stats['scan_start_time']
            if not isinstance(scan_start, datetime):
                return
            elapsed = datetime.now() - scan_start
            time_str = str(elapsed).split('.')[0]  # Убираем микросекунды
            
            # Обновляем отображение времени
            if 'scan_time' in self.stats_labels:
                self.stats_labels['scan_time'].setText(time_str)
            
            # Также обновляем в статистике
            if hasattr(self, '_stats'):
                # self._stats['scan_time'] = time_str  # Не сохраняем строку в int
                pass
            
            # Периодически обновляем все счетчики для синхронизации
            # Обновляем каждые 5 секунд (5-й вызов таймера)
            if not hasattr(self, '_timer_counter'):
                self._timer_counter = 0
            self._timer_counter += 1
            
            if self._timer_counter % 5 == 0:  # Каждые 5 секунд
                self.update_all_counters()
                
        except Exception as e:
            log_and_notify('error', f"Error updating scan time: {e}")
            # В случае ошибки останавливаем таймер
            if hasattr(self, '_scan_timer'):
                self._scan_timer.stop()

    def _on_vulnerability_found(self, url: str, vuln_type: str, details: str, target: str):
        """Обработчик обнаружения уязвимости"""
        message = f"Обнаружена уязвимость {vuln_type}"
        self._add_log_entry("VULNERABILITY", message, url, details)
        
        # Обновляем статистику
        self._stats['vulnerabilities'] += 1
        self._update_stats('vulnerabilities', self._stats['vulnerabilities'])
        
        # Обновляем статус в дереве
        self._update_url_status(url, "Уязвимость")

    def _update_url_status(self, url: str, status: str):
        """Обновляет статус URL в дереве"""
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
                        if url not in getattr(self, '_scanned_forms', set()):
                            if not hasattr(self, '_scanned_forms'):
                                self._scanned_forms = set()
                            self._scanned_forms.add(url)
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

    async def _on_scan_result(self, result: dict):
        """Обработка результата сканирования"""
        try:
            # Останавливаем таймер
            if hasattr(self, '_scan_timer'):
                self._scan_timer.stop()
            
            # Обновляем интерфейс
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
            self._stats['urls_scanned'] = total_urls
            self._stats['vulnerabilities'] = total_vulnerabilities
            self._stats['forms_scanned'] = total_forms_scanned
            
            # Обновляем отображение статистики
            self._update_stats('urls_scanned', total_urls)
            self._update_stats('vulnerabilities', total_vulnerabilities)
            self._update_stats('forms_scanned', total_forms_scanned)
            
            # Финальное обновление всех счетчиков для синхронизации
            self.update_all_counters()
            
            # Завершаем метрики производительности
            performance_monitor.end_timer("scan_session", performance_monitor.start_timer("scan_session"))
            
            # Сохраняем результат в базу данных
            await self.scan_controller.save_scan_result(result)
            
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

    def _on_scan_progress(self, progress: int, url: str):
        """Обработчик прогресса сканирования"""
        try:
            # Проверяем, что сканирование все еще активно
            if not hasattr(self, '_scan_timer') or not self._scan_timer.isActive():
                return
            
            # Обновляем прогресс-бар
            self.scan_progress.setValue(progress)
            self.progress_label.setText(f"{progress}%")
            
            # Добавляем URL в дерево если он новый
            if url:
                # Проверяем, есть ли уже такой URL в дереве
                existing_urls = []
                for i in range(self.site_tree.topLevelItemCount()):
                    root_item = self.site_tree.topLevelItem(i)
                    if root_item is not None:
                        for j in range(root_item.childCount()):
                            child = root_item.child(j)
                            if child is not None:
                                existing_urls.append(child.text(0))
                
                if url not in existing_urls:
                    self._add_url_to_tree(url, "URL", "Сканируется")
                    # Увеличиваем счетчик найденных URL только для новых URL
                    self._stats['urls_found'] += 1
                    self._update_stats('urls_found', self._stats['urls_found'])
                
                # Обновляем статус URL в дереве
                self._update_url_status(url, "Просканирован")
                
                # Обновляем счетчик просканированных URL только если это новый URL
                if url not in getattr(self, '_scanned_urls', set()):
                    if not hasattr(self, '_scanned_urls'):
                        self._scanned_urls = set()
                    self._scanned_urls.add(url)
                    self._stats['urls_scanned'] += 1
                    self._update_stats('urls_scanned', self._stats['urls_scanned'])
            
            # Добавляем запись о прогрессе
            if progress % 10 == 0:  # Логируем каждые 10%
                self._add_log_entry("PROGRESS", f"Прогресс: {progress}%", url)
            
        except Exception as e:
            log_and_notify('error', f"Error in _on_scan_progress: {e}")

    def _on_scan_progress_with_forms(self, progress: int, url: str, forms_found: int | None = None, forms_scanned: int | None = None):
        """Обработчик прогресса сканирования с информацией о формах"""
        try:
            # Проверяем, что сканирование все еще активно
            if not hasattr(self, '_scan_timer') or not self._scan_timer.isActive():
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
        pixmap = QPixmap(self.avatar_path).scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatio)
        self.avatar_label.setPixmap(pixmap)

    def handle_scan(self):
        url = self.url_input.text()
        scan_types = []
        if self.sql_checkbox.isChecked():
            scan_types.append('SQL Injection')
        if self.xss_checkbox.isChecked():
            scan_types.append('XSS')
        if self.csrf_checkbox.isChecked():
            scan_types.append('CSRF')

        if url and scan_types:
            asyncio.create_task(self.scan_controller.start_scan(url, scan_types))

    # ----------------------- Отчёты -----------------------
    def setup_reports_tab(self):
        layout = QVBoxLayout()

        # Фильтры
        filter_group = QGroupBox("Фильтры")
        filter_layout = QVBoxLayout()
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Фильтр по URL")
        filter_layout.addWidget(self.filter_input)

        self.filter_sql_cb = QCheckBox("SQL Injection")
        self.filter_xss_cb = QCheckBox("XSS")
        self.filter_csrf_cb = QCheckBox("CSRF")
        cb_layout = QHBoxLayout()
        cb_layout.addWidget(self.filter_sql_cb)
        cb_layout.addWidget(self.filter_xss_cb)
        cb_layout.addWidget(self.filter_csrf_cb)
        filter_layout.addLayout(cb_layout)

        date_layout = QHBoxLayout()
        from PyQt5.QtWidgets import QDateTimeEdit
        self.date_from = QDateTimeEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.date_from.setDateTime(QDateTime.currentDateTime().addDays(-30))
        date_layout.addWidget(QLabel("С: "))
        date_layout.addWidget(self.date_from)
        
        # Кнопки быстрого выбора времени для "С"
        from_time_buttons = QHBoxLayout()
        from_start_day_btn = QPushButton("00:00")
        from_start_day_btn.setMaximumWidth(50)
        from_start_day_btn.clicked.connect(lambda: self._set_time_to_start_of_day(self.date_from))
        from_time_buttons.addWidget(from_start_day_btn)
        date_layout.addLayout(from_time_buttons)
        
        self.date_to = QDateTimeEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.date_to.setDateTime(QDateTime.currentDateTime())
        date_layout.addWidget(QLabel("По: "))
        date_layout.addWidget(self.date_to)
        
        # Кнопки быстрого выбора времени для "По"
        to_time_buttons = QHBoxLayout()
        to_end_day_btn = QPushButton("23:59")
        to_end_day_btn.setMaximumWidth(50)
        to_end_day_btn.clicked.connect(lambda: self._set_time_to_end_of_day(self.date_to))
        to_time_buttons.addWidget(to_end_day_btn)
        to_now_btn = QPushButton("Сейчас")
        to_now_btn.setMaximumWidth(50)
        to_now_btn.clicked.connect(lambda: self._set_time_to_now(self.date_to))
        to_time_buttons.addWidget(to_now_btn)
        date_layout.addLayout(to_time_buttons)

        filter_layout.addLayout(date_layout)

        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)

        # Таблица со сканированиями
        table_group = QGroupBox("Список сканирований")
        table_layout = QVBoxLayout()
        
        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(7)
        self.scans_table.setHorizontalHeaderLabels([
            "ID", "URL", "Дата", "Тип", "Статус", "Длительность", "Уязвимости"
        ])
        
        # Настраиваем ширину колонок
        header = self.scans_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        
        self.scans_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.scans_table.setSelectionMode(QTableWidget.SingleSelection)
        self.scans_table.itemSelectionChanged.connect(self.on_scan_selected)
        table_layout.addWidget(self.scans_table)
        
        # Кнопки для работы с выбранным сканированием
        selected_scan_layout = QHBoxLayout()
        self.export_selected_json_button = QPushButton("Экспорт в JSON")
        self.export_selected_json_button.clicked.connect(self.export_selected_scan_json)
        selected_scan_layout.addWidget(self.export_selected_json_button)

        self.export_selected_csv_button = QPushButton("Экспорт в CSV")
        self.export_selected_csv_button.clicked.connect(self.export_selected_scan_csv)
        selected_scan_layout.addWidget(self.export_selected_csv_button)

        self.export_selected_pdf_button = QPushButton("Экспорт в PDF")
        self.export_selected_pdf_button.clicked.connect(self.export_selected_scan_pdf)
        selected_scan_layout.addWidget(self.export_selected_pdf_button)

        self.export_selected_html_button = QPushButton("Экспорт в HTML")
        self.export_selected_html_button.clicked.connect(self.export_selected_scan_html)
        selected_scan_layout.addWidget(self.export_selected_html_button)
        
        self.export_selected_txt_button = QPushButton("Экспорт в TXT")
        self.export_selected_txt_button.clicked.connect(self.export_selected_scan_txt)
        selected_scan_layout.addWidget(self.export_selected_txt_button)
        table_layout.addLayout(selected_scan_layout)
        table_group.setLayout(table_layout)
        layout.addWidget(table_group)

        # Текстовый отчет
        report_group = QGroupBox("Сводный отчет")
        report_layout = QVBoxLayout()
        
        self.reports_text = QTextEdit()
        self.reports_text.setReadOnly(True)
        report_layout.addWidget(self.reports_text)

        self.refresh_reports_button = QPushButton("Обновить отчёты")
        self.refresh_reports_button.clicked.connect(self.refresh_reports)

        self.clear_reports_button = QPushButton("Очистить отчёты")
        self.clear_reports_button.clicked.connect(self.clear_reports_text)

        self.export_json_button = QPushButton("Экспорт всех в JSON")
        self.export_json_button.clicked.connect(self.export_to_json)

        self.export_csv_button = QPushButton("Экспорт всех в CSV")
        self.export_csv_button.clicked.connect(self.export_to_csv)

        self.export_pdf_button = QPushButton("Экспорт всех в PDF")
        self.export_pdf_button.clicked.connect(self.export_to_pdf)

        self.export_html_button = QPushButton("Экспорт всех в HTML")
        self.export_html_button.clicked.connect(self.export_to_html)

        self.export_txt_button = QPushButton("Экспорт всех в TXT")
        self.export_txt_button.clicked.connect(self.export_to_txt)

        self.generate_detailed_report_button = QPushButton("Создать детальный отчет")
        self.generate_detailed_report_button.clicked.connect(self.generate_detailed_report)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.refresh_reports_button)
        button_layout.addWidget(self.clear_reports_button)
        button_layout.addWidget(self.export_json_button)
        button_layout.addWidget(self.export_csv_button)
        button_layout.addWidget(self.export_pdf_button)
        button_layout.addWidget(self.export_html_button)
        button_layout.addWidget(self.export_txt_button)
        button_layout.addWidget(self.generate_detailed_report_button)
        
        report_layout.addLayout(button_layout)
        report_group.setLayout(report_layout)
        layout.addWidget(report_group)

        self.reports_tab.setLayout(layout)
        
        # Загружаем данные при создании
        self.refresh_reports()

    def reset_filters(self):
        self.filter_input.clear()
        self.filter_sql_cb.setChecked(False)
        self.filter_xss_cb.setChecked(False)
        self.filter_csrf_cb.setChecked(False)
        self.date_from.setDateTime(QDateTime.currentDateTime().addDays(-30))
        self.date_to.setDateTime(QDateTime.currentDateTime())
        self.refresh_reports()

    def refresh_reports(self):
        scans = db.get_scans_by_user(self.user_id)
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
        report_lines = []
        
        # Добавляем заголовок отчета
        report_lines.append("=" * 80)
        report_lines.append("ОТЧЕТ О СКАНИРОВАНИИ УЯЗВИМОСТЕЙ")
        report_lines.append("=" * 80)
        report_lines.append(f"Период: {from_dt} - {to_dt}")
        report_lines.append(f"Фильтр URL: {url_filter if url_filter else 'Все'}")
        report_lines.append(f"Типы уязвимостей: {', '.join(selected_types) if selected_types else 'Все'}")
        report_lines.append("=" * 80)
        report_lines.append("")

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

    def populate_scans_table(self, scans, url_filter, selected_types, from_dt, to_dt):
        """Заполняет таблицу сканирований с учетом фильтров"""
        try:
            self.scans_table.setRowCount(0)
            filtered_scans = []
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
                filtered_scans.append(scan)
            self.scans_table.setRowCount(len(filtered_scans))
            for row, scan in enumerate(filtered_scans):
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
                
                self.scans_table.setItem(row, 0, QTableWidgetItem(str(scan['id'])))
                self.scans_table.setItem(row, 1, QTableWidgetItem(scan['url']))
                self.scans_table.setItem(row, 2, QTableWidgetItem(scan['timestamp']))
                self.scans_table.setItem(row, 3, QTableWidgetItem(scan['scan_type']))
                self.scans_table.setItem(row, 4, QTableWidgetItem(scan['status']))
                self.scans_table.setItem(row, 5, QTableWidgetItem(self.format_duration(scan.get('scan_duration', 0))))
                
                # Создаем элемент с детальной информацией об уязвимостях
                vuln_item = QTableWidgetItem(vuln_text)
                self.scans_table.setItem(row, 6, vuln_item)
                
                # Устанавливаем цвет фона в зависимости от наличия уязвимостей
                if total_vulns > 0:
                    vuln_item.setBackground(QColor("red"))
                    vuln_item.setForeground(QColor("white"))
                else:
                    vuln_item.setBackground(QColor("green"))
                    vuln_item.setForeground(QColor("black"))
                
                # Устанавливаем подсказку с дополнительной информацией
                if total_vulns > 0:
                    tooltip_text = f"Всего уязвимостей: {total_vulns}\n"
                    for vuln_type, count in vulnerability_counts.items():
                        if count > 0:
                            tooltip_text += f"• {vuln_type}: {count}\n"
                    vuln_item.setToolTip(tooltip_text.strip())
                else:
                    vuln_item.setToolTip("Уязвимостей не обнаружено")
            
            self.filtered_scans = filtered_scans
            logger.info(f"Populated scans table: {len(filtered_scans)} scans found")
            self.on_scan_selected()
        except Exception as e:
            error_handler.handle_database_error(e, "populate_scans_table")
            log_and_notify('error', f"Error populating scans table: {e}")

    def on_scan_selected(self):
        """Обработчик выбора сканирования в таблице"""
        current_row = self.scans_table.currentRow()
        logger.info(f"Scan selected: row={current_row}, has_filtered_scans={hasattr(self, 'filtered_scans')}, filtered_count={len(self.filtered_scans) if hasattr(self, 'filtered_scans') else 0}")

    def get_selected_scan(self):
        """Получает выбранное сканирование"""
        current_row = self.scans_table.currentRow()
        if current_row >= 0 and hasattr(self, 'filtered_scans') and current_row < len(self.filtered_scans):
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

    def _on_period_changed(self, period_combo, custom_period_widget):
        """Обработчик изменения периода"""
        custom_period_widget.setVisible(period_combo.currentText() == "Произвольный период")

    def _filter_scans_for_report(self, scans, from_date, to_date, vuln_types, risk_levels, url_filter):
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

    def _generate_enhanced_report(self, scans, format_type, filename, sections, include_charts, include_colors, sort_option):
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
    def setup_stats_tab(self):
        layout = QVBoxLayout()

        self.refresh_stats_button = QPushButton("Обновить статистику")
        self.refresh_stats_button.clicked.connect(self.refresh_stats)
        if MATPLOTLIB_AVAILABLE and FigureCanvas is not None and Figure is not None:
            self.stats_canvas = FigureCanvas(Figure(figsize=(5, 4)))
            layout.addWidget(self.refresh_stats_button)
            layout.addWidget(self.stats_canvas)
        else:
            # Альтернативный виджет для статистики без matplotlib
            self.stats_text = QTextEdit()
            self.stats_text.setReadOnly(True)
            layout.addWidget(self.refresh_stats_button)
            layout.addWidget(QLabel("Статистика (matplotlib недоступен):"))
            layout.addWidget(self.stats_text)

        self.stats_tab.setLayout(layout)

    def refresh_stats(self):
        scans = db.get_scans_by_user(self.user_id)
        if not scans:
            if MATPLOTLIB_AVAILABLE and FigureCanvas is not None:
                self.stats_canvas.figure.clear()
                ax = self.stats_canvas.figure.add_subplot(111)
                ax.text(0.5, 0.5, "Нет данных для отображения", 
                       horizontalalignment='center', verticalalignment='center')
                self.stats_canvas.draw()
            else:
                self.stats_text.setText("Нет данных для отображения")
            return

        if MATPLOTLIB_AVAILABLE and FigureCanvas is not None:
            self._refresh_stats_with_matplotlib(scans)
        else:
            self._refresh_stats_text_only(scans)

    def _refresh_stats_with_matplotlib(self, scans):
        """Обновление статистики с использованием matplotlib"""
        try:
            if not scans:
                logger.warning("No scan data avalible")
                return
            
            self.stats_canvas.figure.clear()
            ax = self.stats_canvas.figure.add_subplot(111)

            # Подготовка данных
            dates = []
            vulnerability_counts = {"SQL Injection": 0, "XSS": 0, "CSRF": 0}
            date_vulnerability_counts = {}

            for scan in scans:
                date = datetime.strptime(scan['timestamp'], "%Y-%m-%d %H:%M:%S").date()
                dates.append(date)

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
                    for result in results:
                        # Проверяем разные возможные структуры результатов
                        vuln_type = None
                        if isinstance(result, dict):
                            vuln_type = result.get('type') or result.get('vuln_type')
                            # Если нет прямого типа, проверяем в vulnerabilities
                            if not vuln_type and 'vulnerabilities' in result:
                                for vuln_cat, vulns in result['vulnerabilities'].items():
                                    if vulns:  # Если есть уязвимости в этой категории
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

                            if vuln_type and vuln_type in date_vulnerability_counts[date]:
                                date_vulnerability_counts[date][vuln_type] += 1
                elif isinstance(results, dict):
                    # Если результат - это словарь с vulnerabilities
                    if 'vulnerabilities' in results:
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

            # Линейный график по датам
            for vuln_type in vulnerability_counts.keys():
                counts = [date_vulnerability_counts.get(date, {}).get(vuln_type, 0) for date in sorted_dates]
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
            ax = self.stats_canvas.figure.add_subplot(111)
            ax.text(0.5, 0.5, f"Ошибка отображения статистики: {str(e)}", 
                   horizontalalignment='center', verticalalignment='center')
            self.stats_canvas.draw()

    def _refresh_stats_text_only(self, scans):
        """Обновление статистики в текстовом виде (без matplotlib)"""
        if not scans:
            self.stats_text.setText("Нет данных для отображения")
            return

        stats_lines = []
        stats_lines.append("=" * 60)
        stats_lines.append("СТАТИСТИКА СКАНИРОВАНИЙ")
        stats_lines.append("=" * 60)
        stats_lines.append("")

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
                    # Проверяем старую структуру
                    elif result.get('type') or result.get('vuln_type'):
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
                    vuln_type = None
                    if 'vulnerabilities' in result:
                        # Новая структура
                        for vuln_cat, vulns in result['vulnerabilities'].items():
                            if isinstance(vulns, list) and vulns:
                                if vuln_cat == 'sql':
                                    vuln_type = 'SQL Injection'
                                elif vuln_cat == 'xss':
                                    vuln_type = 'XSS'
                                elif vuln_cat == 'csrf':
                                    vuln_type = 'CSRF'
                                break
                    else:
                        # Старая структура
                        vuln_type = result.get('type', 'Unknown')
                    
                    if vuln_type and vuln_type in vuln_by_type:
                        vuln_by_type[vuln_type] += 1
                    
                    # Определяем серьезность
                    if vuln_type and vuln_type in vuln_by_type:
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
    def setup_profile_tab(self):
        layout = QVBoxLayout()

        # Приветствие над аватаром
        self.username_label = QLabel(f"Добро пожаловать, {self.username}!")
        self.username_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.username_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #00ffcc;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(self.username_label)

        # Аватар
        self.avatar_label = QLabel()
        layout.addWidget(self.avatar_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.load_avatar()

        # Кнопка смены аватара
        self.change_avatar_button = QPushButton("Сменить аватар")
        self.change_avatar_button.clicked.connect(self.change_avatar)
        layout.addWidget(self.change_avatar_button)

        # Кнопка редактирования профиля
        self.edit_profile_button = QPushButton("Редактировать учетные данные")
        self.edit_profile_button.clicked.connect(self.edit_profile)
        layout.addWidget(self.edit_profile_button)

        # Кнопка выхода
        self.logout_button = QPushButton("Выйти из аккаунта")
        self.logout_button.clicked.connect(self.logout)
        layout.addWidget(self.logout_button)

        # --- История активности ---
        layout.addWidget(QLabel("История активности:"))
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        layout.addWidget(self.activity_log)

        self.refresh_activity_button = QPushButton("Обновить историю")
        self.refresh_activity_button.clicked.connect(self.refresh_activity_log)
        layout.addWidget(self.refresh_activity_button)

        self.profile_tab.setLayout(layout)

        self.refresh_activity_log()

    def refresh_activity_log(self):
        scans = db.get_scans_by_user(self.user_id)
        if not scans:
            self.activity_log.setText("История активности пуста.")
            return

        log_text = ""
        for scan in scans:
            log_text += f"[{scan['timestamp']}] URL: {scan['url']}\n"
        self.activity_log.setText(log_text)

    def edit_profile(self):
        self.edit_window = EditProfileWindow(self.user_id, self.username, self)
        self.edit_window.show()

    def change_avatar(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите аватар", "", "Image Files (*.png *.jpg *.bmp)")
        if path:
            self.avatar_path = path
            self.load_avatar()
            logger.info(f"User '{self.username}' changed his avatar to: {path}")
            QMessageBox.information(self, "Аватар обновлён", "Ваш аватар успешно обновлён.")

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
            except Exception as e:
                log_and_notify('error', f"Error in logout: {e}")
                # В случае ошибки закрываем текущее окно
                self.close()
        else:
            # Если нет родительского окна, закрываем текущее окно
            self.close()

    def _stop_scan_silent(self):
        """Останавливает текущее сканирование без показа уведомлений (для logout)."""
        try:
            # Останавливаем таймер
            if hasattr(self, '_scan_timer'):
                self._scan_timer.stop()
            
            # Останавливаем сканирование
            self.scan_controller.stop_scan()
            
            # Сбрасываем состояние интерфейса
            self.scan_status.setText("Сканирование остановлено")
            self.scan_progress.setValue(0)
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
                self.pause_button.setText("▶️ Продолжить")
                self.scan_status.setText("Сканирование приостановлено")
                
                # Останавливаем таймер обновления времени
                if hasattr(self, '_scan_timer'):
                    self._scan_timer.stop()
                
                # Приостанавливаем сканирование в контроллере
                self.scan_controller.pause_scan()
                
                # Добавляем запись в лог
                self._add_log_entry("WARNING", "⏸️ Сканирование приостановлено пользователем")
                
                logger.info("Scan paused by user")
                
            else:
                # Возобновляем сканирование
                self._is_paused = False
                self.pause_button.setText("⏸️ Пауза")
                self.scan_status.setText("Сканирование...")
                
                # Возобновляем таймер обновления времени
                if hasattr(self, '_scan_timer'):
                    self._scan_timer.start(1000)
                
                # Возобновляем сканирование в контроллере
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
        self._log_entries.clear()
        self._filtered_log_entries.clear()
        self.detailed_log.clear()
        self.site_tree.clear()
        
        # Сбрасываем статистику
        for key in self.stats_labels:
            self.stats_labels[key].setText("0")

    def export_scan_log(self):
        """Экспортирует лог сканирования"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Сохранить лог сканирования", 
                f"scan_log_{get_local_timestamp().replace(':', '').replace(' ', '_')}.txt",
                "Text Files (*.txt);;HTML Files (*.html);;All Files (*)"
            )
            
            if filename:
                if filename.endswith('.html'):
                    # Экспорт в HTML
                    html_content = "<html><head><title>Лог сканирования</title></head><body>"
                    html_content += "<h1>Лог сканирования</h1>"
                    html_content += f"<p>Дата: {get_local_timestamp()}</p>"
                    html_content += "<hr>"
                    
                    for entry in self._log_entries:
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
                            f.write(f"[{entry['timestamp']}] {entry['level']}: {entry['message']}\n")
                            if entry['url']:
                                f.write(f"  URL: {entry['url']}\n")
                            if entry['details']:
                                f.write(f"  Детали: {entry['details']}\n")
                            f.write("\n")
                
                error_handler.show_info_message("Экспорт", f"Лог успешно экспортирован в файл:\n{filename}")
                
        except Exception as e:
            error_handler.handle_file_error(e, "export_scan_log")
            log_and_notify('error', f"Error exporting scan log: {e}")

    def _add_url_to_tree(self, url: str, url_type: str = "URL", status: str = "Найден"):
        """Добавляет URL в древовидное представление"""
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
        if not hasattr(self, '_scan_timer') or not self._scan_timer.isActive():
            return
        
        # Обновляем счетчик запросов
        if any(keyword in message.lower() for keyword in [
            "запрос", "request", "get request", "post request", 
            "making request", "отправлен запрос", "получен ответ"
        ]):
            self._stats['requests_sent'] += 1
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
                    if forms_found > self._stats['forms_found']:
                        self._stats['forms_found'] = forms_found
                        self._update_stats('forms_found', self._stats['forms_found'])
            
            # Обновляем счетчик просканированных форм
            if "scanned" in message_lower or "просканировано" in message_lower:
                import re
                numbers = re.findall(r'\d+', message)
                if len(numbers) >= 2:
                    forms_scanned = int(numbers[1])  # Второе число обычно просканированные формы
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
            # Увеличиваем счетчик найденных URL
            self._stats['urls_found'] += 1
            self._update_stats('urls_found', self._stats['urls_found'])
        
        # Обновляем счетчики из сообщений о завершении сканирования URL
        if "scanned" in message_lower and "url" in message_lower:
            # Увеличиваем счетчик просканированных URL
            self._stats['urls_scanned'] += 1
            self._update_stats('urls_scanned', self._stats['urls_scanned'])

    # Методы для работы с временем в отчетах
    def _set_time_to_start_of_day(self, datetime_edit):
        """Устанавливает время на начало дня (00:00:00)"""
        current_datetime = datetime_edit.dateTime()
        new_datetime = QDateTime(current_datetime.date(), QTime(0, 0, 0))
        datetime_edit.setDateTime(new_datetime)

    def _set_time_to_midnight(self, datetime_edit):
        """Устанавливает время на полночь (00:00:00)"""
        self._set_time_to_start_of_day(datetime_edit)

    def _set_time_to_end_of_day(self, datetime_edit):
        """Устанавливает время на конец дня (23:59:59)"""
        current_datetime = datetime_edit.dateTime()
        new_datetime = QDateTime(current_datetime.date(), QTime(23, 59, 59))
        datetime_edit.setDateTime(new_datetime)

    def _set_time_to_now(self, datetime_edit):
        """Устанавливает время на текущий момент"""
        datetime_edit.setDateTime(QDateTime.currentDateTime())

    def load_scanner_log_to_ui(self, full: bool = False):
        """
        Загружает scanner.log в детальный лог UI.
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
                self.log_status_label.setText("Файл лога отсутствует.")
                return

            if full:
                self.log_status_label.setText("Идет загрузка полного лога...")
                QApplication.processEvents() # Обновляем UI
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    log_content = f.read()
                self.log_status_label.setText(f"Полный лог загружен ({len(log_content.splitlines())} строк).")
            else:
                log_content = self._read_log_tail(log_path, lines=500)
                self.log_status_label.setText("Отображены последние 500 строк.")

            # Очищаем старые записи и добавляем новые
            self.detailed_log.clear()
            self._log_entries.clear()
            
            # Добавляем новые записи, чтобы фильтры работали
            for line in log_content.splitlines():
                if not line.strip():  # Пропускаем пустые строки
                    continue
                    
                # Простая эвристика для разбора уровня лога
                level = "INFO" # По умолчанию
                if "ERROR" in line: level = "ERROR"
                elif "WARNING" in line: level = "WARNING"
                elif "DEBUG" in line: level = "DEBUG"
                elif "VULNERABILITY" in line: level = "VULNERABILITY"
                
                try:
                    self._add_log_entry(level, line)
                except Exception as e:
                    logger.warning(f"Failed to add log entry: {e}")
                    continue
                
        except Exception as e:
            log_and_notify('error', f"Failed to load scanner.log: {e}")
            if hasattr(self, '_on_scan_log'):
                self._on_scan_log(f"Ошибка загрузки scanner.log: {e}")
            if hasattr(self, 'log_status_label'):
                self.log_status_label.setText("Ошибка загрузки лога.")

    def _read_log_tail(self, filepath: str, lines: int = 500, buffer_size: int = 4096) -> str:
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
            self.concurrent_spinbox.setValue(self.concurrent_spinbox.maximum())
            self.concurrent_spinbox.setEnabled(False)
            self.timeout_spinbox.setValue(self.timeout_spinbox.minimum())
            self.timeout_spinbox.setEnabled(False)
            # Отключаем подробный лог (оставляем только WARNING/ERROR)
            from utils.logger import set_log_level
            set_log_level('scanner', 'WARNING')
            set_log_level('scan_controller', 'WARNING')
            set_log_level('main', 'WARNING')
            set_log_level('performance', 'WARNING')
        else:
            self.concurrent_spinbox.setEnabled(True)
            self.timeout_spinbox.setEnabled(True)
            self.concurrent_spinbox.setValue(10)
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
            if hasattr(self, '_scan_timer'):
                self._scan_timer.stop()
            
            # Останавливаем сканирование
            self.scan_controller.stop_scan()
            
            # Сбрасываем состояние интерфейса
            self.scan_status.setText("Сканирование остановлено")
            self.scan_progress.setValue(0)
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
            if hasattr(self, '_stats'):
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
