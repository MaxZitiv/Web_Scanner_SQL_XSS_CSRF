import os
import asyncio
import inspect
from datetime import datetime
from typing import Dict, List, Any, Optional, Self, cast, Coroutine, Awaitable
from types import CoroutineType
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                         QPushButton, QLineEdit, QCheckBox,
                         QTabWidget, QSpinBox, QMessageBox,
                         QComboBox, QGroupBox, QDialog, QDialogButtonBox, QApplication,
                         QFormLayout, QTextEdit, QProgressBar)

# Импортируем константы из QMessageBox
StandardButton = QMessageBox.StandardButton
StandardButtons = QMessageBox.StandardButtons

# Контроллеры и утилиты
from controllers.scan_controller import ScanController
from utils import error_handler
from utils.database import db
from utils.logger import logger
from utils.security import is_safe_url
from utils.qt_utils import SignalWrapper

# Представления и компоненты
from views.edit_profile_window import EditProfileWindow
from views.dialogs import PolicyEditDialog, ScanSettingsDialog
from views.tabs.profile_tab import ProfileTabWidget
from views.tabs.reports_tab import ReportsTabWidget
from views.tabs.scan_tab import ScanTabWidget
from views.tabs.stats_tab import StatsTabWidget

# Менеджеры и миксины
from views.managers.scan_manager import ScanManagerStatsMixin
from views.mixins.export_mixin import ExportMixin
from views.mixins.scan_mixin import ScanMixin
from views.mixins.log_mixin import LogMixin
from views.mixins.log_processor_mixin import LogProcessorMixin

# Импорт matplotlib с обработкой ошибок
try:
    import matplotlib
    matplotlib.use('Qt5Agg')
    # Используем правильный импорт для matplotlib
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    matplotlib_available = True
except ImportError as e:
    logger.warning(f"matplotlib not available: {e}")
    matplotlib_available = False
    FigureCanvas = None
    Figure = None

# Для обратной совместимости создаем константу
# MATPLOTLIB_AVAILABLE = matplotlib_available  # Закомментировано, чтобы избежать предупреждения о переопределении константы

from qasync import asyncSlot  # type: ignore  # Игнорируем отсутствие stub-файлов для qasync
import importlib
import policies.policy_manager
importlib.reload(policies.policy_manager)
from policies.policy_manager import PolicyManager


class DashboardWindowBase:
    """Базовый класс для DashboardWindow, содержащий общую функциональность"""

    def init_stats_manager(self):
        """Инициализация менеджера статистики
        
        Базовая реализация, которая может быть переопределена в миксинах.
        """
        # Базовая реализация - ничего не делаем
        pass

    def _init_scan_attributes(self):
        """Инициализация атрибутов для сканирования
        
        Базовая реализация, которая может быть переопределена в миксинах.
        """
        # Базовая реализация - ничего не делаем
        pass

    def load_avatar(self):
        """Загрузка аватара пользователя
        
        Базовая реализация, которая может быть переопределена в миксинах.
        """
        # Базовая реализация - ничего не делаем
        pass

    def _process_scan_results(self, results: Dict[str, Any]) -> None:
        """Обработка результатов сканирования."""
        vulnerabilities = results.get("vulnerabilities", [])

        if not vulnerabilities:
            QMessageBox.information(None, "Результаты сканирования", "Уязвимости не обнаружены")
            return

        # Формируем сообщение с результатами
        message = f"Обнаружено уязвимостей: {len(vulnerabilities)}\n\n"

        # Группируем по типам
        by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(vuln)

        # Добавляем информацию по каждому типу
        for vuln_type, vulns in by_type.items():
            message += f"{vuln_type}: {len(vulns)}\n"

        QMessageBox.information(None, "Результаты сканирования", message)

        # Обновляем вкладку сканирования, если она существует
        if hasattr(self, 'scan_tab') and self.scan_tab is not None:
            self.scan_tab.add_scan_results(results)

    async def _start_scan_async(self) -> None:
        """Асинхронный метод для выполнения сканирования."""
        scan_progress_attr = None
        scan_url: Optional[str] = None
        try:
            # Получаем URL для сканирования
            url_input_attr = getattr(self, 'url_input', None)
            if not isinstance(url_input_attr, QLineEdit):
                QMessageBox.warning(None, "Ошибка", "Компонент для ввода URL не найден")
                return

            scan_url = url_input_attr.text().strip()
                
            if not scan_url:
                QMessageBox.warning(None, "Предупреждение", "Пожалуйста, введите URL для сканирования")
                return

            if not is_safe_url(scan_url):
                QMessageBox.warning(None, "Предупреждение", "Введенный URL небезопасен")
                return
                
            logger.info(f"Starting scan for URL: {scan_url}")

            # Определение типа сканирования
            scan_type_combo_attr = getattr(self, 'scan_type_combo', None)
            if not isinstance(scan_type_combo_attr, QComboBox):
                QMessageBox.warning(None, "Ошибка", "Компонент выбора типа сканирования не найден")
                return

            scan_type_text: str = scan_type_combo_attr.currentText()
            scan_types: list[str] = []

            if scan_type_text == "SQL-инъекции":
                scan_types = ["sql"]
            elif scan_type_text == "XSS":
                scan_types = ["xss"]
            elif scan_type_text == "CSRF":
                scan_types = ["csrf"]
            else:  # "Все"
                scan_types = ["sql", "xss", "csrf"]

            # Показываем индикатор прогресса
            scan_progress_attr = getattr(self, 'scan_progress', None)
            if isinstance(scan_progress_attr, QProgressBar):
                scan_progress_attr.setVisible(True)
                scan_progress_attr.setRange(0, 0)  # Неопределенный прогресс

            # Запускаем асинхронное сканирование
            await self._run_scan(scan_url, scan_types)

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            QMessageBox.critical(None, "Ошибка", f"Ошибка во время сканирования: {e}")
        finally:
            # Скрываем индикатор прогресса в любом случае
            if isinstance(scan_progress_attr, QProgressBar):
                scan_progress_attr.setVisible(False)

    async def _run_scan(self, url: str, scan_types: List[str]) -> None:
        """Запуск сканирования в асинхронном режиме"""
        try:
            # Создаем контроллер сканирования
            controller_params: Dict[str, Any] = {
                'url': url,
                'scan_types': scan_types,
                'user_id': self.user_id,
                'max_depth': 2,
                'max_concurrent': 5,
                'timeout': 30
            }

            # Фильтруем только те параметры, которые поддерживает конструктор
            sig = inspect.signature(ScanController.__init__)
            valid_params = {k: v for k, v in controller_params.items() if k in sig.parameters}

            controller = ScanController(**valid_params)

            # Запускаем сканирование
            scan_results: Any = await controller.scan()

            # Обрабатываем результаты
            if isinstance(scan_results, dict):
                typed_results: Dict[str, Any] = scan_results
                self._process_scan_results(typed_results)
            else:
                logger.warning(f"Scan results are not in expected format: {type(scan_results)}")

            # Обновляем статистику
            update_stats_method = getattr(self, 'update_scan_stats', None)
            if update_stats_method is not None and callable(update_stats_method):
                update_stats_method()
            else:
                logger.warning("update_scan_stats method not found or not callable")

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            QMessageBox.critical(None, "Ошибка", f"Произошла ошибка при сканировании: {e}")
        finally:
            # Скрываем индикатор прогресса
            scan_progress_attr = getattr(self, 'scan_progress', None)
            if isinstance(scan_progress_attr, QProgressBar):
                scan_progress_attr.setVisible(False)

    def _init_attributes(self):
        """Инициализация атрибутов класса"""
        # Системные атрибуты
        self._log_loader_thread = None
        self.edit_window = None
        self._visible_rows_timer = None
        self._filtered_scans_data = None
        self._scan_timer = None
        self.user_id = None

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

        # Сигналы будут инициализированы в дочернем классе

    def _finalize_initialization(self):
        """Завершение инициализации компонентов"""
        try:
            # Инициализация вкладок
            self.initialize_tabs()

            # Инициализация stats_canvas
            self.stats_canvas = None
            if matplotlib_available and FigureCanvas is not None and Figure is not None:
                try:
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
            QMessageBox.critical(None, "Error", f"Failed to initialize dashboard window: {init_error}")
            raise

    def initialize_tabs(self) -> None:
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

                if self.user_id is not None:
                    # Cast self to QWidget for type checker
                    widget_self: QWidget = self  # type: ignore
                    self.scan_tab = ScanTabWidget(self.user_id, widget_self)
                    self.reports_tab = ReportsTabWidget(self.user_id, widget_self)
                    self.stats_tab = StatsTabWidget(self.user_id, widget_self)
                    self.profile_tab = ProfileTabWidget(self.user_id, widget_self)
                else:
                    logger.error("Cannot initialize tabs: user_id is None")
                    return

                # Добавление вкладок
                self.tabs.addTab(self.scan_tab, "Сканирование")
                self.tabs.addTab(self.reports_tab, "Отчеты")
                self.tabs.addTab(self.stats_tab, "Статистика")
                self.tabs.addTab(self.profile_tab, "Профиль")

                self.tabs_initialized = True
                logger.info("Tabs initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing tabs: {e}")
            QMessageBox.critical(None, "Error", f"Failed to initialize tabs: {e}")


class DashboardWindowUI(DashboardWindowBase):
    """Класс для управления UI компонентами DashboardWindow"""

    def open_edit_profile(self) -> None:
        """Открытие окна редактирования профиля"""
        # Будет реализовано в DashboardWindowHandlers
        pass

    def logout(self) -> None:
        """Обработка выхода из системы"""
        # Будет реализовано в DashboardWindowHandlers
        pass

    @asyncSlot()
    async def start_scan(self, *, url: Optional[str] = None) -> None:
        """Начало сканирования
        
        Args:
            url: URL для сканирования. Если не указан, берется из поля ввода.
        """
        pass

    @pyqtSlot()
    def on_scan_button_clicked(self) -> None:
        """Handle scan button click by starting the scan asynchronously."""
        asyncio.create_task(self._start_scan_async())

    def init_components(self):
        """Инициализация компонентов интерфейса"""
        # Основной макет
        self.main_layout = QVBoxLayout()
        
        # Инициализация атрибутов пользователя
        self.username = ""

        # Верхняя панель с информацией о пользователе
        self._init_user_panel()

        # Панель сканирования
        self._init_scan_panel()

        # Область для вкладок
        self.tabs_container = QWidget()
        self.tabs_layout = QVBoxLayout()
        self.tabs_container.setLayout(self.tabs_layout)
        self.main_layout.addWidget(self.tabs_container)

    def _init_user_panel(self):
        """Инициализация панели пользователя"""
        user_panel = QWidget()
        user_layout = QHBoxLayout()
        user_panel.setLayout(user_layout)

        # Аватар
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(64, 64)
        self.avatar_label.setScaledContents(True)
        self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        user_layout.addWidget(self.avatar_label)

        # Информация о пользователе
        user_info_layout = QVBoxLayout()
        self.username_label = QLabel(self.username)
        self.username_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        user_info_layout.addWidget(self.username_label)

        # Роль пользователя
        self.user_role_label = QLabel("Scanner")
        user_info_layout.addWidget(self.user_role_label)

        user_layout.addLayout(user_info_layout)
        user_layout.addStretch()

        # Кнопки действий
        actions_layout = QHBoxLayout()

        # Кнопка редактирования профиля
        edit_profile_btn = QPushButton("Редактировать профиль")
        edit_profile_btn.clicked.connect(self.open_edit_profile)
        actions_layout.addWidget(edit_profile_btn)

        # Кнопка выхода
        logout_btn = QPushButton("Выход")
        logout_btn.clicked.connect(self.logout)
        actions_layout.addWidget(logout_btn)

        user_layout.addLayout(actions_layout)
        self.main_layout.addWidget(user_panel)

    def _init_scan_panel(self):
        """Инициализация панели сканирования"""
        scan_panel = QGroupBox("Быстрое сканирование")
        scan_layout = QHBoxLayout()
        scan_panel.setLayout(scan_layout)

        # Поле для URL
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Введите URL для сканирования...")
        scan_layout.addWidget(self.url_input)

        # Выбор типа сканирования
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["SQL-инъекции", "XSS", "CSRF", "Все"])
        scan_layout.addWidget(self.scan_type_combo)

        # Кнопка запуска сканирования
        self.scan_button = QPushButton("Начать сканирование")
        scan_layout.addWidget(self.scan_button)

        # Индикатор прогресса
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        scan_layout.addWidget(self.scan_progress)

        self.main_layout.addWidget(scan_panel)

    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        self.init_components()

        # Подключение обработчиков событий
        if hasattr(self, 'scan_button'):
            self.scan_button.clicked.connect(self.on_scan_button_clicked)

        # Применение стилей
        self._apply_styles()

    def _apply_styles(self):
        """Применение стилей к компонентам"""
        self.styleSheet = """
            QWidget {
                background-color: #f5f5f5;
                font-family: Arial, sans-serif;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #4a86e8;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 5px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3a76d8;
            }
            QPushButton:pressed {
                background-color: #2a66c8;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #cccccc;
                border-radius: 3px;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                padding: 8px 15px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #4a86e8;
                color: white;
            }
        """


class DashboardWindowHandlers:
    """Класс для обработки событий DashboardWindow"""

    def __init__(self):
        """Инициализация атрибутов обработчика"""
        self.user_id = None
        self.user_model = None
        self.username = None
        self.edit_window = None
        self.scan_tab = None

    def open_edit_profile(self) -> None:
        """Открытие окна редактирования профиля"""
        try:
            if self.edit_window is None or not self.edit_window.isVisible():
                self.edit_window = EditProfileWindow(self.user_id, self.user_model, self)
                self.edit_window.show()
            else:
                self.edit_window.raise_()
                self.edit_window.activateWindow()
            logger.info(f"Opened edit profile window for user {self.username}")
        except Exception as e:
            logger.error(f"Error opening edit profile window: {e}")
            QMessageBox.critical(None, "Ошибка", f"Не удалось открыть окно редактирования профиля: {e}")

    def logout(self) -> None:
        """Обработка выхода из системы"""
        try:
            buttons = QMessageBox.StandardButtons()
            buttons |= QMessageBox.StandardButton.Yes
            buttons |= QMessageBox.StandardButton.No
            reply = QMessageBox.question(
                None, 'Подтверждение',
                'Вы уверены, что хотите выйти?',
                buttons,
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                # Закрываем все дочерние окна
                if self.edit_window:
                    self.edit_window.close()

                # Логируем выход
                logger.info(f"User {self.username} logged out")
                
                # Отправляем сигнал о выходе
                # Явно указываем типы для Pylance
                parent: Any = getattr(self, 'parent', lambda: None)()
                if parent is not None:
                    parent_widget: QWidget = parent
                    if hasattr(parent_widget, 'logout'):
                        # Явно указываем тип метода logout для Pylance
                        logout_method: Any = getattr(parent_widget, 'logout')
                        if callable(logout_method):
                            logout_method()
                elif hasattr(self, 'close'):
                    # Явно указываем тип метода close для Pylance
                    close_method: Any = getattr(self, 'close')
                    if callable(close_method):
                        close_method()
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            QMessageBox.critical(None, "Ошибка", f"Ошибка при выходе из системы: {e}")

    @pyqtSlot()
    def on_scan_button_clicked(self) -> None:
        """Handle scan button click by starting the scan asynchronously."""
        asyncio.create_task(self._start_scan_async())

    async def _start_scan_async(self) -> None:
        """Асинхронный метод для выполнения сканирования."""
        scan_progress_attr = None
        scan_url: Optional[str] = None
        try:
            # Получаем URL для сканирования
            url_input_attr = getattr(self, 'url_input', None)
            if not isinstance(url_input_attr, QLineEdit):
                QMessageBox.warning(None, "Ошибка", "Компонент для ввода URL не найден")
                return

            scan_url = url_input_attr.text().strip()
                
            if not scan_url:
                QMessageBox.warning(None, "Предупреждение", "Пожалуйста, введите URL для сканирования")
                return

            if not is_safe_url(scan_url):
                QMessageBox.warning(None, "Предупреждение", "Введенный URL небезопасен")
                return
                
            logger.info(f"Starting scan for URL: {scan_url}")

            # Определение типа сканирования
            scan_type_combo_attr = getattr(self, 'scan_type_combo', None)
            if not isinstance(scan_type_combo_attr, QComboBox):
                QMessageBox.warning(None, "Ошибка", "Компонент выбора типа сканирования не найден")
                return

            scan_type_text: str = scan_type_combo_attr.currentText()
            scan_types: list[str] = []

            if scan_type_text == "SQL-инъекции":
                scan_types = ["sql"]
            elif scan_type_text == "XSS":
                scan_types = ["xss"]
            elif scan_type_text == "CSRF":
                scan_types = ["csrf"]
            else:  # "Все"
                scan_types = ["sql", "xss", "csrf"]

            # Показываем индикатор прогресса
            scan_progress_attr = getattr(self, 'scan_progress', None)
            if isinstance(scan_progress_attr, QProgressBar):
                scan_progress_attr.setVisible(True)
                scan_progress_attr.setRange(0, 0)  # Неопределенный прогресс

            # Запускаем асинхронное сканирование
            await self._run_scan(scan_url, scan_types)

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            QMessageBox.critical(None, "Ошибка", f"Ошибка во время сканирования: {e}")
        finally:
            # Скрываем индикатор прогресса в любом случае
            if isinstance(scan_progress_attr, QProgressBar):
                scan_progress_attr.setVisible(False)
                
            if not scan_url:
                QMessageBox.warning(None, "Предупреждение", "Пожалуйста, введите URL для сканирования")
                return

            if not is_safe_url(scan_url):
                QMessageBox.warning(None, "Предупреждение", "Введенный URL небезопасен")
                return
                
            logger.info(f"Starting scan for URL: {scan_url}")


    @asyncSlot()
    async def _run_scan(self, url: str, scan_types: List[str]) -> None:
        """Запуск сканирования в асинхронном режиме"""
        try:
            # Создаем контроллер сканирования
            controller_params: Dict[str, Any] = {
                'url': url,
                'scan_types': scan_types,
                'user_id': self.user_id,
                'max_depth': 2,
                'max_concurrent': 5,
                'timeout': 30
            }

            # Фильтруем только те параметры, которые поддерживает конструктор
            sig = inspect.signature(ScanController.__init__)
            valid_params = {k: v for k, v in controller_params.items() if k in sig.parameters}

            controller = ScanController(**valid_params)

            # Запускаем сканирование
            # Явно указываем типы для Pylance
            scan_method = getattr(controller, 'scan', None)
            if scan_method is None:
                logger.error("Scan method not found in controller")
                return

            # Вызываем метод сканирования и получаем результаты
            scan_results: Any = await scan_method()
            # Явно указываем тип для результатов
            results: Dict[str, Any] = {}
            # Явно указываем тип для результатов
            if isinstance(scan_results, dict):
                # Явное приведение типа для Pylance
                results = cast(Dict[str, Any], scan_results)
            else:
                # Если результаты не в формате словаря, создаем пустой словарь
                results = {}
                logger.warning(f"Scan results are not in expected format: {type(scan_results)}")

            # Обрабатываем результаты
            # Явно указываем тип для Pylance
            typed_results: Dict[str, Any] = results
            self._process_scan_results(typed_results)

            # Обновляем статистику
            # Явно указываем тип метода для Pylance
            update_stats_method = getattr(self, 'update_scan_stats', None)
            if update_stats_method is not None and callable(update_stats_method):
                update_stats_method()
            else:
                logger.warning("update_scan_stats method not found or not callable")

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            QMessageBox.critical(None, "Ошибка", f"Произошла ошибка при сканировании: {e}")
        finally:
            # Скрываем индикатор прогресса
            # Явно указываем типы для Pylance
            scan_progress_attr = getattr(self, 'scan_progress', None)
            if scan_progress_attr is not None:
                scan_progress: QProgressBar = scan_progress_attr
                scan_progress.setVisible(False)

    def _process_scan_results(self, results: Dict[str, Any]) -> None:
        """Обработка результатов сканирования"""
        vulnerabilities = results.get("vulnerabilities", [])

        if not vulnerabilities:
            QMessageBox.information(None, "Результаты сканирования", "Уязвимости не обнаружены")
            return

        # Формируем сообщение с результатами
        message = f"Обнаружено уязвимостей: {len(vulnerabilities)}\n\n"

        # Группируем по типам
        by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(vuln)

        # Добавляем информацию по каждому типу
        for vuln_type, vulns in by_type.items():
            message += f"{vuln_type}: {len(vulns)}\n"

        QMessageBox.information(None, "Результаты сканирования", message)

        # Обновляем вкладку сканирования, если она существует
        if self.scan_tab:
            self.scan_tab.add_scan_results(results)


class DashboardWindow(QWidget, DashboardWindowUI, DashboardWindowHandlers,
                    ScanManagerStatsMixin, ExportMixin, ScanMixin, LogMixin, LogProcessorMixin):
    """
    Основное окно приложения - панель управления сканером
    Объединяет функциональность из нескольких классов-миксинов
    """

    # Сигналы
    scan_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    _log_loaded_signal = pyqtSignal(str, int)
    _scan_result_signal = pyqtSignal(dict)

    @property
    def user_id(self) -> int:
        """Получить ID пользователя."""
        return self._user_id

    @user_id.setter
    def user_id(self, value: int) -> None:
        """Установить ID пользователя."""
        self._user_id = value

    @property
    def username(self) -> str:
        """Получить имя пользователя."""
        return self._username

    @username.setter
    def username(self, value: str) -> None:
        """Установить имя пользователя."""
        self._username = value

    @property
    def user_model(self) -> Any:
        """Получить модель пользователя."""
        return self._user_model

    def __init__(self, user_id: int, username: str, user_model: Any, parent: Optional[QWidget] = None) -> None:
        """
        Инициализация окна панели управления
        
        Args:
            user_id: ID пользователя
            username: Имя пользователя
            user_model: Модель данных пользователя
            parent: Родительский виджет
        """
        # Инициализация базового класса QWidget первым
        QWidget.__init__(self, parent)

        # Инициализация основного лейаута
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        
        # Инициализация вкладок
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        self.tabs_initialized = False

        # Сохраняем критичные атрибуты
        self._user_id = user_id  # Используем защищенное имя
        self._username = username
        self._user_model = user_model
        
        # Инициализируем вкладки после установки всех атрибутов
        self.initialize_tabs()

        # Инициализация всех миксинов
        ScanManagerStatsMixin.__init__(self)
        ExportMixin.__init__(self, user_id)
        ScanMixin.__init__(self, user_id)
        LogMixin.__init__(self)
        LogProcessorMixin.__init__(self)

        # Базовые настройки
        self.error_handler = error_handler
        self.setWindowTitle(f"Web Scanner - Control Panel [{username}]")
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

        # Подключение сигналов
        self._log_loaded_signal.connect(self._process_log_content)

        # Инициализация компонентов
        self.init_components()

        # Настройка UI
        self.setup_ui()
        
        if hasattr(self, 'stylesheet'):
            self.setStyleSheet(self.stylesheet)

        # Загрузка политик
        self.load_policies_to_combobox()

        # Инициализация оставшихся компонентов
        self._finalize_initialization()

        logger.info(f"Opened control panel for user '{self.username}' (ID: {self.user_id})")

    def load_policies_to_combobox(self):
        """Загрузка политик в выпадающий список"""
        try:
            policy_manager = PolicyManager()
            policies = policy_manager.get_all_policies()

            if hasattr(self, 'policy_combo') and self.policy_combo:
                self.policy_combo.clear()
                self.policy_combo.addItem("Выберите политику", None)

                for policy in policies:
                    self.policy_combo.addItem(policy['name'], policy['id'])

        except Exception as e:
            logger.error(f"Error loading policies: {e}")

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
                    return

            # Если аватар не найден, используем аватар по умолчанию
            default_avatar = "assets/default_avatar.png"
            if os.path.exists(default_avatar) and hasattr(self, 'avatar_label') and self.avatar_label is not None:
                pixmap = QPixmap(default_avatar)
                self.avatar_label.setPixmap(pixmap)
                self.avatar_path = default_avatar
            elif hasattr(self, 'avatar_label') and self.avatar_label is not None:
                # Если аватар по умолчанию не найден, используем заглушку
                self.avatar_label.setText("👤")
                self.avatar_label.setStyleSheet("font-size: 32px;")

        except Exception as e:
            logger.error(f"Error loading avatar: {e}")
            if hasattr(self, 'avatar_label') and self.avatar_label is not None:
                self.avatar_label.setText("👤")
                self.avatar_label.setStyleSheet("font-size: 32px;")

    def _process_log_content(self, content: str, log_type: int) -> None:
        """
        Обработка загруженного содержимого лога
        :param content: Содержимое лога
        :param log_type: Тип лога (1 - системный, 2 - сканирование)
        """
        # Вызываем метод из миксина
        super()._process_log_content(content, log_type)

    def _update_log_display(self) -> None:
        """Обновление отображения логов"""
        if hasattr(self, 'detailed_log') and self.detailed_log:
            self.detailed_log.clear()
            # Преобразуем словари в строки перед объединением
            log_lines = []
            for entry in self._log_entries:
                # Форматируем каждую запись как [timestamp] [level] message
                timestamp = entry.get('timestamp', '')
                level = entry.get('level', 'INFO')
                message = entry.get('message', '')
                log_lines.append(f"[{timestamp}] [{level}] {message}")
            
            self.detailed_log.append('\n'.join(log_lines))

            # Обновляем статус
            if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                self.log_status_label.setText(f"Загружено записей: {len(self._log_entries)}")

    def update_scan_stats(self):
        """Обновление статистики сканирования"""
        try:
            # Получаем статистику из базы данных
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Общее количество сканирований
            cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (self.user_id,))
            total_scans = cursor.fetchone()[0]

            # Количество сканирований за сегодня
            today = datetime.now().strftime('%Y-%m-%d')
            cursor.execute(
                "SELECT COUNT(*) FROM scans WHERE user_id = ? AND DATE(start_time) = ?",
                (self.user_id, today)
            )
            today_scans = cursor.fetchone()[0]

            # Количество найденных уязвимостей
            cursor.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE user_id = ?",
                (self.user_id,)
            )
            total_vulnerabilities = cursor.fetchone()[0]

            conn.close()

            # Обновляем статистику на вкладке статистики, если она существует
            if self.stats_tab:
                self.stats_tab.update_stats({
                    'total_scans': total_scans,
                    'today_scans': today_scans,
                    'total_vulnerabilities': total_vulnerabilities
                })

        except Exception as e:
            logger.error(f"Error updating scan stats: {e}")


class PolicyEditDialog(QDialog):
    """Диалог редактирования политик безопасности"""

    def __init__(self, policy_id=None, parent=None):
        super().__init__(parent)
        self.policy_id = policy_id
        self.policy_manager = PolicyManager()
        self.setup_ui()

        if policy_id:
            self.load_policy_data()

    def setup_ui(self):
        """Настройка интерфейса диалога"""
        self.setWindowTitle("Редактирование политики безопасности")
        self.setMinimumWidth(500)

        layout = QVBoxLayout()
        self.setLayout(layout)

        # Форма редактирования
        form_layout = QFormLayout()
        layout.addLayout(form_layout)

        # Название политики
        self.name_edit = QLineEdit()
        form_layout.addRow("Название:", self.name_edit)

        # Описание политики
        self.description_edit = QTextEdit()
        self.description_edit.setMaximumHeight(100)
        form_layout.addRow("Описание:", self.description_edit)

        # Настройки политики
        policy_group = QGroupBox("Настройки политики")
        policy_layout = QFormLayout()
        policy_group.setLayout(policy_layout)
        layout.addWidget(policy_group)

        # Максимальная глубина сканирования
        self.max_depth_spin = QSpinBox()
        self.max_depth_spin.setRange(1, 10)
        self.max_depth_spin.setValue(3)
        policy_layout.addRow("Максимальная глубина:", self.max_depth_spin)

        # Максимальное количество потоков
        self.max_threads_spin = QSpinBox()
        self.max_threads_spin.setRange(1, 20)
        self.max_threads_spin.setValue(5)
        policy_layout.addRow("Макс. потоков:", self.max_threads_spin)

        # Таймаут
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix(" сек")
        policy_layout.addRow("Таймаут:", self.timeout_spin)

        # Типы сканирования
        self.sql_check = QCheckBox("SQL-инъекции")
        self.sql_check.setChecked(True)
        self.xss_check = QCheckBox("XSS")
        self.xss_check.setChecked(True)
        self.csrf_check = QCheckBox("CSRF")
        self.csrf_check.setChecked(True)

        scan_types_layout = QHBoxLayout()
        scan_types_layout.addWidget(self.sql_check)
        scan_types_layout.addWidget(self.xss_check)
        scan_types_layout.addWidget(self.csrf_check)

        policy_layout.addRow("Типы сканирования:", scan_types_layout)

        # Кнопки
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save_policy)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def load_policy_data(self):
        """Загрузка данных политики для редактирования"""
        try:
            # Проверяем, что policy_id не равен None
            if self.policy_id is None:
                return
                
            policy = self.policy_manager.get_policy(self.policy_id)
            if policy:
                self.name_edit.setText(policy.get('name', ''))
                self.description_edit.setText(policy.get('description', ''))

                # Загрузка настроек
                settings = policy.get('settings', {})
                self.max_depth_spin.setValue(settings.get('max_depth', 3))
                self.max_threads_spin.setValue(settings.get('max_threads', 5))
                self.timeout_spin.setValue(settings.get('timeout', 30))

                # Загрузка типов сканирования
                scan_types = settings.get('scan_types', ['sql', 'xss', 'csrf'])
                self.sql_check.setChecked('sql' in scan_types)
                self.xss_check.setChecked('xss' in scan_types)
                self.csrf_check.setChecked('csrf' in scan_types)

        except Exception as e:
            logger.error(f"Error loading policy data: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить данные политики: {e}")

    def save_policy(self):
        """Сохранение политики"""
        try:
            # Валидация данных
            name = self.name_edit.text().strip()
            if not name:
                QMessageBox.warning(self, "Предупреждение", "Название политики не может быть пустым")
                return

            # Формирование данных политики
            policy_data = {
                'name': name,
                'description': self.description_edit.toPlainText(),
                'settings': {
                    'max_depth': self.max_depth_spin.value(),
                    'max_threads': self.max_threads_spin.value(),
                    'timeout': self.timeout_spin.value(),
                    'scan_types': []
                }
            }

            # Определение выбранных типов сканирования
            if self.sql_check.isChecked():
                policy_data['settings']['scan_types'].append('sql')
            if self.xss_check.isChecked():
                policy_data['settings']['scan_types'].append('xss')
            if self.csrf_check.isChecked():
                policy_data['settings']['scan_types'].append('csrf')

            # Сохранение политики
            if self.policy_id:
                self.policy_manager.update_policy(self.policy_id, policy_data)
            else:
                self.policy_manager.create_policy(policy_data)

            self.accept()

        except Exception as e:
            logger.error(f"Error saving policy: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить политику: {e}")
