"""
Полный класс DashboardWindow для веб-сканера уязвимостей
views/dashboard_window_optimized.py
"""

import asyncio
from typing import Optional, Dict, Any, TypeVar, List, Callable, cast
from PyQt6.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
        QCheckBox, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit,
        QLabel, QMessageBox
    )
from PyQt6.QtWidgets import QMessageBox
from PyQt6.QtGui import (
    QFont, QColor
)

from models.user_model import UserModel
from controllers.scan_controller import ScanController
from views.statistics_widget import StatisticsWidget
from utils.logger import logger
from utils.security import is_safe_url, validate_input_length
from utils.error_handler import error_handler
from utils.vulnerability_info import extract_location_from_details

# Сканирование всегда выполняется полностью.
FULL_SCAN_MAX_DEPTH = 10
SCAN_CONCURRENCY = 5

T = TypeVar('T')

# Определяем константы для кнопок
Yes = QMessageBox.StandardButton.Yes
No = QMessageBox.StandardButton.No

class DashboardWindow(QMainWindow):
    """Главное окно дашборда для пользователя"""

    def __init__(self, user_id: int, username: str, user_model: UserModel,
                 parent: Optional[QMainWindow] = None):
        """
        Инициализация окна дашборда

        Args:
            user_id: ID пользователя
            username: Имя пользователя
            user_model: Модель пользователя
            parent: Родительское окно
        """
        super().__init__(parent)

        self.user_id = user_id
        self.username = username
        self.user_model = user_model
        self.scan_controller: Optional[ScanController] = None
        self.current_scan_task: Optional[asyncio.Task[None]] = None
        self.is_scanning = False

        logger.info(f"Инициализация DashboardWindow для пользователя {username} (ID: {user_id})")

        try:
            # ===== ОСНОВНЫЕ ПАРАМЕТРЫ ОКНА =====
            self.setWindowTitle(f"Web Scanner - {username}")
            self.setGeometry(100, 100, 1400, 950)

            # Центральный виджет
            central_widget = QWidget()
            self.setCentralWidget(central_widget)

            # Главный layout
            main_layout = QVBoxLayout()
            main_layout.setSpacing(10)
            main_layout.setContentsMargins(10, 10, 10, 10)

            # ===== ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ =====
            profile_layout = QHBoxLayout()

            profile_label = QLabel(f"👤 Пользователь: {username}")
            profile_font = QFont()
            profile_font.setPointSize(10)
            profile_label.setFont(profile_font)
            profile_layout.addWidget(profile_label)

            profile_layout.addStretch()

            # Кнопка профиля
            profile_btn = QPushButton("👤 Профиль")
            profile_btn.setMaximumWidth(100)
            cast(Any, profile_btn.clicked).connect(self.on_profile)
            profile_layout.addWidget(profile_btn)

            # Кнопка статистики
            statistics_btn = QPushButton("📊 Статистика")
            statistics_btn.setMaximumWidth(100)
            cast(Any, statistics_btn.clicked).connect(self.on_statistics)
            profile_layout.addWidget(statistics_btn)

            # Кнопка отчетов
            reports_btn = QPushButton("📋 Отчеты")
            reports_btn.setMaximumWidth(100)
            cast(Any, reports_btn.clicked).connect(self.on_reports)
            profile_layout.addWidget(reports_btn)

            logout_btn = QPushButton("🚪 Выход")
            logout_btn.setMaximumWidth(100)
            cast(Any, logout_btn.clicked).connect(self.on_logout)
            profile_layout.addWidget(logout_btn)

            main_layout.addLayout(profile_layout)

            # ===== СТРОКА ВВОДА URL И ОПЦИЙ =====
            scan_options_layout = QHBoxLayout()

            # URL
            url_label = QLabel("🔗 URL:")
            scan_options_layout.addWidget(url_label)

            self.url_input = QLineEdit()
            self.url_input.setPlaceholderText("Введите URL (https://example.com)")
            scan_options_layout.addWidget(self.url_input)

            # Сканирование выполняется всегда полностью: глубина и параллельность
            # не настраиваются пользователем (см. FULL_SCAN_MAX_DEPTH/SCAN_CONCURRENCY).
            full_scan_hint = QLabel("🔎 Сканирование выполняется полностью")
            scan_options_layout.addWidget(full_scan_hint)
            scan_options_layout.addStretch()

            main_layout.addLayout(scan_options_layout)

            # ===== ТИПЫ СКАНИРОВАНИЯ =====
            scan_types_layout = QHBoxLayout()

            types_label = QLabel("🔍 Типы сканирования:")
            types_font = QFont()
            types_font.setBold(True)
            types_label.setFont(types_font)
            scan_types_layout.addWidget(types_label)

            self.sql_checkbox = QCheckBox("SQL Injection")
            self.sql_checkbox.setChecked(True)
            scan_types_layout.addWidget(self.sql_checkbox)

            self.xss_checkbox = QCheckBox("XSS")
            self.xss_checkbox.setChecked(True)
            scan_types_layout.addWidget(self.xss_checkbox)

            self.csrf_checkbox = QCheckBox("CSRF")
            self.csrf_checkbox.setChecked(True)
            scan_types_layout.addWidget(self.csrf_checkbox)

            scan_types_layout.addStretch()
            main_layout.addLayout(scan_types_layout)

            # ===== КНОПКИ УПРАВЛЕНИЯ СКАНИРОВАНИЕМ =====
            buttons_layout = QHBoxLayout()
            buttons_layout.setSpacing(5)

            self.start_scan_btn = QPushButton("▶ Начать сканирование")
            self.start_scan_btn.setMinimumHeight(35)
            self.start_scan_btn.setStyleSheet("""
                QPushButton {
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    font-weight: bold;
                    padding: 5px;
                }
                QPushButton:hover {
                    background-color: #45a049;
                }
                QPushButton:pressed {
                    background-color: #3d8b40;
                }
            """)
            cast(Any, self.start_scan_btn.clicked).connect(lambda: self._start_scan_wrapper())
            buttons_layout.addWidget(self.start_scan_btn)

            self.pause_scan_btn = QPushButton("⏸ Пауза")
            self.pause_scan_btn.setMinimumHeight(35)
            cast(Any, self.pause_scan_btn.clicked).connect(self.on_pause_scan)
            self.pause_scan_btn.setEnabled(False)
            buttons_layout.addWidget(self.pause_scan_btn)

            self.resume_scan_btn = QPushButton("▶ Продолжить")
            self.resume_scan_btn.setMinimumHeight(35)
            cast(Any, self.resume_scan_btn.clicked).connect(self.on_resume_scan)
            self.resume_scan_btn.setEnabled(False)
            buttons_layout.addWidget(self.resume_scan_btn)

            self.stop_scan_btn = QPushButton("⏹ Остановить")
            self.stop_scan_btn.setMinimumHeight(35)
            self.stop_scan_btn.setStyleSheet("""
                QPushButton {
                    background-color: #f44336;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    font-weight: bold;
                    padding: 5px;
                }
                QPushButton:hover {
                    background-color: #da190b;
                }
                QPushButton:pressed {
                    background-color: #ba0000;
                }
            """)
            cast(Any, self.stop_scan_btn.clicked).connect(self.on_stop_scan)
            self.stop_scan_btn.setEnabled(False)
            buttons_layout.addWidget(self.stop_scan_btn)

            main_layout.addLayout(buttons_layout)

            # ===== СОЗДАЁМ ВИДЖЕТ СТАТИСТИКИ =====
            try:
                self.statistics_widget = StatisticsWidget()
                main_layout.addWidget(self.statistics_widget)
                logger.info("StatisticsWidget успешно создан")
            except Exception as stats_error:
                logger.error(f"Ошибка при создании StatisticsWidget: {stats_error}")
                self.statistics_widget = None

            # ===== ТАБЛИЦА РЕЗУЛЬТАТОВ =====
            results_label = QLabel("📋 Найденные уязвимости:")
            results_font = QFont()
            results_font.setBold(True)
            results_font.setPointSize(10)
            results_label.setFont(results_font)
            main_layout.addWidget(results_label)

            self.results_table = QTableWidget()
            self.results_table.setColumnCount(5)
            cast(Any, self.results_table).setHorizontalHeaderLabels([
                "Тип уязвимости",
                "URL",
                "Место в коде",
                "Серьёзность",
                "Время обнаружения"
            ])
            header = self.results_table.horizontalHeader()
            if header is not None:
                header.setStretchLastSection(True)
            else:
                logger.warning("Не удалось получить заголовок таблицы результатов")

            # Настройка таблицы
            self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.results_table.setMinimumHeight(150)
            self.results_table.setAlternatingRowColors(True)

            # Устанавливаем ширину колонок
            self.results_table.resizeColumnsToContents()
            main_layout.addWidget(self.results_table)

            # ===== ЛОГ СОБЫТИЯ =====
            log_label = QLabel("📝 Лог событий:")
            log_font = QFont()
            log_font.setBold(True)
            log_font.setPointSize(10)
            log_label.setFont(log_font)
            main_layout.addWidget(log_label)

            self.log_text = QTextEdit()
            self.log_text.setReadOnly(True)
            self.log_text.setMaximumHeight(120)
            self.log_text.setStyleSheet("""
                QTextEdit {
                    background-color: #f5f5f5;
                    border: 1px solid #cccccc;
                    border-radius: 3px;
                    font-family: Courier;
                    font-size: 9pt;
                }
            """)
            main_layout.addWidget(self.log_text)

            # ===== УСТАНАВЛИВАЕМ MAIN LAYOUT =====
            central_widget.setLayout(main_layout)

            # ===== ПРИМЕНЯЕМ СТИЛИ =====
            self.apply_styles()

            logger.info(f"DashboardWindow инициализирован успешно для пользователя {username}")

        except Exception as e:
            error_msg = f"Критическая ошибка при инициализации DashboardWindow: {e}"
            logger.error(error_msg, exc_info=True)
            error_handler.show_error_message("Критическая ошибка", error_msg)
            raise

    def apply_styles(self):
        """Применяет стили к окну"""
        try:
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #ffffff;
                }
                QLabel {
                    color: #333333;
                }
                QLineEdit {
                    border: 1px solid #cccccc;
                    border-radius: 3px;
                    padding: 5px;
                    background-color: #fafafa;
                }
                QLineEdit:focus {
                    border: 2px solid #4CAF50;
                    background-color: #ffffff;
                }
                QSpinBox {
                    border: 1px solid #cccccc;
                    border-radius: 3px;
                    padding: 3px;
                }
                QCheckBox {
                    color: #333333;
                    spacing: 5px;
                }
                QTableWidget {
                    background-color: #ffffff;
                    alternate-background-color: #f9f9f9;
                    border: 1px solid #cccccc;
                    gridline-color: #e0e0e0;
                }
                QTableWidget::item:selected {
                    background-color: #4CAF50;
                }
                QHeaderView::section {
                    background-color: #f0f0f0;
                    padding: 5px;
                    border: 1px solid #cccccc;
                    font-weight: bold;
                }
            """)
        except Exception as e:
            logger.error(f"Ошибка при применении стилей: {e}")

    def on_profile(self):
        """Открывает окно редактирования профиля"""
        try:
            from views.edit_profile_window import EditProfileWindow
            profile_window = EditProfileWindow(self.user_id, self.username, self)
            profile_window.exec()
        except Exception as e:
            logger.error(f"Ошибка при открытии окна профиля: {e}")
            error_handler.show_error_message("Ошибка", f"Не удалось открыть окно профиля: {str(e)}")

    def on_statistics(self):
        """Открывает окно статистики"""
        try:
            from views.statistics_window import StatisticsWindow

            statistics_window = getattr(self, 'statistics_window', None)
            if statistics_window is None:
                statistics_window = StatisticsWindow(self.user_id, self)
                self.statistics_window = statistics_window

            statistics_window.show()
            statistics_window.raise_()
            statistics_window.activateWindow()
        except Exception as e:
            logger.error(f"Ошибка при открытии статистики: {e}")
            error_handler.show_error_message("Ошибка", f"Не удалось открыть статистику: {str(e)}")

    def on_reports(self):
        """Открывает окно отчетов"""
        try:
            # Получаем данные из таблицы результатов
            reports_data: List[Dict[str, str]] = []
            for row in range(self.results_table.rowCount()):
                # Проверяем каждый item на None
                type_item = self.results_table.item(row, 0)
                url_item = self.results_table.item(row, 1)
                param_item = self.results_table.item(row, 2)
                severity_item = self.results_table.item(row, 3)
                time_item = self.results_table.item(row, 4)

                # Создаем отчет только если все ячейки существуют
                if all([type_item, url_item, param_item, severity_item, time_item]):
                    report_item = {
                        "Тип уязвимости": type_item.text() if type_item else "",
                        "URL": url_item.text() if url_item else "",
                        "Параметр": param_item.text() if param_item else "",
                        "Серьёзность": severity_item.text() if severity_item else "",
                        "Время обнаружения": time_item.text() if time_item else ""
                    }
                    reports_data.append(report_item)

            if not reports_data:
                error_handler.show_info_message("Информация", "Нет данных для отчета. Сначала выполните сканирование.")
                return

            # Создаем окно отчетов
            from utils.export_utils import ExportUtils

            # Пользователь выбирает формат отчёта: JSON, CSV, PDF, HTML или TXT
            selected_format = self._select_report_format()
            if selected_format is None:
                return

            format_name, file_extension = selected_format
            success = ExportUtils.export_data(
                self,
                reports_data,
                format_name,
                file_extension,
                self.user_id
            )

            if not success:
                error_handler.show_error_message("Ошибка", "Не удалось создать отчет")
        except Exception as e:
            logger.error(f"Ошибка при создании отчета: {e}")
            error_handler.show_error_message("Ошибка", f"Не удалось создать отчет: {str(e)}")

    def _select_report_format(self) -> Optional[tuple[str, str]]:
        """Показывает диалог выбора формата отчёта.

        Returns:
            Кортеж (название формата, расширение файла) или None при отмене.
        """
        try:
            formats = ["JSON", "CSV", "PDF", "HTML", "TXT"]
            extensions = {
                "JSON": "json",
                "CSV": "csv",
                "PDF": "pdf",
                "HTML": "html",
                "TXT": "txt",
            }

            dialog = QMessageBox(self)
            dialog.setWindowTitle("Формат отчёта")
            dialog.setText("Выберите формат сохранения:")
            dialog.setIcon(QMessageBox.Icon.Question)
            for option in formats:
                cast(Any, dialog.addButton)(
                    option, QMessageBox.ButtonRole.AcceptRole
                )
            cast(Any, dialog.addButton)(
                "Отмена", QMessageBox.ButtonRole.RejectRole
            )
            dialog.exec()

            clicked = dialog.clickedButton()
            if clicked is None:
                return None
            selected = clicked.text() if hasattr(clicked, "text") else ""
            if selected not in extensions:
                return None
            return selected, extensions[selected]
        except Exception as e:
            logger.error(f"Ошибка при выборе формата отчёта: {e}")
            return None

    def scroll_to_widget(self, widget: QWidget) -> None:
        """Прокручивает к указанному виджету"""
        try:
            # Ищем родительский виджет с прокруткой
            parent_obj = widget.parent()
            while parent_obj is not None:
                # Проверяем, что parent_obj является QWidget
                if isinstance(parent_obj, QWidget) and hasattr(parent_obj, "verticalScrollBar"):
                    parent_widget = parent_obj
                    try:
                        # Явно указываем тип возвращаемого значения
                        scroll_bar = self.log_text.verticalScrollBar()
                        if scroll_bar is not None:
                            widget_pos = widget.mapTo(parent_widget, widget.rect().topLeft()).y()
                            scroll_bar.setValue(int(widget_pos))
                            return
                    except Exception as e:
                        logger.error(f"Ошибка при установке позиции прокрутки: {e}")
                parent_obj = parent_obj.parent()
        except Exception as e:
            logger.error(f"Ошибка при прокрутке к виджету: {e}")

    # Остальные методы остаются без изменений...
    def _start_scan_wrapper(self):
        """Обертка для вызова асинхронного метода on_start_scan"""
        asyncio.create_task(self.on_start_scan())
    async def on_start_scan(self):
        """
        Начинает сканирование сайта.
        Валидирует входные данные, создает ScanController и запускает асинхронное сканирование.
        """
        try:
            # ===== ВАЛИДАЦИЯ ДАННЫХ =====

            # Получаем URL и удаляем пробелы
            url = self.url_input.text().strip()

            # Проверяем, что URL не пустой
            if not url:
                error_handler.show_error_message(
                    "Ошибка",
                    "Пожалуйста, введите URL для сканирования"
                )
                logger.warning("Попытка начать сканирование без URL")
                return

            # Добавляем протокол если его нет
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                self.url_input.setText(url)
                logger.info(f"Добавлен протокол HTTPS. URL: {url}")

            # Валидируем длину URL
            if not validate_input_length(url, 1, 2048):
                error_handler.show_error_message(
                    "Ошибка",
                    "URL слишком длинный (максимум 2048 символов). "
                    f"Текущая длина: {len(url)}"
                )
                logger.warning(f"URL слишком длинный: {len(url)} символов")
                return

            # Проверяем безопасность URL
            if not is_safe_url(url):
                logger.warning(f"Предупреждение о безопасности URL: {url}")
                reply: QMessageBox.StandardButton = QMessageBox.question(
                    self,
                    "⚠️ Предупреждение безопасности",
                    "URL может быть небезопасным. Продолжить?\n\n"
                    "Убедитесь, что вы сканируете только свои собственные сайты,\n"
                    "или сайты, на которые у вас есть разрешение.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )

                if reply == QMessageBox.StandardButton.No:
                    logger.info("Сканирование отменено пользователем")
                    return
                logger.info("Пользователь подтвердил сканирование небезопасного URL")

            # ===== ПОЛУЧЕНИЕ ПАРАМЕТРОВ СКАНИРОВАНИЯ =====

            # Собираем типы сканирования
            scan_types: List[str] = []

            if self.sql_checkbox.isChecked():
                scan_types.append("sql")

            if self.xss_checkbox.isChecked():
                scan_types.append("xss")

            if self.csrf_checkbox.isChecked():
                scan_types.append("csrf")

            # Проверяем, что выбран хотя бы один тип
            if not scan_types:
                error_handler.show_error_message(
                    "Ошибка",
                    "Выберите хотя бы один тип сканирования:"
                    "• SQL Injection\n"
                    "• XSS\n"
                    "• CSRF"
                )
                logger.warning("Попытка начать сканирование без типов")
                return

            logger.info(f"Выбранные типы сканирования: {', '.join(scan_types)}")

            # Параметры полного сканирования. Глубина и параллельность больше
            # не настраиваются пользователем — сайт сканируется целиком.
            max_depth = FULL_SCAN_MAX_DEPTH
            max_concurrent = SCAN_CONCURRENCY
            logger.info("Полное сканирование: без ограничения глубины")

            # ===== СБРОС ПРЕДЫДУЩИХ ДАННЫХ =====

            # Очищаем таблицу результатов
            self.results_table.setRowCount(0)
            logger.debug("Таблица результатов очищена")

            # Очищаем лог
            self.log_text.clear()
            logger.debug("Лог событий очищен")

            # Сбрасываем статистику
            self.reset_scan_stats()
            logger.info("Статистика сброшена")

            # ===== СОЗДАНИЕ SCAN CONTROLLER =====

            try:
                self.scan_controller = ScanController(
                    url=url,
                    scan_types=scan_types,
                    user_id=self.user_id,
                    max_depth=max_depth,
                    max_concurrent=max_concurrent,
                    timeout=30,
                    username=self.username
                )
                logger.info(f"ScanController создан для URL: {url}")
            except Exception as controller_error:
                logger.error(f"Ошибка при создании ScanController: {controller_error}")
                error_handler.show_error_message(
                    "Ошибка",
                    f"Ошибка при инициализации сканера: {str(controller_error)}"
                )
                return

            # ===== ПОДКЛЮЧЕНИЕ СИГНАЛОВ =====

            try:
                self.connect_scan_signals()
                logger.info("Сигналы ScanController подключены успешно")
            except Exception as signals_error:
                logger.error(f"Ошибка при подключении сигналов: {signals_error}")
                error_handler.show_error_message(
                    "Ошибка",
                    f"Ошибка при подключении сигналов: {str(signals_error)}"
                )
                return

            # ===== ОБНОВЛЕНИЕ UI =====

            # Устанавливаем флаг сканирования
            self.is_scanning = True

            # Отключаем кнопку "Начать"
            self.start_scan_btn.setEnabled(False)
            # Включаем кнопки управления
            self.pause_scan_btn.setEnabled(True)
            self.resume_scan_btn.setEnabled(False)
            self.stop_scan_btn.setEnabled(True)

            # Отключаем поля ввода (нельзя менять параметры во время сканирования)
            self.url_input.setEnabled(False)
            self.sql_checkbox.setEnabled(False)
            self.xss_checkbox.setEnabled(False)
            self.csrf_checkbox.setEnabled(False)

            logger.info("UI обновлен для начала сканирования")

            # ===== ЛОГИРОВАНИЕ И УВЕДОМЛЕНИЕ =====

            # Добавляем начальное сообщение в лог
            self.log_text.append("=" * 70)
            self.log_text.append(f"🚀 НАЧИНАЕМ СКАНИРОВАНИЕ")
            self.log_text.append("=" * 70)
            self.log_text.append(f"📍 URL: {url}")
            self.log_text.append(f"🔍 Типы сканирования: {', '.join(scan_types)}")
            self.log_text.append(f"👤 Пользователь: {self.username}")
            self.log_text.append(f"🕐 Время начала: {self._get_current_time()}")
            self.log_text.append("=" * 70)
            self.log_text.append("")

            # Прокручиваем лог к началу
            try:
                scroll_bar = self.log_text.verticalScrollBar()
                if scroll_bar is not None:
                    scroll_bar.setValue(0)
            except AttributeError:
                logger.warning("verticalScrollBar() не доступен для log_text")

            # ===== ЗАПУСК АСИНХРОННОГО СКАНИРОВАНИЯ =====

            try:
                # Получаем event loop. Python 3.14 предпочитает get_running_loop().
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    # Если нет запущенного цикла, создаем новый
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                async def scan_task():
                    try:
                        if self.scan_controller is None:
                            raise RuntimeError("ScanController должен быть инициализирован")
                        await self.scan_controller.start_scan(
                            url=url,
                            scan_types=scan_types,
                            max_depth=max_depth,
                            max_concurrent=max_concurrent,
                            on_log=self.on_log_event,
                            on_result=self.on_scan_complete
                        )
                    finally:
                        self._restore_scan_controls()

                self.current_scan_task = loop.create_task(scan_task())

                logger.info("Асинхронная задача сканирования создана и запущена")
                self.log_text.append("✅ Сканирование инициализировано")

            except Exception as task_error:
                logger.error(f"Ошибка при создании асинхронной задачи: {task_error}")
                error_handler.show_error_message(
                    "Ошибка",
                    f"Ошибка при запуске сканирования: {str(task_error)}"
                )

                # Восстанавливаем UI при ошибке
                self.is_scanning = False
                self.start_scan_btn.setEnabled(True)
                self.pause_scan_btn.setEnabled(False)
                self.stop_scan_btn.setEnabled(False)
                self.url_input.setEnabled(True)
                self.sql_checkbox.setEnabled(True)
                self.xss_checkbox.setEnabled(True)
                self.csrf_checkbox.setEnabled(True)

                self.log_text.append("❌ Ошибка при запуске сканирования")
                return

        except Exception as e:
            # Обработка неожиданных ошибок
            logger.error(f"Неожиданная ошибка в on_start_scan: {e}", exc_info=True)
            error_handler.show_error_message(
                "Критическая ошибка",
                f"Неожиданная ошибка: {str(e)}"
                f"Проверьте логи для деталей"
            )

            # Пытаемся восстановить UI
            try:
                self.is_scanning = False
                self.start_scan_btn.setEnabled(True)
                self.pause_scan_btn.setEnabled(False)
                self.stop_scan_btn.setEnabled(False)
                self.url_input.setEnabled(True)
                self.sql_checkbox.setEnabled(True)
                self.xss_checkbox.setEnabled(True)
                self.csrf_checkbox.setEnabled(True)
            except Exception as recovery_error:
                logger.error(f"Ошибка при восстановлении UI: {recovery_error}")

    def _get_current_time(self):
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")

    def on_pause_scan(self):
        """Приостанавливает сканирование"""
        try:
            if self.scan_controller:
                self.scan_controller.pause_scan()
                self.pause_scan_btn.setEnabled(False)
                self.resume_scan_btn.setEnabled(True)
                self.log_text.append("⏸ Сканирование приостановлено")
                logger.info("Сканирование приостановлено пользователем")
        except Exception as e:
            logger.error(f"Ошибка при приостановке сканирования: {e}")
            error_handler.show_error_message("Ошибка", f"Ошибка при приостановке: {str(e)}")

    def on_resume_scan(self):
        """Возобновляет сканирование"""
        try:
            if self.scan_controller:
                self.scan_controller.resume_scan()
                self.pause_scan_btn.setEnabled(True)
                self.resume_scan_btn.setEnabled(False)
                self.log_text.append("▶ Сканирование возобновлено")
                logger.info("Сканирование возобновлено пользователем")
        except Exception as e:
            logger.error(f"Ошибка при возобновлении сканирования: {e}")
            error_handler.show_error_message("Ошибка", f"Ошибка при возобновлении: {str(e)}")

    def on_stop_scan(self):
        """Останавливает сканирование"""
        try:
            reply = QMessageBox.question(
                self,
                "Подтверждение",
                "Вы уверены, что хотите остановить сканирование?",
                QMessageBox.StandardButton(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No),
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                if self.scan_controller:
                    self.scan_controller.stop_scan()
                    self.is_scanning = False
                    self.start_scan_btn.setEnabled(True)
                    self.pause_scan_btn.setEnabled(False)
                    self.resume_scan_btn.setEnabled(False)
                    self.stop_scan_btn.setEnabled(False)
                    self.url_input.setEnabled(True)
                    self.log_text.append("⏹ Сканирование остановлено пользователем")
                    logger.info("Сканирование остановлено пользователем")
        except Exception as e:
            logger.error(f"Ошибка при остановке сканирования: {e}")
            error_handler.show_error_message("Ошибка", f"Ошибка при остановке: {str(e)}")

    def connect_scan_signals(self):
        """Подключает сигналы от ScanController к UI"""
        try:
            if self.scan_controller is None:
                logger.warning("ScanController не инициализирован")
                return

            if not hasattr(self.scan_controller, 'signals'):
                logger.warning("ScanController не имеет сигналов")
                return

            # Подключаем сигналы статистики
            if self.statistics_widget is not None:
                cast(Any, self.scan_controller.signals.stats_updated).connect(
                    self.on_stats_updated
                )
                # Используем лямбда-функцию для обновления прогресса в главном потоке
                progress_handler: Callable[[Any], None] = lambda progress: (
                    self.update_progress_in_main_thread(progress)
                )
                cast(Any, self.scan_controller.signals.progress_updated).connect(progress_handler)
                logger.info("Сигналы статистики подключены успешно")
            else:
                logger.warning("StatisticsWidget не инициализирован, сигналы не подключены")

            # Подключаем другие сигналы
            cast(Any, self.scan_controller.signals.log_event).connect(self.on_log_event)
            cast(Any, self.scan_controller.signals.vulnerability_found).connect(
                self.on_vulnerability_found
            )

        except Exception as e:
            logger.error(f"Ошибка при подключении сигналов: {e}")
    def update_progress_in_main_thread(self, progress: int) -> None:
        """Обновляет прогресс-бар в главном потоке GUI"""
        try:
            if self.statistics_widget is not None:
                # Вызываем метод напрямую, так как мы уже в главном потоке GUI
                self.statistics_widget.update_progress(progress)
        except Exception as e:
            logger.error(f"Ошибка при обновлении прогресса: {e}")

    def on_stats_updated(self, stat_name: str, value: object) -> None:
        """
        Обработчик обновления статистики из ScanWorker

        Args:
            stat_name: Название счётчика статистики (urls_found, forms_scanned и т.д.)
            value: Значение счётчика (может быть int или str)
        """
        try:
            # Проверяем что statistics_widget инициализирован
            if self.statistics_widget is None:
                logger.debug(f"statistics_widget is None, пропускаем обновление {stat_name}")
                return

            # Логируем полученное значение для отладки
            logger.debug(f"Получено обновление статистики: {stat_name} = {value} (тип: {type(value).__name__})")

            # Обрабатываем разные типы значений
            if stat_name == 'scan_time':
                # Время передаётся как строка (HH:MM:SS)
                try:
                    time_str = str(value) if value is not None else "00:00:00"
                    self.statistics_widget.update_stat_string(stat_name, time_str)
                    logger.debug(f"Обновлено время сканирования: {time_str}")
                except Exception as time_error:
                    logger.error(f"Ошибка при обновлении времени: {time_error}")
                    self.statistics_widget.update_stat_string(stat_name, "00:00:00")

            else:
                # Все остальные счётчики - целые числа
                try:
                    # Преобразуем значение в int
                    if value is None:
                        value_int = 0
                    elif isinstance(value, int):
                        value_int = value
                    elif isinstance(value, str):
                        # Пытаемся преобразовать строку в int
                        value_int = int(value)
                    elif isinstance(value, float):
                        # Преобразуем float в int
                        value_int = int(value)
                    else:
                        # Пытаемся преобразовать через str
                        try:
                            value_int = int(str(value))
                        except (ValueError, TypeError):
                            logger.warning(f"Не удалось преобразовать {stat_name} = {value} в int, используем 0")
                            value_int = 0

                    # Гарантируем что значение в допустимом диапазоне
                    if value_int < 0:
                        logger.warning(f"Отрицательное значение для {stat_name}: {value_int}, устанавливаем 0")
                        value_int = 0

                    # Обновляем в UI напрямую, без использования QMetaObject.invokeMethod
                    self.statistics_widget.update_stat(stat_name, value_int)
                    logger.debug(f"Обновлена статистика {stat_name}: {value_int}")

                except (ValueError, TypeError) as conv_error:
                    logger.error(f"Ошибка преобразования {stat_name} со значением {value}: {conv_error}")
                    # Используем 0 при ошибке
                    try:
                        self.statistics_widget.update_stat(stat_name, 0)
                    except Exception as fallback_error:
                        logger.error(f"Ошибка при установке значения 0: {fallback_error}")

                except AttributeError as attr_error:
                    logger.error(f"Метод обновления для {stat_name} недоступен: {attr_error}")

        except Exception as e:
            logger.error(f"Критическая ошибка в on_stats_updated для {stat_name}: {e}", exc_info=True)
    def on_log_event(self, message: str):
        """Обработчик событий логирования"""
        try:
            if not hasattr(self, 'log_text'):
                logger.warning("log_text не инициализирован")
                return

            # Добавляем сообщение в лог
            self.log_text.append(message)
            logger.debug(f"Добавлено в лог: {message}")

            # Прокручиваем к последнему сообщению
            try:
                scroll_bar = self.log_text.verticalScrollBar()

                if scroll_bar is not None:
                    max_value = scroll_bar.maximum()
                    scroll_bar.setValue(max_value)
                else:
                    logger.warning("verticalScrollBar() вернул None для log_text")
            except AttributeError as attr_error:
                logger.warning(f"ScrollBar атрибут не найден: {attr_error}")
            except Exception as scroll_error:
                logger.debug(f"Ошибка при прокрутке логов: {scroll_error}")
        except Exception as e:
            logger.error(f"Ошибка при логировании события: {e}")
    def on_vulnerability_found(self, url: str, vulnerability_type: str, details: str):
        """Обработчик нахождения уязвимости"""
        try:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)

            # Определяем цвет по типу уязвимости
            if vulnerability_type.lower() == 'sql':
                color = QColor("#ffcccc")
            elif vulnerability_type.lower() == 'xss':
                color = QColor("#ffffcc")
            else:  # CSRF
                color = QColor("#ccffcc")

            # Заполняем ячейки
            type_item = QTableWidgetItem(vulnerability_type)
            type_item.setBackground(color)
            self.results_table.setItem(row, 0, type_item)

            url_item = QTableWidgetItem(url)
            url_item.setBackground(color)
            self.results_table.setItem(row, 1, url_item)

            # В отдельной колонке показываем точное место: параметр/поле/метод/форму.
            location = extract_location_from_details(str(details)) or str(details)
            location_item = QTableWidgetItem(location)
            location_item.setBackground(color)
            location_item.setToolTip(str(details))
            self.results_table.setItem(row, 2, location_item)

            severity_item = QTableWidgetItem("Высокая")
            severity_item.setBackground(color)
            self.results_table.setItem(row, 3, severity_item)

            from utils.performance import get_local_timestamp
            time_item = QTableWidgetItem(get_local_timestamp())
            time_item.setBackground(color)
            self.results_table.setItem(row, 4, time_item)

            logger.info(f"Найдена уязвимость: {vulnerability_type} на {url}")

        except Exception as e:
            logger.error(f"Ошибка при добавлении уязвимости в таблицу: {e}")
    def _restore_scan_controls(self) -> None:
        """Возвращает элементы управления сканированием в исходное состояние."""
        try:
            self.is_scanning = False
            self.start_scan_btn.setEnabled(True)
            self.pause_scan_btn.setEnabled(False)
            self.resume_scan_btn.setEnabled(False)
            self.stop_scan_btn.setEnabled(False)
            self.url_input.setEnabled(True)
            self.sql_checkbox.setEnabled(True)
            self.xss_checkbox.setEnabled(True)
            self.csrf_checkbox.setEnabled(True)
        except Exception as e:
            logger.error(f"Ошибка при восстановлении элементов управления: {e}")

    def on_scan_complete(self, result: Dict[str, Any]):
        """Обработчик завершения сканирования"""
        try:
            self.is_scanning = False
            self.start_scan_btn.setEnabled(True)
            self.pause_scan_btn.setEnabled(False)
            self.resume_scan_btn.setEnabled(False)
            self.stop_scan_btn.setEnabled(False)
            self.url_input.setEnabled(True)

            # Выводим результаты
            total_vulns = result.get('total_vulnerabilities', 0)
            total_urls = result.get('total_urls_scanned', 0)
            scan_duration = result.get('scan_duration', 0)

            self.log_text.append(f"✅ Сканирование завершено!")
            self.log_text.append(f"📊 Результаты:")
            self.log_text.append(f"  • Просканировано URL: {total_urls}")
            self.log_text.append(f"  • Найдено уязвимостей: {total_vulns}")
            self.log_text.append(f"  • Время сканирования: {scan_duration:.2f}s")

            logger.info(f"Сканирование завершено. Найдено уязвимостей: {total_vulns}")

        except Exception as e:
            logger.error(f"Ошибка при завершении сканирования: {e}")

    def reset_scan_stats(self) -> None:
        """Сбрасывает статистику при новом сканировании"""
        try:
            if self.statistics_widget is not None:
                self.statistics_widget.reset_stats()
                logger.info("Статистика сброшена")
        except Exception as e:
            logger.error(f"Ошибка при сбросе статистики: {e}")

    def on_logout(self):
        try:
            reply = QMessageBox.question(
                self,
                "Подтверждение",
                "Вы уверены, что хотите выйти из системы?",
                QMessageBox.StandardButton(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No),
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                parent = self.parent()
                if parent is not None and isinstance(parent, QMainWindow):
                    parent.close()
                else:
                    self.close()
        except Exception as e:
            logger.error(f"Ошибка при выходе из системы: {e}")
            error_handler.show_error_message("Ошибка", f"Ошибка при выходе: {str(e)}")
