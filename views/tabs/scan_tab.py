from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox,
    QLineEdit, QCheckBox, QSpinBox, QPushButton, QTreeWidget,
    QTextEdit, QComboBox,
    QSplitter, QTableWidget, 
    QHeaderView, QScrollArea, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt
from controllers.scan_controller import ScanController
from utils.logger import logger
from utils.error_handler import error_handler
from utils.performance import get_local_timestamp
from qasync import asyncSlot
from views.tabs.scan_tab_optimized import ScanTabStatsMixin

class ScanTabWidget(ScanTabStatsMixin, QWidget):
    def __init__(self, user_id, parent=None):
        # Инициализация родительского класса QWidget
        QWidget.__init__(self, parent)

        # Инициализация миксина
        ScanTabStatsMixin.__init__(self, parent)

        self.user_id = user_id
        self.scan_controller = ScanController(user_id)
        self._scan_start_time = None
        self._total_urls = 0
        self._completed_urls = 0
        self._total_progress = 0
        self._active_workers = 0
        self._worker_progress = {}
        self._is_paused = False
        self._log_entries = []
        self._filtered_log_entries = []
        self._current_filter = "Все"
        self._search_text = ""
        self._stats = {
            'urls_found': 0,
            'urls_scanned': 0,
            'forms_found': 0,
            'forms_scanned': 0,
            'vulnerabilities': 0,
            'requests_sent': 0,
            'errors': 0,
        }
        try:
            self.init_components()
            self.init_stats_manager()
            self.setup_ui()
        except Exception as e:
            logger.error(f"Failed to initialize ScanTabWidget: {e}")
            raise

    def init_components(self):
        try:
            # Базовые компоненты
            self.url_input = QLineEdit()
            self.scan_button = QPushButton("Начать сканирование")
            self.results_table = QTableWidget()

            # Чекбоксы для типов уязвимостей
            self.sql_checkbox = QCheckBox("SQL Injection")
            self.xss_checkbox = QCheckBox("XSS")
            self.csrf_checkbox = QCheckBox("CSRF")

            # Компоненты настроек производительности
            self.depth_spinbox = QSpinBox()
            self.concurrent_spinbox = QSpinBox()
            self.timeout_spinbox = QSpinBox()

            # Кнопки управления
            self.pause_button = QPushButton("⏸️ Пауза")
            self.stop_button = QPushButton("Остановить")

            # Компоненты прогресса
            self.scan_status = QLabel()
            # Удален прогресс-бар по требованию пользователя

            # Компоненты лога
            self.site_tree = QTreeWidget()
            self.detailed_log = QTextEdit()
            self.log_filter = QComboBox()
            self.log_search = QLineEdit()
            self.clear_search_button = QPushButton("🗑️")

            # Компоненты статистики
            self.stats_labels = {}

            # Проверка наличия всех необходимых компонентов
            required_components = [
                'url_input', 'scan_button', 'results_table',
                'sql_checkbox', 'xss_checkbox', 'csrf_checkbox',
                'depth_spinbox', 'concurrent_spinbox', 'timeout_spinbox',
                'pause_button', 'stop_button',
                'scan_status',
                'site_tree', 'detailed_log',
                'log_filter', 'log_search', 'clear_search_button',
                'stats_labels'
            ]

            for component in required_components:
                if not hasattr(self, component):
                    raise ValueError(f"Component '{component}' not found in ScanTabWidget")

        except Exception as e:
            logger.error(f"Failed to initialize scan tab components: {e}")
            raise

    @asyncSlot()
    async def on_scan_button_clicked(self):
        """Обработчик нажатия кнопки сканирования"""
        try:
            await self.scan_website_sync()
        except Exception as e:
            logger.error(f"Error creating task: {e}")
            error_handler.handle_error(e)

    def on_scan_button_clicked_wrapper(self):
        """Обертка для запуска асинхронного обработчика кнопки сканирования"""
        # Просто вызываем асинхронный метод, так как @asyncSlot уже обрабатывает его выполнение
        _ = self.on_scan_button_clicked()  # Используем _ для явного игнорирования результата

    def setup_ui(self):
        """Настройка пользовательского интерфейса вкладки сканирования"""
        try:
            # Проверяем, что все компоненты инициализированы
            if not hasattr(self, 'url_input') or self.url_input is None:
                raise ValueError("url_input not initialized")
            if not hasattr(self, 'scan_button') or self.scan_button is None:
                raise ValueError("scan_button not initialized")
            if not hasattr(self, 'results_table') or self.results_table is None:
                raise ValueError("results_table not initialized")

            # Создаем основной контейнер с прокруткой
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)

            # Создаем виджет-контейнер для всего содержимого
            content_widget = QWidget()
            content_widget.setMinimumWidth(700)

            # Устанавливаем layout для контента
            layout = QVBoxLayout(content_widget)

            # 1) Группа для ввода URL
            url_group = QGroupBox("URL для сканирования")
            url_layout = QVBoxLayout()
            self.url_input.setPlaceholderText("Введите URL (например: https://example.com)")
            url_layout.addWidget(self.url_input)
            url_group.setLayout(url_layout)
            layout.addWidget(url_group)

            # 2) Группа для выбора типов уязвимостей
            vuln_group = QGroupBox("Типы уязвимостей")
            vuln_layout = QHBoxLayout()
            self.sql_checkbox = QCheckBox("SQL Injection")
            self.xss_checkbox = QCheckBox("XSS")
            self.csrf_checkbox = QCheckBox("CSRF")
            for cb in (self.sql_checkbox, self.xss_checkbox, self.csrf_checkbox):
                vuln_layout.addWidget(cb)
            vuln_group.setLayout(vuln_layout)
            layout.addWidget(vuln_group)

            # 3) Группа настроек производительности
            perf_group = QGroupBox("Настройки производительности")
            perf_layout = QVBoxLayout()

            # Глубина обхода
            depth_layout = QHBoxLayout()
            depth_layout.addWidget(QLabel("Глубина обхода:"))
            self.depth_spinbox = QSpinBox()
            self.depth_spinbox.setRange(0, 10)
            self.depth_spinbox.setValue(3)
            depth_layout.addWidget(self.depth_spinbox)
            depth_layout.addStretch()
            perf_layout.addLayout(depth_layout)

            # Параллельные запросы
            concurrent_layout = QHBoxLayout()
            concurrent_layout.addWidget(QLabel("Параллельные запросы:"))
            self.concurrent_spinbox = QSpinBox()
            self.concurrent_spinbox.setRange(1, 20)
            self.concurrent_spinbox.setValue(5)
            concurrent_layout.addWidget(self.concurrent_spinbox)
            concurrent_layout.addStretch()
            perf_layout.addLayout(concurrent_layout)

            # Таймаут
            timeout_layout = QHBoxLayout()
            timeout_layout.addWidget(QLabel("Таймаут (сек):"))
            self.timeout_spinbox = QSpinBox()
            self.timeout_spinbox.setRange(5, 60)
            self.timeout_spinbox.setValue(30)
            timeout_layout.addWidget(self.timeout_spinbox)
            timeout_layout.addStretch()
            perf_layout.addLayout(timeout_layout)

            perf_group.setLayout(perf_layout)
            layout.addWidget(perf_group)

            # 4) Группа кнопок управления
            control_group = QGroupBox("Управление")
            control_layout = QHBoxLayout()

            self.scan_button = QPushButton("Начать сканирование")
            self.scan_button.clicked.connect(self.on_scan_button_clicked_wrapper)
            self.pause_button = QPushButton("⏸️ Пауза")
            self.pause_button.clicked.connect(self.pause_scan)
            self.pause_button.setEnabled(False)
            self.stop_button = QPushButton("Остановить")
            self.stop_button.clicked.connect(self.stop_scan)
            self.stop_button.setEnabled(False)

            control_layout.addWidget(self.scan_button)
            control_layout.addWidget(self.pause_button)
            control_layout.addWidget(self.stop_button)
            control_group.setLayout(control_layout)
            layout.addWidget(control_group)

            # 5) Группа статуса сканирования (с прогресс-баром)
            status_group = QGroupBox("Статус")
            status_layout = QVBoxLayout()

            self.scan_status = QLabel("Готов к сканированию")
            self.scan_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            status_layout.addWidget(self.scan_status)

            # Добавляем прогресс-бар
            self.scan_progress = QProgressBar()
            self.scan_progress.setRange(0, 100)
            self.scan_progress.setValue(0)
            self.scan_progress.setTextVisible(True)
            self.scan_progress.setFormat("%p%")
            status_layout.addWidget(self.scan_progress)

            status_group.setLayout(status_layout)
            layout.addWidget(status_group)

            # 6) Группа детального лога сканирования
            log_group = QGroupBox("🔍 Детальный просмотр сканирования")
            log_splitter = QSplitter(Qt.Orientation.Horizontal)

            # Левая панель: Древовидное представление
            left_panel = QWidget()
            left_layout = QVBoxLayout(left_panel)

            tree_header = QLabel("🌐 Структура сайта")
            left_layout.addWidget(tree_header)

            self.site_tree = QTreeWidget()
            self.site_tree.setHeaderLabels(["Ресурс", "Тип", "Статус"])
            left_layout.addWidget(self.site_tree)

            # Статистика в реальном времени
            stats_group = QGroupBox("📊 Статистика")
            stats_layout = QVBoxLayout(stats_group)

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
                value = QLabel(default_value)
                label_layout.addWidget(label)
                label_layout.addWidget(value)
                label_layout.addStretch()
                stats_layout.addLayout(label_layout)
                self.stats_labels[key] = value

            left_layout.addWidget(stats_group)

            # Правая панель: Детальный лог
            right_panel = QWidget()
            right_layout = QVBoxLayout(right_panel)

            log_header = QLabel("📄 Детальный лог")
            right_layout.addWidget(log_header)

            # Фильтры лога
            filter_layout = QHBoxLayout()
            filter_layout.addWidget(QLabel("Фильтр:"))
            self.log_filter = QComboBox()
            self.log_filter.addItems(["Все", "Информация", "Успех", "Предупреждение", "Ошибка"])
            self.log_filter.currentTextChanged.connect(self.filter_log)
            filter_layout.addWidget(self.log_filter)

            filter_layout.addWidget(QLabel("Поиск:"))
            self.log_search = QLineEdit()
            self.log_search.setPlaceholderText("Поиск в логе...")
            self.log_search.textChanged.connect(self.search_log)
            filter_layout.addWidget(self.log_search)

            self.clear_search_button = QPushButton("🗑️")
            self.clear_search_button.clicked.connect(self.clear_search)
            filter_layout.addWidget(self.clear_search_button)

            right_layout.addLayout(filter_layout)

            # Поле детального лога
            self.detailed_log = QTextEdit()
            self.detailed_log.setReadOnly(True)
            right_layout.addWidget(self.detailed_log)

            # Добавляем панели в сплиттер
            log_splitter.addWidget(left_panel)
            log_splitter.addWidget(right_panel)
            log_splitter.setSizes([300, 500])  # Начальные размеры панелей

            log_layout = QVBoxLayout(log_group)
            log_layout.addWidget(log_splitter)

            layout.addWidget(log_group)

            # Устанавливаем виджет с контентом в область прокрутки
            scroll.setWidget(content_widget)

            # Создаем основной layout для вкладки
            main_layout = QVBoxLayout(self)
            main_layout.addWidget(scroll)

            # Инициализируем таблицу результатов
            self.init_results_table()

            logger.debug("Scan tab UI setup completed successfully")

        except Exception as e:
            logger.error(f"Error setting up scan tab UI: {e}")
            raise

    def init_results_table(self):
        """Инициализация таблицы результатов сканирования"""
        try:
            # Проверяем, что таблица инициализирована
            if not hasattr(self, 'results_table') or self.results_table is None:
                raise ValueError("results_table not initialized")

            # Настраиваем таблицу
            self.results_table.setColumnCount(5)
            self.results_table.setHorizontalHeaderLabels(["URL", "Тип уязвимости", "Параметр", "Статус", "Действия"])

            header = self.results_table.horizontalHeader()
            if header is not None:
                header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
                header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)

            self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.results_table.setAlternatingRowColors(True)
            self.results_table.setSortingEnabled(True)

            # Скрываем таблицу по умолчанию
            self.results_table.hide()

        except Exception as e:
            logger.error(f"Error initializing results table: {e}")
            raise

    def filter_log(self, filter_text):
        """Фильтрация записей лога по типу"""
        try:
            self._current_filter = filter_text
            self.update_log_display()
        except Exception as e:
            logger.error(f"Error filtering log: {e}")

    def search_log(self, search_text):
        """Поиск в логе по тексту"""
        try:
            self._search_text = search_text.lower()
            self.update_log_display()
        except Exception as e:
            logger.error(f"Error searching in log: {e}")

    def clear_search(self):
        """Очистка поля поиска и сброс фильтров"""
        try:
            self.log_search.clear()
            self._search_text = ""
            self.log_filter.setCurrentIndex(0)  # "Все"
            self._current_filter = "Все"
            self.update_log_display()
        except Exception as e:
            logger.error(f"Error clearing search: {e}")

    def update_log_display(self):
        """Обновление отображения лога с учетом фильтров и поиска"""
        try:
            # Применяем фильтры
            self._filtered_log_entries = []
            for entry in self._log_entries:
                # Фильтр по типу
                if self._current_filter != "Все" and entry.get('type', '') != self._current_filter:
                    continue

                # Фильтр по тексту поиска
                if self._search_text and self._search_text not in entry.get('message', '').lower():
                    continue

                self._filtered_log_entries.append(entry)

            # Обновляем отображение
            self.detailed_log.clear()
            for entry in self._filtered_log_entries:
                # Форматируем запись
                timestamp = entry.get('timestamp', '')
                message_type = entry.get('type', '')
                message = entry.get('message', '')

                # Определяем цвет в зависимости от типа сообщения
                color = "black"
                if message_type == "Ошибка":
                    color = "red"
                elif message_type == "Предупреждение":
                    color = "orange"
                elif message_type == "Успех":
                    color = "green"
                elif message_type == "Информация":
                    color = "blue"

                # Добавляем отформатированную запись
                formatted_entry = f'<span style="color:{color}">[{timestamp}] {message_type}: {message}</span>'
                self.detailed_log.append(formatted_entry)

        except Exception as e:
            logger.error(f"Error updating log display: {e}")

    def add_log_entry(self, message, message_type="Информация"):
        """Добавление записи в лог"""
        try:
            # Получаем текущую временную метку
            timestamp = get_local_timestamp()

            # Создаем запись
            entry = {
                'timestamp': timestamp,
                'type': message_type,
                'message': message
            }

            # Добавляем в общий список
            self._log_entries.append(entry)

            # Обновляем отображение
            self.update_log_display()

        except Exception as e:
            logger.error(f"Error adding log entry: {e}")

    def pause_scan(self):
        """Приостановка/возобновление сканирования"""
        try:
            self._is_paused = not self._is_paused
            if self._is_paused:
                self.pause_button.setText("▶️ Продолжить")
                self.scan_status.setText("Сканирование приостановлено")
                self.add_log_entry("Сканирование приостановлено пользователем", "Информация")
            else:
                self.pause_button.setText("⏸️ Пауза")
                self.scan_status.setText("Сканирование продолжается")
                self.add_log_entry("Сканирование возобновлено", "Информация")
        except Exception as e:
            logger.error(f"Error pausing/resuming scan: {e}")

    def stop_scan(self):
        """Остановка сканирования"""
        try:
            # Сбрасываем состояние
            self._is_paused = False
            self._scan_start_time = None
            self._total_urls = 0
            self._completed_urls = 0
            self._total_progress = 0
            self._active_workers = 0
            self._worker_progress = {}

            # Обновляем UI
            self.scan_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.pause_button.setText("⏸️ Пауза")
            self.stop_button.setEnabled(False)
            self.scan_status.setText("Сканирование остановлено")
            self.add_log_entry("Сканирование остановлено пользователем", "Информация")

            # Сбрасываем статистику
            self.reset_stats()

        except Exception as e:
            logger.error(f"Error stopping scan: {e}")

    def update_scan_status(self, status):
        """Обновление статуса сканирования"""
        try:
            self.scan_status.setText(status)
        except Exception as e:
            logger.error(f"Error updating scan status: {e}")

    def update_scan_progress(self, progress):
        """Обновление прогресса сканирования"""
        try:
            # Обновляем прогресс-бар
            if hasattr(self, 'scan_progress'):
                self.scan_progress.setValue(int(progress))
        except Exception as e:
            logger.error(f"Error updating scan progress: {e}")

    def update_stats(self, key, value):
        """Обновление статистики"""
        try:
            if key in self._stats:
                self._stats[key] = value
                if key in self.stats_labels:
                    self.stats_labels[key].setText(str(value))
        except Exception as e:
            logger.error(f"Error updating stats: {e}")

    def reset_stats(self):
        """Сброс статистики"""
        try:
            for key in self._stats:
                self._stats[key] = 0
                if key in self.stats_labels:
                    self.stats_labels[key].setText("0")

            # Особый случай для времени сканирования
            if 'scan_time' in self.stats_labels:
                self.stats_labels['scan_time'].setText("00:00:00")
        except Exception as e:
            logger.error(f"Error resetting stats: {e}")

    async def scan_website_sync(self):
        """Синхронная обертка для асинхронного сканирования"""
        try:
            # Получаем URL из поля ввода
            url = self.url_input.text().strip()
            if not url:
                QMessageBox.warning(self, "Ошибка", "Введите URL для сканирования")
                return

            # Проверяем, что выбран хотя бы один тип уязвимостей
            vuln_types = []
            if self.sql_checkbox.isChecked():
                vuln_types.append("sql")
            if self.xss_checkbox.isChecked():
                vuln_types.append("xss")
            if self.csrf_checkbox.isChecked():
                vuln_types.append("csrf")

            if not vuln_types:
                QMessageBox.warning(self, "Ошибка", "Выберите хотя бы один тип уязвимостей для сканирования")
                return

            # Получаем настройки
            depth = self.depth_spinbox.value()
            concurrent = self.concurrent_spinbox.value()
            timeout = self.timeout_spinbox.value()

            # Обновляем UI
            self.scan_button.setEnabled(False)
            self.pause_button.setEnabled(True)
            self.stop_button.setEnabled(True)
            self.pause_button.setText("⏸️ Пауза")
            self.scan_status.setText("Подготовка к сканированию...")
            self.add_log_entry(f"Начало сканирования: {url}", "Информация")
            self.add_log_entry(f"Типы уязвимостей: {', '.join(vuln_types)}", "Информация")
            self.add_log_entry(f"Глубина обхода: {depth}, Параллельных запросов: {concurrent}, Таймаут: {timeout}с", "Информация")

            # Сбрасываем статистику
            self.reset_stats()

            # Запускаем сканирование
            self._scan_start_time = get_local_timestamp()
            await self.scan_controller.start_scan(
                url=url,
                scan_types=vuln_types,
                max_depth=depth,
                max_concurrent=concurrent,
                timeout=timeout,
                on_progress=self.update_scan_progress,
                on_log=self.add_log_entry,
                on_vulnerability=self.update_stats
            )

            # Обновляем UI после завершения
            self.scan_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            self.scan_status.setText("Сканирование завершено")
            self.add_log_entry("Сканирование завершено", "Успех")

        except Exception as e:
            logger.error(f"Error during website scan: {e}")
            self.scan_status.setText("Ошибка при сканировании")
            self.add_log_entry(f"Ошибка при сканировании: {str(e)}", "Ошибка")
            self.scan_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.stop_button.setEnabled(False)
