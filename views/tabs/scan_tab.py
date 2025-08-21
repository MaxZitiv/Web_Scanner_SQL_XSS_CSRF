from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox,
    QLineEdit, QCheckBox, QSpinBox, QPushButton, QTreeWidget,
    QTreeWidgetItem, QProgressBar, QTextEdit, QComboBox,
    QFileDialog, QSplitter
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QColor, QPixmap
from controllers.scan_controller import ScanController
from utils.logger import log_and_notify
from utils.error_handler import error_handler
from utils.performance import get_local_timestamp, extract_time_from_timestamp
import asyncio
from qasync import asyncSlot

class ScanTabWidget(QWidget):
    def __init__(self, user_id, parent=None):
        super().__init__(parent)
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
        self.setup_ui()

    def on_scan_button_clicked(self):
        asyncio.create_task(self.scan_website_sync())

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
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

        # 4) Кнопки управления
        control_group = QGroupBox("Управление")
        control_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Начать сканирование")
        self.scan_button.clicked.connect(self.on_scan_button_clicked)
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

        # 5) Прогресс-бар
        progress_group = QGroupBox("Прогресс")
        progress_layout = QVBoxLayout()
        
        self.scan_status = QLabel("Готов к сканированию")
        self.scan_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_layout.addWidget(self.scan_status)
        
        progress_bar_layout = QHBoxLayout()
        self.scan_progress = QProgressBar()
        self.scan_progress.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_bar_layout.addWidget(self.scan_progress)
        
        self.progress_label = QLabel("0%")
        self.progress_label.setMinimumWidth(50)
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_bar_layout.addWidget(self.progress_label)
        
        progress_layout.addLayout(progress_bar_layout)
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        # 6) Расширенный лог сканирования
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
        
        log_header = QLabel("📋 Детальный лог")
        right_layout.addWidget(log_header)
        
        # Панель фильтров
        filter_panel = QWidget()
        filter_layout = QHBoxLayout(filter_panel)
        
        self.log_filter = QComboBox()
        self.log_filter.addItems(["Все", "DEBUG", "INFO", "WARNING", "ERROR", "VULNERABILITY"])
        filter_layout.addWidget(self.log_filter)
        
        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText("Введите текст для поиска...")
        filter_layout.addWidget(self.log_search)
        
        self.clear_search_button = QPushButton("🗑️")
        self.clear_search_button.clicked.connect(self._clear_search)
        filter_layout.addWidget(self.clear_search_button)
        
        filter_layout.addStretch()
        right_layout.addWidget(filter_panel)
        
        self.detailed_log = QTextEdit()
        self.detailed_log.setReadOnly(True)
        right_layout.addWidget(self.detailed_log)
        
        # Кнопки управления логом
        log_buttons_layout = QHBoxLayout()
        self.clear_log_button = QPushButton("🗑️ Очистить лог")
        self.clear_log_button.clicked.connect(self.clear_scan_log)
        self.export_log_button = QPushButton("📤 Экспорт лога")
        self.export_log_button.clicked.connect(self.export_scan_log)
        self.auto_scroll_checkbox = QCheckBox("Автоскролл")
        self.auto_scroll_checkbox.setChecked(True)
        
        log_buttons_layout.addWidget(self.clear_log_button)
        log_buttons_layout.addWidget(self.export_log_button)
        log_buttons_layout.addWidget(self.auto_scroll_checkbox)
        log_buttons_layout.addStretch()
        
        right_layout.addLayout(log_buttons_layout)
        
        log_splitter.addWidget(left_panel)
        log_splitter.addWidget(right_panel)
        log_splitter.setSizes([400, 600])
        
        log_layout = QVBoxLayout()
        log_layout.addWidget(log_splitter)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

    @asyncSlot()
    async def scan_website_sync(self):
        try:
            await self.scan_website()
        except Exception as e:
            error_handler.handle_validation_error(e, "scan_website_sync")
            log_and_notify('error', f"Error in scan_website_sync: {e}")

    async def scan_website(self):
        url = self.url_input.text().strip()
        
        if not url:
            error_handler.show_error_message("Ошибка", "Введите URL для сканирования")
            return
        
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
        
        max_depth = self.depth_spinbox.value()
        max_concurrent = self.concurrent_spinbox.value()
        timeout = self.timeout_spinbox.value()
        
        await self.start_scan(url, selected_types, max_depth, max_concurrent, timeout)

    async def start_scan(self, url: str, types: list, max_depth: int, max_concurrent: int, timeout: int):
        try:
            self.scan_progress.setValue(0)
            self.scan_status.setText("Подготовка к сканированию...")
            self.scan_button.setEnabled(False)
            self.pause_button.setEnabled(True)
            self.stop_button.setEnabled(True)
            
            self._is_paused = False
            self.pause_button.setText("⏸️ Пауза")
            
            self.site_tree.clear()
            self._log_entries.clear()
            self._filtered_log_entries.clear()
            
            for key in self.stats_labels:
                self.stats_labels[key].setText("0")
            
            await self.scan_controller.start_scan(
                url=url,
                scan_types=types,
                max_depth=max_depth,
                max_concurrent=max_concurrent,
                timeout=timeout,
                on_progress=self._on_scan_progress,
                on_log=self._on_scan_log,
                on_vulnerability=self._on_vulnerability_found,
                on_result=self._on_scan_result
            )
            
        except Exception as e:
            error_handler.handle_network_error(e, "start_scan")
            log_and_notify('error', f"Error in start_scan: {e}")
            self.scan_status.setText("Ошибка запуска сканирования")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def pause_scan(self):
        try:
            if not self._is_paused:
                self._is_paused = True
                self.pause_button.setText("▶️ Продолжить")
                self.scan_status.setText("Сканирование приостановлено")
                self.scan_controller.pause_scan()
                self._add_log_entry("WARNING", "⏸️ Сканирование приостановлено пользователем")
            else:
                self._is_paused = False
                self.pause_button.setText("⏸️ Пауза")
                self.scan_status.setText("Сканирование...")
                self.scan_controller.resume_scan()
                self._add_log_entry("INFO", "▶️ Сканирование возобновлено")
        except Exception as e:
            log_and_notify('error', f"Error pausing/resuming scan: {e}")

    def stop_scan(self):
        try:
            self.scan_controller.stop_scan()
            self.scan_status.setText("Сканирование остановлено")
            self.scan_progress.setValue(0)
            self.progress_label.setText("0%")
            self.scan_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            self._is_paused = False
            self.pause_button.setText("⏸️ Пауза")
            self._add_log_entry("WARNING", "⏹️ Сканирование остановлено пользователем")
        except Exception as e:
            log_and_notify('error', f"Error stopping scan: {e}")

    def clear_scan_log(self):
        self._log_entries.clear()
        self._filtered_log_entries.clear()
        self.detailed_log.clear()
        self.site_tree.clear()
        for key in self.stats_labels:
            self.stats_labels[key].setText("0")

    def export_scan_log(self):
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Сохранить лог сканирования", 
                f"scan_log_{get_local_timestamp().replace(':', '').replace(' ', '_')}.txt",
                "Text Files (*.txt);;HTML Files (*.html);;All Files (*)"
            )
            
            if filename:
                if filename.endswith('.html'):
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

    def _add_log_entry(self, level: str, message: str, url: str = "", details: str = ""):
        timestamp = extract_time_from_timestamp(get_local_timestamp())
        
        color_map = {
            "DEBUG": "#888888",
            "INFO": "#00ff00",
            "WARNING": "#ffff00",
            "ERROR": "#ff0000",
            "VULNERABILITY": "#ff6600"
        }
        
        color = color_map.get(level, "#ffffff")
        
        html_entry = f'<div style="margin: 2px 0;"><span style="color: {color}; font-weight: bold;">[{timestamp}] {level}</span>'
        
        if url:
            html_entry += f' <span style="color: #3498db;">{url}</span>'
        
        html_entry += f' <span style="color: #ffffff;">{message}</span>'
        
        if details:
            html_entry += f'<br><span style="color: #cccccc; margin-left: 20px;">{details}</span>'
        
        html_entry += '</div>'
        
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message,
            'url': url,
            'details': details,
            'html': html_entry
        }
        
        self._log_entries.append(log_entry)
        self._apply_filters()
        self._update_log_display()
        
        if self.auto_scroll_checkbox.isChecked():
            scrollbar = self.detailed_log.verticalScrollBar()
            if scrollbar is not None:
                scrollbar.setValue(scrollbar.maximum())

            

    def _apply_filters(self):
        self._filtered_log_entries = []
        
        for entry in self._log_entries:
            if self._current_filter != "Все" and entry['level'] != self._current_filter:
                continue
            
            if self._search_text:
                search_lower = self._search_text.lower()
                if (search_lower not in entry['message'].lower() and 
                    search_lower not in entry['url'].lower() and
                    search_lower not in entry['details'].lower()):
                    continue
            
            self._filtered_log_entries.append(entry)

    def _update_log_display(self):
        html_content = ""
        for entry in self._filtered_log_entries:
            html_content += entry['html']
        
        self.detailed_log.setHtml(html_content)

    def _clear_search(self):
        self.log_search.clear()
        self._search_text = ""
        self._apply_filters()
        self._update_log_display()

    def _update_stats(self, key: str, value):
        if key in self._stats:
            self._stats[key] = value
            if key in self.stats_labels:
                self.stats_labels[key].setText(str(value))

    def _on_scan_progress(self, progress: int, url: str):
        self.scan_progress.setValue(progress)
        self.progress_label.setText(f"{progress}%")
        
        if url:
            self._add_url_to_tree(url, "URL", "Просканировано")
            self._stats['urls_scanned'] += 1
            self._update_stats('urls_scanned', self._stats['urls_scanned'])
        
        if progress % 10 == 0:
            self._add_log_entry("PROGRESS", f"Прогресс: {progress}%", url)

    def _on_vulnerability_found(self, url: str, vuln_type: str, details: str):
        message = f"Обнаружена уязвимость {vuln_type}"
        self._add_log_entry("VULNERABILITY", message, url, details)
        
        self._stats['vulnerabilities'] += 1
        self._update_stats('vulnerabilities', self._stats['vulnerabilities'])
        
        self._update_url_status(url, "Уязвимость")

    def _update_url_status(self, url: str, status: str):
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
                    if status == "Уязвимость":
                        child.setBackground(2, QColor("#ffcccc"))
                    elif status == "Просканирован":
                        child.setBackground(2, QColor("#ccffcc"))
                    elif status == "Ошибка":
                        child.setBackground(2, QColor("#ffcc99"))
                    break

    def _add_url_to_tree(self, url: str, url_type: str = "URL", status: str = "Найден"):
        domain = url.split('/')[2] if len(url.split('/')) > 2 else url
        
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
        
        url_item = QTreeWidgetItem(root_item)
        url_item.setText(0, url)
        url_item.setText(1, url_type)
        url_item.setText(2, status)

    async def _on_scan_result(self, result: dict):
        self.scan_progress.setValue(100)
        self.progress_label.setText("100%")
        self.scan_status.setText("Сканирование завершено")
        self.scan_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        
        self._is_paused = False
        self.pause_button.setText("⏸️ Пауза")
        
        scan_duration = result.get('scan_duration', 0)
        total_urls = result.get('total_urls_scanned', 0)
        total_vulnerabilities = result.get('total_vulnerabilities', 0)
        
        self._add_log_entry("INFO", f"✅ Сканирование завершено за {scan_duration:.2f} секунд")
        self._add_log_entry("INFO", f"📊 Результаты: {total_urls} URL просканировано, {total_vulnerabilities} уязвимостей найдено")
        
        self._stats['urls_scanned'] = total_urls
        self._stats['vulnerabilities'] = total_vulnerabilities
        
        self._update_stats('urls_scanned', total_urls)
        self._update_stats('vulnerabilities', total_vulnerabilities)
        
        await self.scan_controller.save_scan_result(result)
        
        if total_vulnerabilities > 0:
            msg = (
                f"Сканирование завершено!\n\n"
                f"🔴 Найдено {total_vulnerabilities} уязвимостей!\n\n"
                f"📊 Статистика:\n"
                f"• Просканировано URL: {total_urls}\n\n"
                f"📋 Проверьте вкладку 'Отчёты' для подробной информации."
            )
        else:
            msg = (
                f"Сканирование завершено!\n\n"
                f"🟢 Уязвимостей не найдено.\n\n"
                f"📊 Статистика:\n"
                f"• Просканировано URL: {total_urls}"
            )
        
        error_handler.show_info_message("Сканирование завершено", msg)

    def _on_scan_log(self, message: str):
        message_lower = message.lower()
        level = "INFO"
        
        if " - " in message:
            parts = message.split(" - ", 1)
            if len(parts) == 2:
                potential_level = parts[0].strip().upper()
                valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "VULNERABILITY"]
                if potential_level in valid_levels:
                    level = potential_level
                    message = parts[1].strip()
        
        if level == "INFO":
            if any(keyword in message_lower for keyword in ["error", "ошибка", "failed", "неудачно"]):
                level = "ERROR"
            elif any(keyword in message_lower for keyword in ["warning", "предупреждение"]):
                level = "WARNING"
            elif any(keyword in message_lower for keyword in ["vulnerability", "уязвимость"]):
                level = "VULNERABILITY"
        
        self._add_log_entry(level, message)

