"""
Миксин для функциональности работы с логами
"""
from typing import List, Dict, Any, Optional
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QLabel, QTextEdit, QLineEdit, QCheckBox, QScrollBar
from utils.logger import logger


def _get_current_timestamp() -> str:
    """Получить текущую временную метку в формате строки"""
    from utils.performance import get_local_timestamp
    return get_local_timestamp()


def _get_log_color(level: str) -> QColor:
    """Получить цвет для уровня лога"""

    if level == "Ошибка":
        return QColor(255, 0, 0)  # Красный
    elif level == "Предупреждение":
        return QColor(255, 165, 0)  # Оранжевый
    else:
        return QColor(0, 0, 0)  # Черный


class LogMixin:
    """Миксин, предоставляющий функциональность работы с логами"""

    # Сигналы будут определены в классе, который использует этот миксин
    # _log_loaded_signal = pyqtSignal(str, int)

    def __init__(self):
        """Инициализация миксина"""
        pass

    def _init_log_attributes(self) -> None:
        """Инициализация атрибутов, связанных с логами"""
        # Логи и фильтры
        self._log_entries: List[Dict[str, str]] = []
        self._filtered_log_entries: List[Dict[str, str]] = []
        self.detailed_log: Optional[QTextEdit] = None
        self.log_status_label: Optional[QLabel] = None
        self._search_text: Optional[str] = None

    def _init_log_components(self) -> None:
        """Инициализация компонентов для работы с логами"""
        self.detailed_log: Optional[QTextEdit] = QTextEdit()
        self._log_entries: List[Dict[str, str]] = []
        self._filtered_log_entries: List[Dict[str, str]] = []
        self.log_status_label: Optional[QLabel] = QLabel()
        self.log_search: QLineEdit = QLineEdit()
        self.auto_scroll_checkbox: QCheckBox = QCheckBox("Автопрокрутка")
        self.clear_log_checkbox: QCheckBox = QCheckBox("Очищать лог перед сканированием")

    def add_log_entry(self, message: str, level: str = "Информация") -> None:
        """
        Добавить запись в лог

        Args:
            message: Текст сообщения
            level: Уровень сообщения (Информация, Предупреждение, Ошибка)
        """
        timestamp: str = _get_current_timestamp()
        log_entry: Dict[str, str] = {
            'timestamp': timestamp,
            'level': level,
            'message': message
        }

        self._log_entries.append(log_entry)

        # Обновляем отфильтрованные записи, если фильтр активен
        if hasattr(self, '_search_text') and self._search_text:
            self._filter_log_entries()
        else:
            self._filtered_log_entries = self._log_entries.copy()

        # Обновляем UI
        self._update_log_display()

        # Логируем в системный лог
        if level == "Ошибка":
            logger.error(message)
        elif level == "Предупреждение":
            logger.warning(message)
        else:
            logger.info(message)

    def _filter_log_entries(self) -> None:
        """Фильтрация записей лога по поисковому запросу"""
        search_text: Optional[str] = getattr(self, '_search_text', None)
        if not search_text:
            self._filtered_log_entries = self._log_entries.copy()
            return

        search_text = search_text.lower()
        self._filtered_log_entries = [
            entry for entry in self._log_entries
            if search_text in entry['message'].lower() or 
               search_text in entry['level'].lower()
        ]

    def _update_log_display(self) -> None:
        """Обновить отображение лога в UI"""
        if not hasattr(self, 'detailed_log') or not self.detailed_log:
            return

        # Очищаем текущее содержимое
        self.detailed_log.clear()

        # Добавляем отфильтрованные записи
        for entry in self._filtered_log_entries:
            color: QColor = _get_log_color(entry['level'])
            formatted_message: str = f"[{entry['timestamp']}] [{entry['level']}] {entry['message']}"

            # Применяем цвет и добавляем сообщение
            self.detailed_log.setTextColor(color)
            self.detailed_log.append(formatted_message)

        # Прокручиваем вниз, если включена автопрокрутка
        if hasattr(self, 'auto_scroll_checkbox') and self.auto_scroll_checkbox.isChecked():
            scrollbar: Optional[QScrollBar] = self.detailed_log.verticalScrollBar()
            if scrollbar is not None:
                scrollbar.setValue(scrollbar.maximum())

        # Обновляем статус
        if hasattr(self, 'log_status_label') and self.log_status_label:
            total: int = len(self._log_entries)
            filtered: int = len(self._filtered_log_entries)
            self.log_status_label.setText(f"Показано {filtered} из {total} записей")

    def clear_log(self) -> None:
        """Очистить лог"""
        self._log_entries.clear()
        self._filtered_log_entries.clear()
        if hasattr(self, 'detailed_log') and self.detailed_log:
            self.detailed_log.clear()
        if hasattr(self, 'log_status_label') and self.log_status_label:
            self.log_status_label.setText("Лог очищен")
        logger.info("Log cleared")

    def _process_log_content(self, content: str, line_count: int) -> None:
        """Обработать содержимое лога, загруженное из файла"""
        try:
            lines: List[str] = content.split('\n')
            for line in lines:
                if not line.strip():
                    continue

                # Простая проверка формата [timestamp] [level] message
                if line.startswith('[') and '] [' in line:
                    parts: List[str] = line.split('] [', 2)
                    if len(parts) >= 3:
                        timestamp: str = parts[0][1:]  # Удаляем [
                        level: str = parts[1]
                        message: str = parts[2][:-1] if parts[2].endswith(']') else parts[2]

                        log_entry: Dict[str, str] = {
                            'timestamp': timestamp,
                            'level': level,
                            'message': message
                        }
                        self._log_entries.append(log_entry)

            # Обновляем отфильтрованные записи
            self._filter_log_entries()

            # Обновляем отображение
            self._update_log_display()

            logger.info(f"Loaded {len(self._log_entries)} log entries")

        except Exception as e:
            logger.error(f"Error processing log content: {e}")
            self.add_log_entry(f"Ошибка обработки содержимого лога: {e}", "Ошибка")
