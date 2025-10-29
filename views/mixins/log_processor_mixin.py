import json
from typing import List, TypedDict, Optional
from PyQt5.QtWidgets import QTextEdit, QLabel, QTableWidget
from PyQt5.QtCore import pyqtSignal

from utils.logger import logger
from utils.performance import extract_time_from_timestamp, get_local_timestamp
from utils.qt_utils import SignalWrapper

class LogProcessorMixin:
    """Миксин для обработки и отображения логов"""

    def __init__(self):
        """Инициализация миксина"""
        # Сигнал для результатов сканирования
        self._scan_result_signal = SignalWrapper(pyqtSignal(dict))
        # Компоненты для работы с логами
        self.detailed_log: Optional[QTextEdit] = None
        # Метка для отображения статуса лога
        self.log_status_label: Optional[QLabel] = None
        # Таблица последних сканирований
        self.recent_scans_table: Optional[QTableWidget] = None
        # Список записей лога
        self._log_entries: List[dict] = []
        # Фильтрованные записи лога
        self._filtered_log_entries: List[dict] = []

    def _process_log_content(self, content: str, log_type: int) -> None:
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

                # Форматирование и отображение записей
                for entry in entries_to_display:
                    formatted_entry = (
                        f"[{entry['timestamp']}] {entry['level']}\n"
                        f"{entry['message']}\n"
                        f"{'=' * 80}\n"
                    )
                    self.detailed_log.append(formatted_entry)

                # Обновление метки статуса
                if hasattr(self, 'log_status_label') and self.log_status_label is not None:
                    total = len(self._log_entries)
                    filtered = len(self._filtered_log_entries) if self._filtered_log_entries else total
                    self.log_status_label.setText(f"Показано {filtered} из {total} записей")
        except Exception as e:
            logger.error(f"Error updating log display: {e}")