"""
Миксин для оптимизации вкладки сканирования
"""
from PyQt5.QtCore import QTimer, QObject
from utils.logger import logger
from typing import Optional, Any, Dict


class ScanTabStatsMixin:
    """Миксин для добавления функциональности статистики сканирования"""

    def __init__(self, parent: Optional[QObject] = None):
        """Инициализация миксина"""
        self._scan_stats_timer = None
        # Инициализируем атрибуты, которые могут использоваться в методах
        self.stats_labels: Dict[str, Any] = {}
        self._scan_start_time = None
        self.stats_manager: Optional[Any] = None  # Явно указываем, что stats_manager может быть None
        self._setup_stats_timer()
        # Сначала инициализируем stats_manager, а потом обновляем статистику
        self.init_stats_manager()
        self._update_scan_stats()


    def _setup_stats_timer(self):
        """Настройка таймера для обновления статистики"""
        self._scan_stats_timer = QTimer()
        self._scan_stats_timer.setInterval(1000)  # Обновление каждую секунду
        self._scan_stats_timer.timeout.connect(self._update_scan_stats)
        self._scan_stats_timer.start()

    def stop_stats_timer(self):
        """Остановка таймера статистики"""
        if self._scan_stats_timer:
            self._scan_stats_timer.stop()

    def start_stats_timer(self):
        """Запуск таймера статистики"""
        if self._scan_stats_timer:
            self._scan_stats_timer.start()

    def init_stats_manager(self):
        """Инициализация менеджера статистики"""
        try:
            # Импортируем и создаем StatsManager
            from views.managers.stats_manager import StatsManager

            # Если stats_manager еще не создан, создаем его
            if self.stats_manager is None:
                # Проверяем, является ли self наследником QObject
                if isinstance(self, QObject):
                    self.stats_manager = StatsManager(self)
                else:
                    # Если self не является QObject, не создаем StatsManager
                    logger.warning("Cannot initialize StatsManager: self is not a QObject")
                    self.stats_manager = None
                    return

                # Подключаем сигнал обновления статистики
                self.stats_manager.stats_updated.connect(self._on_stats_updated)

                logger.info("StatsManager initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing StatsManager: {e}")
            # В случае ошибки оставляем stats_manager как None
            self.stats_manager = None

    def _on_stats_updated(self, key: str, value: int):
        """Обработчик сигнала обновления статистики от StatsManager"""
        try:
            # Обновляем UI если есть соответствующие метки
            if key in self.stats_labels:
                self.stats_labels[key].setText(str(value))
                logger.debug(f"Updated stat {key} to {value}")
        except Exception as e:
            logger.error(f"Error in _on_stats_updated: {e}")

    def _update_scan_stats(self):
        """Обновление статистики сканирования"""
        try:
            # Проверяем, что stats_manager существует и инициализирован
            if self.stats_manager is not None:
                stats = self.stats_manager.get_stats()

                # Обновляем все метки статистики
                for key, label in self.stats_labels.items():
                    if key in stats:
                        label.setText(str(stats[key]))

                # Дополнительно обновляем время сканирования, если сканирование активно
                if self._scan_start_time is not None:
                    from datetime import datetime
                    scan_time = datetime.now() - self._scan_start_time
                    # Используем total_seconds() вместо seconds для учета дней
                    hours: float; remainder: float
                    hours, remainder = divmod(scan_time.total_seconds(), 3600)
                    minutes: float; seconds: float
                    minutes, seconds = divmod(remainder, 60)
                    time_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
                    if 'scan_time' in self.stats_labels:
                        self.stats_labels['scan_time'].setText(time_str)
        except Exception as e:
            logger.error(f"Error updating scan stats: {e}")
