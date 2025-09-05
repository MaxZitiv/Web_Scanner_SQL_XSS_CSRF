from typing import Dict, Any
from PyQt5.QtCore import QObject
from PyQt5.QtWidgets import QLabel
from utils.logger import logger, log_and_notify

class DashboardStatsMixin(QObject):
    """Миксин класс для оптимизации работы со статистикой в DashboardWindow"""
    
    def __init__(self):
        super().__init__()
        # Инициализация атрибутов для статистики
        self.stats_manager = None
        self._stats = None
        self.stats_labels: Dict[str, QLabel] = {}

    def init_stats_manager(self):
        """Инициализация StatsManager и подключение сигналов"""
        if not hasattr(self, 'stats_manager'):
            from views.managers.stats_manager import StatsManager
            self.stats_manager = StatsManager(self)
            # Подключаем сигнал обновления статистики
            self.stats_manager.stats_updated.connect(self._on_stats_updated)

    def _on_stats_updated(self, key: str, value: int):
        """Обработчик сигнала обновления статистики от StatsManager"""
        try:
            # Обновляем локальную копию статистики
            if not hasattr(self, '_stats') or self._stats is None:
                if self.stats_manager is not None:
                    self._stats = self.stats_manager.get_stats()
            else:
                self._stats[key] = value

            # Обновляем UI если есть соответствующие метки
            if hasattr(self, 'stats_labels') and key in self.stats_labels:
                self.stats_labels[key].setText(str(value))
        except Exception as e:
            logger.error(f"Error in _on_stats_updated: {e}")

    def _update_stats(self, key: str, value: int) -> None:
        """Обновляет статистику через StatsManager"""
        try:
            # Используем StatsManager для обновления статистики
            if self.stats_manager is not None:
                self.stats_manager.update_stats(key, value)
        except Exception as e:
            log_and_notify('error', f"Error in _update_stats: {e}")

    def _flush_stats_updates(self):
        """Применяет накопленные обновления статистики к UI (устаревший метод)"""
        # Этот метод больше не нужен, так как обновление обрабатывается через сигналы
        pass

    def update_forms_counters(self, forms_found: int = 0, forms_scanned: int = 0):
        """Принудительно обновляет счетчики форм"""
        try:
            self._update_stats('forms_found', forms_found)
            self._update_stats('forms_scanned', forms_scanned)
        except Exception as e:
            logger.error(f"Error in update_forms_counters: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Возвращает текущую статистику"""
        if hasattr(self, 'stats_manager') and self.stats_manager is not None:
            return self.stats_manager.get_stats()
        return self._stats if self._stats is not None else {}

    def reset_stats(self):
        """Сбрасывает статистику"""
        if hasattr(self, 'stats_manager') and self.stats_manager is not None:
            self.stats_manager.reset_stats()
        elif self._stats is not None:
            self._stats.clear()
