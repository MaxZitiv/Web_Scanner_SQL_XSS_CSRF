from typing import Dict, Any, Optional
from PyQt5.QtCore import QTimer, QObject, pyqtSignal
from utils.logger import logger
from typing import Tuple, List

class StatsManager(QObject):
    """Базовый класс для управления статистикой в приложении"""

    # Сигнал для обновления UI
    stats_updated = pyqtSignal(str, int)  # key, value

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        # Стандартная статистика для сканера
        self._stats = {
            'urls_found': 0,
            'urls_scanned': 0,
            'forms_found': 0,
            'forms_scanned': 0,
            'vulnerabilities': 0,
            'requests_sent': 0,
            'errors': 0
        }
        self._site_structure: Dict[str, List[Any]] = {
            'urls': [],
            'status': []
        }

        # Накопленные обновления для пакетного применения
        self._pending_stats_updates: Dict[str, int] = {}

        # Таймер для пакетного обновления UI
        self._stats_update_timer = QTimer()
        self._stats_update_timer.setSingleShot(True)
        self._stats_update_timer.timeout.connect(self._flush_stats_updates)

    def update_stats(self, key: str, value: int) -> None:
        """Обновляет значение статистики"""
        try:
            if key in self._stats:
                self._stats[key] = value

            # Накапливаем обновления
            self._pending_stats_updates[key] = value

            # Запускаем таймер для обновления UI
            if not self._stats_update_timer.isActive():
                self._stats_update_timer.start(100)  # Обновляем не чаще чем раз в 100 мс
        except Exception as e:
            logger.error(f"Error in update_stats: {e}")
            
    def update_site_structure(self, url: str, status: str):
        """Обновление структуры сайта"""
        if url not in self._site_structure['urls']:
            self._site_structure['urls'].append(url)
            self._site_structure['status'].append(status)
        else:
            index = self._site_structure['urls'].index(url)
            self._site_structure['status'][index] = status
            
    def get_site_structure(self) -> Tuple[List[str], List[str]]:
        """Получение структуры сайта"""
        return self._site_structure['urls'], self._site_structure['status']

    def increment_stats(self, key: str) -> None:
        """Увеличивает значение статистики на 1"""
        try:
            if key in self._stats:
                self._stats[key] += 1
                self.update_stats(key, self._stats[key])
        except Exception as e:
            logger.error(f"Error in increment_stats: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Возвращает копию текущей статистики"""
        return self._stats.copy()

    def set_stats(self, stats: Dict[str, Any]) -> None:
        """Устанавливает новую статистику"""
        try:
            for key, value in stats.items():
                if key in self._stats:
                    self._stats[key] = value
                    self._pending_stats_updates[key] = value

            # Запускаем таймер для обновления UI
            if not self._stats_update_timer.isActive():
                self._stats_update_timer.start(100)
        except Exception as e:
            logger.error(f"Error in set_stats: {e}")

    def _flush_stats_updates(self) -> None:
        """Применяет накопленные обновления статистики к UI через сигналы"""
        try:
            for key, value in self._pending_stats_updates.items():
                self.stats_updated.emit(key, value)

            # Очищаем накопленные обновления
            self._pending_stats_updates.clear()
        except Exception as e:
            logger.error(f"Error in _flush_stats_updates: {e}")

    def reset_stats(self) -> None:
        """Сбрасывает всю статистику в нулевые значения"""
        try:
            for key in self._stats:
                self._stats[key] = 0
                self._pending_stats_updates[key] = 0

            # Запускаем таймер для обновления UI
            if not self._stats_update_timer.isActive():
                self._stats_update_timer.start(100)
        except Exception as e:
            logger.error(f"Error in reset_stats: {e}")
            
    def refresh_stats(self, user_id: Optional[int] = None) -> None:
        """Обновляет статистику для указанного пользователя"""
        try:
            # Сбрасываем статистику перед обновлением
            self.reset_stats()
            logger.info(f"Stats refreshed for user {user_id if user_id else 'all'}")
        except Exception as e:
            logger.error(f"Error in refresh_stats: {e}")
