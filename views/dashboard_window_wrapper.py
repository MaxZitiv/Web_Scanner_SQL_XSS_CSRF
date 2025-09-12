from typing import Any, Optional
from PyQt5.QtWidgets import QWidget
from utils.logger import logger
from views.dashboard_window_optimized import DashboardWindow


class DashboardWindowWrapper(DashboardWindow):
    """
    Класс-обертка для DashboardWindow, который обеспечивает правильную инициализацию
    всех миксинов, особенно ExportMixin с необходимым аргументом user_id
    """

    def __init__(self, user_id: int, username: str, user_model: Any, parent: Optional[QWidget] = None) -> None:
        # Сохраняем параметры для последующей инициализации
        self._user_id = user_id
        self._username = username
        self._user_model = user_model
        self._parent = parent

        # Инициализируем базовый класс QWidget
        QWidget.__init__(self, parent)

        # Вызываем метод для инициализации всех компонентов
        self._initialize_components()

        logger.info("DashboardWindowWrapper initialized successfully")

    def _initialize_components(self) -> None:
        """Инициализирует все компоненты DashboardWindow с правильными параметрами"""
        try:
            # Инициализируем DashboardWindow с сохраненными параметрами
            DashboardWindow.__init__(self, self._user_id, self._username, self._user_model, self._parent)
        except Exception as e:
            logger.error(f"Error initializing DashboardWindow: {e}")
            raise
