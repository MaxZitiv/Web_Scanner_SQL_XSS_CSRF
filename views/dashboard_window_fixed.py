from typing import Any, Optional
from PyQt5.QtWidgets import QWidget, QMessageBox, QSpinBox, QCheckBox, QComboBox
from utils.logger import logger
from views.dashboard_window_optimized import DashboardWindowBase, DashboardWindowUI, DashboardWindowHandlers
from views.dashboard_optimized import DashboardStatsMixin
from views.mixins.export_mixin import ExportMixin
from views.mixins.scan_mixin import ScanMixin
from views.mixins.log_mixin import LogMixin
from views.dashboard_window_methods import DashboardWindowMethodsMixin
from views.dashboard_window_dialogs import PolicyEditDialog
from policies.policy_manager import PolicyManager


class DashboardWindowFixed(DashboardWindowBase, DashboardWindowUI, DashboardWindowHandlers,
                         DashboardStatsMixin, ExportMixin, ScanMixin, LogMixin, DashboardWindowMethodsMixin, QWidget):
    """
    Исправленная версия основного окна приложения с панелью управления
    Объединяет функциональность из нескольких миксинов и вспомогательных классов
    с правильной инициализацией
    """

    def __init__(self, user_id: int, username: str, user_model: Any, parent: Optional[QWidget] = None) -> None:
        # Инициализация родительского класса QWidget
        QWidget.__init__(self, parent)

        # Инициализация базовых атрибутов
        self.user_id = user_id
        self.username = username
        self.user_model = user_model

        # Инициализация миксинов в правильном порядке
        DashboardWindowBase.__init__(self)
        DashboardWindowUI.__init__(self)
        DashboardWindowHandlers.__init__(self)
        DashboardStatsMixin.__init__(self)
        ExportMixin.__init__(self, user_id)  # Важно передать user_id
        ScanMixin.__init__(self, user_id)
        LogMixin.__init__(self)

        # Инициализация атрибутов DashboardWindowMethodsMixin без вызова конструктора
        from PyQt5.QtWidgets import QTextEdit, QLabel, QTableWidget
        from views.tabs.stats_tab import StatsTabWidget

        self.detailed_log: Optional[QTextEdit] = None
        self.log_status_label: Optional[QLabel] = None
        self.recent_scans_table: Optional[QTableWidget] = None
        self.stats_tab: Optional[StatsTabWidget] = None

        # Явное указание типа для атрибутов
        self.max_depth_spin: Optional[QSpinBox] = None
        self.timeout_spin: Optional[QSpinBox] = None
        self.threads_spin: Optional[QSpinBox] = None
        self.check_forms_check: Optional[QCheckBox] = None
        self.check_links_check: Optional[QCheckBox] = None
        self.check_headers_check: Optional[QCheckBox] = None
        self.scan_type_combo: Optional[QComboBox] = None

        # Дополнительная инициализация
        logger.info("Initialized fixed DashboardWindow")

    def _process_log_content(self, content: str, *args: Any, **kwargs: Any) -> None:
        """Обработка загруженного содержимого лога

        Универсальный метод, совместимый с обоими базовыми классами.
        """
        # Проверяем, был ли передан именованный параметр log_type
        log_type = kwargs.get('log_type', None)
        if log_type is None and len(args) > 0:
            log_type = args[0]

        if log_type is not None:
            # Вызываем метод из DashboardWindowMethodsMixin
            DashboardWindowMethodsMixin._process_log_content(self, content, log_type)
