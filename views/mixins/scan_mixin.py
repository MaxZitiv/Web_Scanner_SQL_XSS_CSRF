"""
Миксин для функциональности сканирования
"""
from typing import Dict, Any, Optional
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QCheckBox, QSpinBox, QProgressBar, QTreeWidget, QDateTimeEdit
from controllers.scan_controller import ScanController
from policies.policy_manager import PolicyManager
from utils.logger import logger


def _validate_scan_parameters(params: Dict[str, Any]) -> tuple[bool, str]:
    """
    Валидация параметров сканирования

    Returns:
        tuple: (валидность, сообщение об ошибке)
    """
    if not params['url']:
        return False, "URL не может быть пустым"

    if not params['vuln_types']:
        return False, "Должен быть выбран хотя бы один тип уязвимости"

    return True, ""


class ScanMixin:
    """Миксин, предоставляющий функциональность сканирования"""

    # Сигналы будут определены в классе, который использует этот миксин
    # scan_completed = pyqtSignal(dict)
    # error_occurred = pyqtSignal(str)

    def __init__(self, user_id: Optional[int] = None):
        """
        Инициализация миксина

        Args:
            user_id: Идентификатор пользователя
        """
        self.user_id = user_id

    def _init_scan_attributes(self) -> None:
        """Инициализация атрибутов, связанных со сканированием"""
        # Состояния сканирования
        self._scan_start_time = None
        self._total_urls = 0
        self._completed_urls = 0
        self._total_progress = 0
        self._active_workers = 0
        self._estimated_total_time = 0
        self._worker_progress = {}
        self._is_paused = False

        # Менеджеры
        self.scan_controller = ScanController(self.user_id if self.user_id is not None else 0)
        self.policy_manager = PolicyManager()
        self.selected_policy = None

        # UI компоненты
        self.progress_label = QLabel()
        self.site_tree = QTreeWidget()

        # Множества для отслеживания
        self._scanned_urls = set()
        self._scanned_forms = set()

    def _init_scan_components(self) -> None:
        """Инициализация компонентов, связанных со сканированием"""
        # Поля ввода и настройки сканирования
        self.url_input = QLineEdit()
        self.sql_checkbox = QCheckBox("SQL Injection")
        self.xss_checkbox = QCheckBox("XSS")
        self.csrf_checkbox = QCheckBox("CSRF")
        self.depth_spinbox = QSpinBox()
        self.concurrent_spinbox = QSpinBox()
        self.timeout_spinbox = QSpinBox()
        self.max_coverage_checkbox = QCheckBox("Максимальное покрытие")
        self.turbo_checkbox = QCheckBox("Турбо режим")

        # Кнопки управления сканированием
        self.scan_button = QPushButton("Начать сканирование")
        self.pause_button = QPushButton("⏸️ Пауза")
        self.stop_button = QPushButton("⏹️ Стоп")

        # Элементы прогресса
        self.scan_progress = QProgressBar()
        self.progress_label.setText("0%")
        self.scan_status = QLabel("Готов к сканированию")

        # Фильтры
        self.filter_input = QLineEdit()
        self.filter_sql_cb = QCheckBox("SQL Injection")
        self.filter_xss_cb = QCheckBox("XSS")
        self.filter_csrf_cb = QCheckBox("CSRF")
        self.date_from = QDateTimeEdit()
        self.date_to = QDateTimeEdit()

    def _reset_scan_state(self) -> None:
        """Сброс состояния сканирования"""
        self._scan_start_time = None
        self._total_urls = 0
        self._completed_urls = 0
        self._total_progress = 0
        self._active_workers = 0
        self._worker_progress = {}
        self._is_paused = False
        self._scanned_urls.clear()
        self._scanned_forms.clear()

        # Сброс UI элементов
        if hasattr(self, 'scan_progress'):
            self.scan_progress.setValue(0)
        if hasattr(self, 'progress_label'):
            self.progress_label.setText("0%")
        if hasattr(self, 'scan_status'):
            self.scan_status.setText("Готов к сканированию")

    def _get_scan_parameters(self) -> Dict[str, Any]:
        """Получить параметры сканирования из UI элементов"""
        return {
            'url': self.url_input.text().strip(),
            'vuln_types': [
                vt for vt, cb in [
                    ('sql', self.sql_checkbox),
                    ('xss', self.xss_checkbox),
                    ('csrf', self.csrf_checkbox)
                ] if cb.isChecked()
            ],
            'depth': self.depth_spinbox.value(),
            'concurrent': self.concurrent_spinbox.value(),
            'timeout': self.timeout_spinbox.value(),
            'max_coverage': self.max_coverage_checkbox.isChecked(),
            'turbo_mode': self.turbo_checkbox.isChecked()
        }
