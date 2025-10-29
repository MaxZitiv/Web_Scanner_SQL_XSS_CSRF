"""
Миксин для функциональности сканирования
"""
from typing import Dict, Any, Optional, List
from types import CoroutineType
from PyQt5.QtWidgets import QLabel, QPushButton, QLineEdit, QCheckBox, QSpinBox, QProgressBar, QTreeWidget, QDateTimeEdit
from utils.security import is_safe_url
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
        self.scan_controller: Optional[ScanController] = None  # Инициализируем при старте сканирования
        self.policy_manager = PolicyManager()
        self.selected_policy = None

        # UI компоненты
        self.progress_label = QLabel()
        self.site_tree = QTreeWidget()

        # Множества для отслеживания
        self._scanned_urls: set[str] = set()
        self._scanned_forms: set[str] = set()

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

    def _ensure_scan_controller(self, url: str, scan_types: List[str]) -> None:
        """
        Убедиться, что у нас есть инициализированный ScanController.
        
        Args:
            url: URL для сканирования
            scan_types: Список типов сканирования
        """
        if self.scan_controller is None:
            self.scan_controller = ScanController(
                url=url,
                scan_types=scan_types,
                user_id=self.user_id if self.user_id is not None else 0,
                max_depth=self.depth_spinbox.value() if hasattr(self, 'depth_spinbox') else 3,
                max_concurrent=self.concurrent_spinbox.value() if hasattr(self, 'concurrent_spinbox') else 5,
                timeout=self.timeout_spinbox.value() if hasattr(self, 'timeout_spinbox') else 30
            )

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
        params: Dict[str, Any] = {
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

        # Валидация параметров
        is_valid, error_msg = _validate_scan_parameters(params)
        if not is_valid:
            logger.error(f"Ошибка валидации параметров сканирования: {error_msg}")

        return params

    def start_scan(self, url: Optional[str] = None) -> CoroutineType[Any, Any, None]:
        """
        Начать сканирование
        
        Args:
            url: URL для сканирования (опционально, если не указан, берется из UI)
            
        Returns:
            CoroutineType: Корутина для выполнения сканирования
        """
        async def _start_scan_impl() -> None:
            try:
                # Проверяем наличие URL
                if url is None:
                    if not hasattr(self, 'url_input'):
                        error_msg = "Компонент ввода URL не найден"
                        logger.error(error_msg)
                        self._handle_error(error_msg)
                        return
                    scan_url = self.url_input.text().strip()
                else:
                    scan_url = url
                    
                if not scan_url:
                    error_msg = "URL не может быть пустым"
                    logger.error(error_msg)
                    self._handle_error(error_msg)
                    return

                if not is_safe_url(scan_url):
                    error_msg = "Введенный URL небезопасен"
                    logger.error(error_msg)
                    self._handle_error(error_msg)
                    return
                    
                # Определяем типы сканирования
                scan_types: List[str] = []
                if hasattr(self, 'sql_checkbox') and self.sql_checkbox.isChecked():
                    scan_types.append("sql")
                if hasattr(self, 'xss_checkbox') and self.xss_checkbox.isChecked():
                    scan_types.append("xss")
                if hasattr(self, 'csrf_checkbox') and self.csrf_checkbox.isChecked():
                    scan_types.append("csrf")

                # Проверяем наличие хотя бы одного типа сканирования
                if not scan_types:
                    error_msg = "Выберите хотя бы один тип сканирования"
                    logger.error(error_msg)
                    self._handle_error(error_msg)
                    return

                # Сбрасываем состояние сканирования
                self._reset_scan_state()

                # Создаем контроллер если нужно
                self._ensure_scan_controller(scan_url, scan_types)
                
                # Запускаем сканирование через контроллер
                assert self.scan_controller is not None, "Scan controller should be initialized"
                scan_id = await self.scan_controller.start_scan(
                    scan_url, 
                    scan_types,
                    max_depth=self.depth_spinbox.value() if hasattr(self, 'depth_spinbox') else 3,
                    max_concurrent=self.concurrent_spinbox.value() if hasattr(self, 'concurrent_spinbox') else 5,
                    timeout=self.timeout_spinbox.value() if hasattr(self, 'timeout_spinbox') else 30
                )

                # Обновляем интерфейс
                if hasattr(self, 'scan_status'):
                    self.scan_status.setText("Сканирование запущено")
                if hasattr(self, 'scan_progress'):
                    self.scan_progress.setVisible(True)
                    self.scan_progress.setRange(0, 0)
                    self.scan_progress.setValue(0)

                # Логируем успешный запуск сканирования
                logger.info(f"Scan started with ID {scan_id} for URL: {scan_url}")
                
            except Exception as e:
                error_msg = f"Ошибка при запуске сканирования: {e}"
                logger.error(error_msg)
                self._handle_error(error_msg)
        
        # Возвращаем корутину для запуска сканирования
        coroutine = _start_scan_impl()
        return coroutine

    def _handle_error(self, error_msg: str) -> None:
        """
        Обработка ошибок с отправкой сигнала, если он доступен
        
        Args:
            error_msg: Сообщение об ошибке
        """
        # Проверяем наличие сигнала и отправляем его, если он есть
        error_signal = getattr(self, 'error_occurred', None)
        if error_signal is not None and callable(error_signal.emit):
            error_signal.emit(error_msg)
        logger.error(error_msg)
