from typing import Any, Optional
from PyQt5.QtWidgets import QWidget, QMessageBox, QSpinBox, QCheckBox, QComboBox
from utils.logger import logger
from views.dashboard_window_main import DashboardWindow
from views.dashboard_window_methods import DashboardWindowMethodsMixin
from views.dashboard_window_dialogs import PolicyEditDialog
from policies.policy_manager import PolicyManager


# Обновленный класс DashboardWindow с дополнительными методами
class DashboardWindowNew(DashboardWindow, DashboardWindowMethodsMixin):
    """
    Оптимизированная версия основного окна приложения
    Наследует функциональность из DashboardWindow и DashboardWindowMethodsMixin
    """

    def __init__(self, user_id: int, username: str, user_model: Any, parent: Optional[QWidget] = None) -> None:
        # Инициализируем только DashboardWindow, который уже содержит все необходимые миксины
        DashboardWindow.__init__(self, user_id, username, user_model, parent)
        
        # Инициализируем атрибуты, специфичные для DashboardWindowMethodsMixin
        # без вызова его конструктора, чтобы избежать конфликтов
        # Явно указываем типы для совместимости с базовыми классами
        from PyQt5.QtWidgets import QTextEdit, QLabel, QTableWidget, QWidget
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

        # Дополнительная инициализация, если необходима
        logger.info("Initialized optimized DashboardWindow")
        
    def _process_log_content(self, content: str, *args: Any, **kwargs: Any) -> None:
        """Обработка загруженного содержимого лога
        
        Универсальный метод, совместимый с обоими базовыми классами.
        """
        # Проверяем, был ли передан именованный параметр log_type
        if 'log_type' in kwargs:
            log_type = kwargs['log_type']
        # Проверяем, был ли передан позиционный параметр (line_count или log_type)
        elif args:
            param = args[0]
            # Если значение 1 или 2, считаем что это log_type
            if param in (1, 2):
                log_type = param
            else:
                # В противном случае считаем что это line_count и преобразуем
                log_type = 1 if param == 1 else 2
        else:
            # Параметры не переданы, используем значение по умолчанию
            log_type = 2
            
        # Вызываем метод из DashboardWindowMethodsMixin
        DashboardWindowMethodsMixin._process_log_content(self, content, log_type)

    def edit_policy(self, policy_id: Optional[int] = None):
        """Открытие диалога редактирования политики"""
        try:
            dialog = PolicyEditDialog(policy_id, self)
            if dialog.exec_():
                # Перезагрузка политик после сохранения
                self.load_policies_to_combobox()
                logger.info(f"Policy dialog closed, policy_id: {policy_id}")
        except Exception as e:
            logger.error(f"Error opening policy edit dialog: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть диалог редактирования политики: {e}")

    def delete_policy(self, policy_id: int):
        """Удаление политики"""
        try:
            confirm = QMessageBox.question(
                self, 
                "Подтверждение", 
                "Вы уверены, что хотите удалить эту политику?",
                QMessageBox.Yes | QMessageBox.No
            )

            if confirm == QMessageBox.StandardButton.Yes:
                policy_manager = PolicyManager()

                success = policy_manager.delete_policy(policy_id)

                if success:
                    QMessageBox.information(self, "Успех", "Политика успешно удалена")
                    # Перезагрузка политик
                    self.load_policies_to_combobox()
                    logger.info(f"Deleted policy with ID: {policy_id}")
                else:
                    QMessageBox.critical(self, "Ошибка", "Не удалось удалить политику")
                    logger.error(f"Failed to delete policy with ID: {policy_id}")
        except Exception as e:
            logger.error(f"Error deleting policy: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить политику: {e}")

    def apply_policy(self, policy_id: int):
        """Применение политики к сканированию"""
        try:
            policy_manager = PolicyManager()

            policy = policy_manager.get_policy_by_id(policy_id)

            if policy:
                # Получение параметров политики
                # Используем прямой доступ к атрибутам вместо метода get
                params = {
                    'max_depth': policy.max_depth,
                    'timeout': policy.timeout,
                    'threads': policy.max_concurrent,
                    'check_forms': 'sql' in policy.enabled_vulns,
                    'check_links': True,  # Значение по умолчанию
                    'check_headers': False  # Значение по умолчанию
                }

                # Применение параметров к настройкам сканирования
                if hasattr(self, 'max_depth_spin') and self.max_depth_spin is not None:
                    self.max_depth_spin.setValue(params.get('max_depth', 3))

                if hasattr(self, 'timeout_spin') and self.timeout_spin is not None:
                    self.timeout_spin.setValue(params.get('timeout', 10))

                if hasattr(self, 'threads_spin') and self.threads_spin is not None:
                    self.threads_spin.setValue(params.get('threads', 5))

                if hasattr(self, 'check_forms_check') and self.check_forms_check is not None:
                    self.check_forms_check.setChecked(params.get('check_forms', True))

                if hasattr(self, 'check_links_check') and self.check_links_check is not None:
                    self.check_links_check.setChecked(params.get('check_links', True))

                if hasattr(self, 'check_headers_check') and self.check_headers_check is not None:
                    self.check_headers_check.setChecked(params.get('check_headers', False))

                # Установка типа сканирования в соответствии с типом политики
                if hasattr(self, 'scan_type_combo') and self.scan_type_combo is not None:
                    # Определяем тип политики на основе включенных уязвимостей
                    if 'sql' in policy.enabled_vulns and len(policy.enabled_vulns) == 1:
                        self.scan_type_combo.setCurrentIndex(0)  # SQL-инъекции
                    elif 'xss' in policy.enabled_vulns and len(policy.enabled_vulns) == 1:
                        self.scan_type_combo.setCurrentIndex(1)  # XSS
                    elif 'csrf' in policy.enabled_vulns and len(policy.enabled_vulns) == 1:
                        self.scan_type_combo.setCurrentIndex(2)  # CSRF
                    else:  # Общая
                        self.scan_type_combo.setCurrentIndex(3)

                QMessageBox.information(self, "Успех", f"Политика '{policy.name}' успешно применена")
                logger.info(f"Applied policy with ID: {policy_id}")
            else:
                QMessageBox.warning(self, "Предупреждение", "Политика не найдена")
                logger.warning(f"Policy not found for ID: {policy_id}")
        except Exception as e:
            logger.error(f"Error applying policy: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось применить политику: {e}")
