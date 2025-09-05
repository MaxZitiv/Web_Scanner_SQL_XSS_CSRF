from typing import Optional, cast, Any, Callable
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QLineEdit, QTextEdit, QComboBox, QCheckBox,
                         QDialogButtonBox, QMessageBox, QFormLayout, QSpinBox, QGroupBox)
from PyQt5.QtCore import QObject, pyqtSignal

from utils.logger import logger
from policies.policy_manager import PolicyManager


class PolicyEditDialog(QDialog):
    """Диалог для редактирования политик безопасности"""

    def __init__(self, policy_id: Optional[int] = None, parent: Optional['QDialog'] = None):
        super().__init__(parent)

        self.policy_id = policy_id
        self.policy_manager = PolicyManager()

        self.setWindowTitle("Редактирование политики безопасности")
        self.setMinimumWidth(500)

        self.setup_ui()

        # Если указан ID политики, загружаем её данные
        if policy_id is not None:
            self.load_policy_data()

    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Форма для редактирования
        form_layout = QFormLayout()

        # Название политики
        self.name_edit = QLineEdit()
        form_layout.addRow("Название политики:", self.name_edit)

        # Описание политики
        self.description_edit = QTextEdit()
        self.description_edit.setMaximumHeight(100)
        form_layout.addRow("Описание:", self.description_edit)

        # Тип политики
        self.type_combo = QComboBox()
        self.type_combo.addItems(["SQL-инъекции", "XSS", "CSRF", "Общая"])
        form_layout.addRow("Тип политики:", self.type_combo)

        # Статус политики
        self.status_combo = QComboBox()
        self.status_combo.addItems(["Активна", "Неактивна"])
        form_layout.addRow("Статус:", self.status_combo)

        # Уровень серьезности
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["Низкий", "Средний", "Высокий", "Критический"])
        form_layout.addRow("Уровень серьезности:", self.severity_combo)

        # Параметры политики
        params_group = QGroupBox("Параметры политики")
        params_layout = QFormLayout()

        # Максимальная глубина сканирования
        self.max_depth_spin = QSpinBox()
        self.max_depth_spin.setRange(1, 10)
        self.max_depth_spin.setValue(3)
        params_layout.addRow("Максимальная глубина:", self.max_depth_spin)

        # Таймаут запроса (в секундах)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 60)
        self.timeout_spin.setValue(10)
        params_layout.addRow("Таймаут запроса:", self.timeout_spin)

        # Количество потоков
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 20)
        self.threads_spin.setValue(5)
        params_layout.addRow("Количество потоков:", self.threads_spin)

        # Проверять формы
        self.check_forms_check = QCheckBox()
        self.check_forms_check.setChecked(True)
        params_layout.addRow("Проверять формы:", self.check_forms_check)

        # Проверять ссылки
        self.check_links_check = QCheckBox()
        self.check_links_check.setChecked(True)
        params_layout.addRow("Проверять ссылки:", self.check_links_check)

        # Проверять заголовки
        self.check_headers_check = QCheckBox()
        self.check_headers_check.setChecked(False)
        params_layout.addRow("Проверять заголовки:", self.check_headers_check)

        params_group.setLayout(params_layout)
        form_layout.addRow(params_group)

        layout.addLayout(form_layout)

        # Кнопки
        from PyQt5.QtWidgets import QDialogButtonBox
        # Явно указываем стандартные кнопки через перечисление
        buttons = QDialogButtonBox()
        buttons.addButton(QDialogButtonBox.Save)
        buttons.addButton(QDialogButtonBox.Cancel)

        # Подключаем сигналы напрямую без приведения типов
        buttons.accepted.connect(self.save_policy)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def load_policy_data(self):
        """Загрузка данных политики"""
        try:
            # Преобразуем ID в имя политики
            policy_name = f"policy_{self.policy_id}"
            policy = self.policy_manager.load_policy(policy_name)

            if policy:
                # Заполнение формы данными
                self.name_edit.setText(policy.get('name', ''))
                self.description_edit.setPlainText(policy.get('description', ''))

                # Установка типа политики
                type_index = self.type_combo.findText(policy.get('type', ''))
                if type_index >= 0:
                    self.type_combo.setCurrentIndex(type_index)

                # Установка статуса
                status = "Активна" if policy.get('is_active', False) else "Неактивна"
                status_index = self.status_combo.findText(status)
                if status_index >= 0:
                    self.status_combo.setCurrentIndex(status_index)

                # Установка уровня серьезности
                severity_index = self.severity_combo.findText(policy.get('severity', ''))
                if severity_index >= 0:
                    self.severity_combo.setCurrentIndex(severity_index)

                # Загрузка параметров
                params = policy.get('parameters', {})
                if isinstance(params, dict):
                    # Явно указываем тип params для Pylance с конкретными типами ключей и значений
                    from typing import Dict, Any, Union, cast
                    # Используем cast для явного преобразования типа, чтобы Pylance понимал точный тип
                    params_dict: Dict[str, Union[int, bool, str]] = cast(Dict[str, Union[int, bool, str]], params)

                    # Получаем значения с явным указанием типов
                    # Для числовых значений просто преобразуем в int, так как Union[int, bool, str] всегда можно преобразовать
                    max_depth: int = int(params_dict.get('max_depth', 3))
                    timeout: int = int(params_dict.get('timeout', 10))
                    threads: int = int(params_dict.get('threads', 5))

                    # Для булевых значений используем более надежное преобразование
                    check_forms: bool = bool(params_dict.get('check_forms', True))
                    check_links: bool = bool(params_dict.get('check_links', True))
                    check_headers: bool = bool(params_dict.get('check_headers', False))

                    # Устанавливаем значения элементов управления
                    # Типы уже преобразованы выше, поэтому используем значения напрямую
                    self.max_depth_spin.setValue(max_depth)
                    self.timeout_spin.setValue(timeout)
                    self.threads_spin.setValue(threads)
                    self.check_forms_check.setChecked(check_forms)
                    self.check_links_check.setChecked(check_links)
                    self.check_headers_check.setChecked(check_headers)

                logger.info(f"Loaded policy data for ID: {self.policy_id}")
            else:
                logger.warning(f"Policy not found for ID: {self.policy_id}")
                QMessageBox.warning(self, "Предупреждение", "Политика не найдена")
        except Exception:
            import sys
            exc_type, exc_value, _ = sys.exc_info()
            logger.error(f"Error loading policy data: {exc_value}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить данные политики: {exc_value}")

    def save_policy(self):
        """Сохранение политики"""
        try:
            # Получение данных из формы
            name = self.name_edit.text().strip()
            if not name:
                QMessageBox.warning(self, "Предупреждение", "Название политики не может быть пустым")
                return

            description = self.description_edit.toPlainText().strip()
            policy_type = self.type_combo.currentText()
            is_active = self.status_combo.currentText() == "Активна"
            severity = self.severity_combo.currentText()

            # Формирование параметров с явной типизацией
            from typing import Dict, Union, cast
            parameters: Dict[str, Union[int, bool]] = {
                'max_depth': int(self.max_depth_spin.value()),
                'timeout': int(self.timeout_spin.value()),
                'threads': int(self.threads_spin.value()),
                'check_forms': bool(self.check_forms_check.isChecked()),
                'check_links': bool(self.check_links_check.isChecked()),
                'check_headers': bool(self.check_headers_check.isChecked())
            }

            # Формирование объекта политики с явной типизацией
            policy_data: Dict[str, Union[str, bool, Dict[str, Union[int, bool]]]] = {
                'name': str(name),
                'description': str(description),
                'type': str(policy_type),
                'is_active': bool(is_active),
                'severity': str(severity),
                'parameters': parameters
            }

            # Сохранение политики
            if self.policy_id is None:
                # Создание новой политики
                import time
                policy_id = int(time.time())  # Генерируем уникальный ID на основе времени
                policy_name = f"policy_{policy_id}"
                try:
                    self.policy_manager.save_policy(policy_name, policy_data)
                    QMessageBox.information(self, "Успех", "Политика успешно создана")
                    self.policy_id = policy_id
                    logger.info(f"Created new policy with ID: {policy_id}")
                except Exception:
                    import sys
                    exc_type, exc_value, _ = sys.exc_info()
                    QMessageBox.critical(self, "Ошибка", "Не удалось создать политику")
                    logger.error(f"Failed to create policy: {exc_value}")
            else:
                # Обновление существующей политики
                policy_name = f"policy_{self.policy_id}"
                try:
                    self.policy_manager.save_policy(policy_name, policy_data)
                    QMessageBox.information(self, "Успех", "Политика успешно обновлена")
                    logger.info(f"Updated policy with ID: {self.policy_id}")
                except Exception:
                    import sys
                    exc_type, exc_value, _ = sys.exc_info()
                    QMessageBox.critical(self, "Ошибка", "Не удалось обновить политику")
                    logger.error(f"Failed to update policy with ID: {self.policy_id}: {exc_value}")

            self.accept()
        except Exception:
            import sys
            exc_type, exc_value, _ = sys.exc_info()
            logger.error(f"Error saving policy: {exc_value}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить политику: {exc_value}")
