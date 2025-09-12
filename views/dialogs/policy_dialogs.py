from typing import Optional
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QLineEdit, QTextEdit, QComboBox, QCheckBox,
                         QMessageBox, QFormLayout, QSpinBox, QGroupBox)

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
        self._setup_ui()
        self._load_policy()

    def _setup_ui(self) -> None:
        """Настройка пользовательского интерфейса"""
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.name_edit = QLineEdit()
        self.description_edit = QTextEdit()
        self.max_depth_spin = QSpinBox()
        self.max_depth_spin.setRange(1, 10)
        self.max_depth_spin.setValue(3)
        
        self.check_xss = QCheckBox("Проверять XSS уязвимости")
        self.check_sql = QCheckBox("Проверять SQL-инъекции")
        self.check_csrf = QCheckBox("Проверять CSRF уязвимости")
        self.check_forms = QCheckBox("Проверять формы")
        
        form_layout = QFormLayout()
        form_layout.addRow("Название:", self.name_edit)
        form_layout.addRow("Описание:", self.description_edit)
        form_layout.addRow("Макс. глубина:", self.max_depth_spin)
        
        checks_group = QGroupBox("Параметры сканирования")
        checks_layout = QVBoxLayout()
        checks_layout.addWidget(self.check_xss)
        checks_layout.addWidget(self.check_sql)
        checks_layout.addWidget(self.check_csrf)
        checks_layout.addWidget(self.check_forms)
        checks_group.setLayout(checks_layout)
        
        layout.addLayout(form_layout)
        layout.addWidget(checks_group)

    def _load_policy(self) -> None:
        """Загрузка существующей политики"""
        if self.policy_id is not None:
            try:
                policy = self.policy_manager.get_policy(self.policy_id)
                if policy:
                    self.name_edit.setText(policy.get('name', ''))
                    self.description_edit.setText(policy.get('description', ''))
                    self.max_depth_spin.setValue(policy.get('max_depth', 3))
                    
                    settings = policy.get('settings', {})
                    self.check_xss.setChecked(settings.get('check_xss', True))
                    self.check_sql.setChecked(settings.get('check_sql', True))
                    self.check_csrf.setChecked(settings.get('check_csrf', True))
                    self.check_forms.setChecked(settings.get('check_forms', True))
            except Exception as e:
                logger.error(f"Error loading policy {self.policy_id}: {e}")
                QMessageBox.critical(self, "Ошибка", "Не удалось загрузить политику безопасности")

    def get_policy_data(self) -> dict:
        """Получение данных политики из диалога"""
        return {
            'name': self.name_edit.text(),
            'description': self.description_edit.toPlainText(),
            'max_depth': self.max_depth_spin.value(),
            'settings': {
                'check_xss': self.check_xss.isChecked(),
                'check_sql': self.check_sql.isChecked(),
                'check_csrf': self.check_csrf.isChecked(),
                'check_forms': self.check_forms.isChecked()
            }
        }


class ScanSettingsDialog(QDialog):
    """Диалог настройки параметров сканирования"""
    
    def __init__(self, parent: Optional['QDialog'] = None):
        super().__init__(parent)
        self.setWindowTitle("Настройки сканирования")
        self.setMinimumWidth(400)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Настройка пользовательского интерфейса"""
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.policy_combo = QComboBox()
        self._load_policies()

        self.max_depth_spin = QSpinBox()
        self.max_depth_spin.setRange(1, 10)
        self.max_depth_spin.setValue(3)

        form_layout = QFormLayout()
        form_layout.addRow("Политика безопасности:", self.policy_combo)
        form_layout.addRow("Макс. глубина сканирования:", self.max_depth_spin)
        
        layout.addLayout(form_layout)

    def _load_policies(self) -> None:
        """Загрузка списка доступных политик"""
        try:
            policy_manager = PolicyManager()
            policies = policy_manager.get_all_policies()
            
            for policy in policies:
                self.policy_combo.addItem(policy.get('name', ''), policy.get('id'))
        except Exception as e:
            logger.error(f"Error loading policies: {e}")
            QMessageBox.warning(self, "Предупреждение", "Не удалось загрузить список политик")

    def get_settings(self) -> dict:
        """Получение настроек сканирования"""
        return {
            'policy_id': self.policy_combo.currentData(),
            'max_depth': self.max_depth_spin.value()
        }