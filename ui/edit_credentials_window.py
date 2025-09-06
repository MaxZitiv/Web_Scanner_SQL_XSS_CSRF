# ui/edit_credentials_window.py

import re
import bcrypt
from PyQt5.QtWidgets import (
    QDialog, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox
)
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QCloseEvent
from utils.database import db
from utils.logger import logger, log_and_notify
import sqlite3
from typing import Optional
from PyQt5.QtWidgets import QWidget


class EditCredentialsWindow(QDialog):
    # Сигнал для безопасного закрытия
    closed = pyqtSignal()

    def __init__(self, user_id: int, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.confirm_input: Optional[QLineEdit] = None
        self.password_input: Optional[QLineEdit] = None
        self.email_input: Optional[QLineEdit] = None
        self.username_input: Optional[QLineEdit] = None
        self.old_password_input: Optional[QLineEdit] = None
        self.setWindowFlags(Qt.WindowFlags(Qt.WindowType.Window) | Qt.WindowFlags(Qt.WindowType.WindowTitleHint) | Qt.WindowFlags(Qt.WindowType.CustomizeWindowHint))
        self.user_id = user_id
        self.parent_dashboard: Optional[QWidget] = parent
        self.setup_ui()
        self.load_current_data()
        logger.info("EditCredentialsWindow initialized")

    def setup_ui(self):
        """Инициализация интерфейса"""
        self.setWindowTitle("Редактирование учетных данных")
        self.setFixedSize(400, 350)  # Увеличиваем размер для дополнительного поля

        layout = QVBoxLayout()

        # Поля ввода
        from typing import List, Tuple
        fields: List[Tuple[str, QLineEdit]] = [
            ("Новое имя пользователя:", QLineEdit()),
            ("Новый Email:", QLineEdit()),
            ("Текущий пароль:", QLineEdit()),
            ("Новый пароль:", QLineEdit()),
            ("Повторите пароль:", QLineEdit())
        ]

        # Добавляем поля в layout
        for label, field in fields:
            # field имеет тип QLineEdit
            layout.addWidget(QLabel(label))
            layout.addWidget(field)

        # Настройка полей паролей
        # QLineEdit.Password - это константа со значением 2
        # Используем явное значение 2, так как это соответствует QLineEdit.Password
        password_mode: int = 2
        # Приводим int к EchoMode для совместимости с setEchoMode
        echo_mode = QLineEdit.EchoMode(password_mode)
        fields[2][1].setEchoMode(echo_mode)
        fields[3][1].setEchoMode(echo_mode)
        fields[4][1].setEchoMode(echo_mode)

        # Сохраняем ссылки на поля
        self.username_input = fields[0][1]
        self.email_input = fields[1][1]
        self.old_password_input = fields[2][1]
        self.password_input = fields[3][1]
        self.confirm_input = fields[4][1]

        # Добавляем поля в layout
        # Код перенесен выше, сразу после объявления fields

        # Кнопки
        buttons = QHBoxLayout()
        save_btn = QPushButton("Сохранить")
        cancel_btn = QPushButton("Отмена")
        buttons.addWidget(save_btn)
        buttons.addWidget(cancel_btn)

        # Подключение сигналов
        save_btn.clicked.connect(self.save_changes)
        cancel_btn.clicked.connect(self.hide)

        layout.addLayout(buttons)
        self.setLayout(layout)
        logger.info("EditCredentialsWindow UI setup completed")

    def load_current_data(self):
        """Загрузка текущих данных пользователя"""
        try:
            logger.info(f"Loading current data for user_id: {self.user_id}")
            user_info = db.get_user_by_id(self.user_id)
            if user_info and self.username_input and self.email_input:
                self.username_input.setText(user_info.get("username", ""))
                self.email_input.setText(user_info.get("email", ""))
                logger.info("Current data loaded successfully")
        except (ValueError, sqlite3.Error, KeyError, AttributeError) as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить данные: {str(e)}")
            log_and_notify('error', f"Failed to load current data: {str(e)}")
            self.hide()

    def save_changes(self):
        if not all([self.username_input, self.email_input, self.old_password_input, 
                   self.password_input, self.confirm_input]):
            QMessageBox.warning(self, "Ошибка", "Не удалось инициализировать поля ввода.")
            return
            
        new_username = self.username_input.text().strip() if self.username_input else ""
        new_email = self.email_input.text().strip() if self.email_input else ""
        old_password = self.old_password_input.text().strip() if self.old_password_input else ""
        new_password = self.password_input.text().strip() if self.password_input else ""
        confirm_password = self.confirm_input.text().strip() if self.confirm_input else ""

        if not all([new_username, new_email, old_password, new_password, confirm_password]):
            QMessageBox.warning(self, "Ошибка ввода", "Все поля должны быть заполнены.")
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Ошибка", "Новый пароль и его подтверждение не совпадают.")
            return

        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Получаем хеш старого пароля
            cursor.execute('SELECT password_hash FROM users WHERE id = ?', (self.user_id,))
            result = cursor.fetchone()
            if not result:
                QMessageBox.warning(self, "Ошибка", "Пользователь не найден.")
                conn.close()
                return

            stored_hash = result[0]
            if not bcrypt.checkpw(old_password.encode('utf-8'), stored_hash.encode('utf-8')):
                QMessageBox.warning(self, "Ошибка", "Текущий пароль неверен.")
                conn.close()
                return

            # Хешируем новый пароль
            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Используем новую функцию для обновления
            if db.update_user_credentials(self.user_id, new_username, new_email, new_hash):
                QMessageBox.information(self, "Успех", "Данные профиля успешно обновлены!")
                logger.info(f"User {self.user_id} updated profile.")

                # Обновляем информацию в родительском окне, если оно существует
                if self.parent_dashboard and hasattr(self.parent_dashboard, 'username'):
                    self.parent_dashboard.username = new_username
                if self.parent_dashboard and hasattr(self.parent_dashboard, 'update_profile_info'):
                    # Проверяем, что update_profile_info является вызываемым объектом
                    update_method = getattr(self.parent_dashboard, 'update_profile_info')
                    if callable(update_method):
                        update_method()
                
                self.close()
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось обновить профиль.")

        except (ValueError, sqlite3.Error, KeyError, AttributeError) as e:
            log_and_notify('error', f"Ошибка обновления профиля: {e}")
            QMessageBox.warning(self, "Ошибка", "Не удалось обновить профиль.")

    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Безопасное закрытие окна"""
        self.closed.emit()
        super().closeEvent(a0)

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Проверка валидности email"""
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None
