import bcrypt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from utils.database import db
from utils.logger import logger, log_and_notify
import sqlite3


class EditProfileWindow(QWidget):
    def __init__(self, user_id, username, parent_dashboard):
        super().__init__()
        self.user_id = user_id
        self.username = username
        self.parent_dashboard = parent_dashboard

        self.setWindowTitle("Редактировать профиль")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # Новое имя пользователя
        layout.addWidget(QLabel("Новое имя пользователя:"))
        self.username_input = QLineEdit()
        self.username_input.setText(self.username)
        layout.addWidget(self.username_input)

        # Новый email
        layout.addWidget(QLabel("Новый Email:"))
        self.email_input = QLineEdit()
        layout.addWidget(self.email_input)

        # Старый пароль
        layout.addWidget(QLabel("Старый пароль:"))
        self.old_password_input = QLineEdit()
        self.old_password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.old_password_input)

        # Новый пароль
        layout.addWidget(QLabel("Новый пароль:"))
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.new_password_input)

        # Подтверждение нового пароля
        layout.addWidget(QLabel("Подтвердите новый пароль:"))
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_password_input)

        # Кнопка
        self.save_button = QPushButton("Сохранить изменения")
        self.save_button.clicked.connect(self.save_changes)
        layout.addWidget(self.save_button)

        self.setLayout(layout)

    def save_changes(self):
        new_username = self.username_input.text().strip()
        new_email = self.email_input.text().strip()
        old_password = self.old_password_input.text().strip()
        new_password = self.new_password_input.text().strip()
        confirm_password = self.confirm_password_input.text().strip()

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

            # Проверка правильности старого пароля
            if not bcrypt.checkpw(old_password.encode('utf-8'), stored_hash.encode('utf-8')):
                QMessageBox.warning(self, "Ошибка", "Старый пароль неверен.")
                conn.close()
                return

            # Хешируем новый пароль
            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Обновляем данные в БД
            cursor.execute(
                'UPDATE users SET username = ?, email = ?, password_hash = ? WHERE id = ?',
                (new_username, new_email, new_hash, self.user_id)
            )

            conn.commit()
            conn.close()

            QMessageBox.information(self, "Успех", "Данные профиля успешно обновлены!")
            logger.info(f"User {self.user_id} updated profile.")

            self.parent_dashboard.username = new_username
            self.parent_dashboard.update_profile_info()
            self.close()

        except (ValueError, sqlite3.Error, KeyError, AttributeError) as e:
            log_and_notify('error', f"Profile update error: {e}")
            QMessageBox.warning(self, "Ошибка", "Не удалось обновить профиль.")

