from PyQt5.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QHBoxLayout, QToolButton
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon
from utils.database import db
import os
from models.user_model import UserModel
import logging
import sqlite3

logger = logging.getLogger(__name__)


class RegistrationWindow(QWidget):
    def __init__(self, parent_login=None):
        super().__init__()
        self.parent_login = parent_login
        self.user_model = UserModel()

        self.setWindowTitle('Регистрация')
        
        # Убираем фиксированный размер
        self.setMinimumSize(400, 350)

        layout = QVBoxLayout()
        
        # Добавляем отступы для лучшего внешнего вида
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        # Заголовок
        title_label = QLabel('Регистрация нового пользователя')
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        layout.addWidget(QLabel('Имя пользователя:'))
        self.username = QLineEdit()
        self.username.setPlaceholderText('Введите имя пользователя (минимум 3 символа)')
        self.username.textChanged.connect(self.on_username_changed)
        layout.addWidget(self.username)

        # Статус имени пользователя
        self.username_status = QLabel('')
        layout.addWidget(self.username_status)

        layout.addWidget(QLabel('Email:'))
        self.email = QLineEdit()
        self.email.setPlaceholderText('Введите email адрес')
        self.email.textChanged.connect(self.on_email_changed)
        layout.addWidget(self.email)

        # Статус email
        self.email_status = QLabel('')
        layout.addWidget(self.email_status)

        layout.addWidget(QLabel('Пароль:'))
        self.password, password_row = self._create_password_input()
        layout.addLayout(password_row)

        layout.addWidget(QLabel('Подтвердите пароль:'))
        self.confirm_password, confirm_row = self._create_password_input()
        layout.addLayout(confirm_row)

        # Создаем горизонтальный layout для кнопок
        button_layout = QHBoxLayout()
        
        # Кнопка "Назад"
        self.btn_back = QPushButton('Назад')
        self.btn_back.clicked.connect(self.on_back)
        button_layout.addWidget(self.btn_back)
        
        # Кнопка "Зарегистрироваться"
        self.btn_register = QPushButton('Зарегистрироваться')
        self.btn_register.clicked.connect(self.on_register)
        button_layout.addWidget(self.btn_register)
        
        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.adjustSize()

        # Таймер для отложенной проверки
        self.check_timer = QTimer()
        self.check_timer.setSingleShot(True)
        self.check_timer.timeout.connect(self.check_availability)
        
        # Загружаем стили
        self.load_styles()

    @staticmethod
    def _create_password_input():
        line_edit = QLineEdit()
        line_edit.setEchoMode(QLineEdit.Password)

        toggle_button = QToolButton()
        toggle_button.setIcon(QIcon.fromTheme("view-password"))  # Используется системная иконка
        toggle_button.setCheckable(True)
        toggle_button.setChecked(False)

        def toggle_password():
            line_edit.setEchoMode(QLineEdit.Normal if toggle_button.isChecked() else QLineEdit.Password)

        toggle_button.clicked.connect(toggle_password)

        row = QHBoxLayout()
        row.setSpacing(0)  # Убираем отступ между полем и кнопкой
        row.addWidget(line_edit)
        row.addWidget(toggle_button)

        return line_edit, row

    def _schedule_check(self):
        """Планирует проверку доступности имени пользователя и email"""
        self.check_timer.stop()
        self.check_timer.start(500)  # Проверяем через 500мс после остановки ввода

    def on_username_changed(self):
        """Обработчик изменения имени пользователя"""
        self._schedule_check()

    def on_email_changed(self):
        """Обработчик изменения email"""
        self._schedule_check()

    def check_availability(self):
        """Проверка доступности username и email"""
        username = self.username.text().strip()
        email = self.email.text().strip()
        
        # Проверяем username
        if len(username) >= 3:
            if db.get_user_by_username_or_email(username):
                self.username_status.setText('❌ Имя пользователя уже занято')
                self.username_status.setStyleSheet("color: #d32f2f; font-size: 11px; margin: 2px;")
            else:
                self.username_status.setText('✅ Имя пользователя доступно')
                self.username_status.setStyleSheet("color: #388e3c; font-size: 11px; margin: 2px;")
        else:
            self.username_status.setText('')
        
        # Проверяем email
        if email and self.user_model.is_valid_email(email):
            if self.user_model.is_email_taken(email):
                self.email_status.setText('❌ Email уже используется')
                self.email_status.setStyleSheet("color: #d32f2f; font-size: 11px; margin: 2px;")
            else:
                self.email_status.setText('✅ Email доступен')
                self.email_status.setStyleSheet("color: #388e3c; font-size: 11px; margin: 2px;")
        elif email:
            self.email_status.setText('❌ Некорректный формат email')
            self.email_status.setStyleSheet("color: #d32f2f; font-size: 11px; margin: 2px;")
        else:
            self.email_status.setText('')

    def on_register(self):
        username = self.username.text().strip()
        email = self.email.text().strip()
        password = self.password.text()
        confirm_password = self.confirm_password.text()

        # Проверяем заполнение всех полей
        if not username or not email or not password or not confirm_password:
            QMessageBox.warning(self, 'Ошибка', 'Заполните все поля')
            return

        # Проверяем минимальную длину пароля
        if len(password) < 8:
            QMessageBox.warning(self, 'Ошибка', 'Пароль должен содержать минимум 8 символов')
            return

        # Проверяем совпадение паролей
        if password != confirm_password:
            QMessageBox.warning(self, 'Ошибка', 'Пароли не совпадают')
            return

        # Используем новую модель пользователя для валидации и создания
        try:
            success, message = self.user_model.create_user(username, email, password)
            
            if message:
                QMessageBox.warning(self, "Ошибка регистрации", message)
            elif success:
                QMessageBox.information(self, "Успех", "Регистрация прошла успешно! Теперь вы можете войти.")
                # Возвращаемся к окну входа - исправляем путь
                if self.parent_login and hasattr(self.parent_login, 'parent') and self.parent_login.parent:
                    parent = self.parent_login.parent
                    if hasattr(parent, 'go_to_login') and callable(parent.go_to_login):
                        parent.go_to_login()
                else:
                    self.close()
        except Exception as e:
            logger.error(f"Error during registration: {e}", exc_info=True)
            QMessageBox.critical(self, "Критическая ошибка", "Произошла непредвиденная ошибка при регистрации.")

    def on_back(self):
        """Обработчик нажатия кнопки 'Назад'"""
        if self.parent_login and hasattr(self.parent_login, 'parent') and self.parent_login.parent:
            parent = self.parent_login.parent
            if hasattr(parent, 'go_to_login') and callable(parent.go_to_login):
                parent.go_to_login()
        self.close()

    def load_styles(self):
        """Загрузка стилей из файла styles.qss"""
        try:
            style_path = 'styles.qss'
            if os.path.exists(style_path):
                with open(style_path, 'r', encoding='utf-8') as f:
                    self.setStyleSheet(f.read())
                logger.info("Стили успешно загружены для окна регистрации")
            else:
                logger.warning(f"Файл стилей styles.qss не найден: {style_path}")
        except (ValueError, sqlite3.Error, KeyError, AttributeError) as e:
            logger.error(f"Ошибка при загрузке стилей: {e}")

