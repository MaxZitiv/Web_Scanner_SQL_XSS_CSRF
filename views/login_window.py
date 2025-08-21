from PyQt5.QtWidgets import QWidget, QPushButton, QLineEdit, QVBoxLayout, QLabel, QMessageBox, QHBoxLayout
from controllers.auth_controller import AuthController
from utils.logger import logger, log_and_notify
import os
import sqlite3
from PyQt5.QtCore import pyqtSignal
from typing import Optional, Any


class LoginWindow(QWidget):
    login_successful = pyqtSignal(int, str)

    def __init__(self, user_model, parent: Optional[Any] = None):
        super().__init__(parent)
        self.user_model = user_model
        self.controller = AuthController(self.user_model)
        self.parent_window = parent
        self.init_ui()
        self.load_styles()
        logger.info("LoginWindow initialized.")

    def load_styles(self):
        """Загрузка стилей из файла styles.qss"""
        try:
            style_path = 'styles.qss'
            if os.path.exists(style_path):
                with open(style_path, 'r', encoding='utf-8') as f:
                    self.setStyleSheet(f.read())
                logger.info("Стили успешно загружены для окна авторизации")
            else:
                logger.warning(f"Файл стилей styles.qss не найден: {style_path}")
        except (ValueError, sqlite3.Error, KeyError, AttributeError, OSError) as e:
            log_and_notify('error', f"Ошибка при загрузке стилей: {e}")

    def init_ui(self):
        self.setWindowTitle("Вход в систему")

        # Поля
        self.username_label = QLabel("Имя пользователя или Email")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Введите имя пользователя или email")

        self.password_label = QLabel("Пароль")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Введите пароль")

        # Кнопка показа/скрытия пароля
        self.show_password_button = QPushButton("👁")
        self.show_password_button.setToolTip("Показать/скрыть пароль")
        self.show_password_button.setMaximumWidth(40)
        self.show_password_button.clicked.connect(self.toggle_password_visibility)
        
        # Контейнер для пароля и кнопки
        password_container = QHBoxLayout()
        password_container.addWidget(self.password_input)
        password_container.addWidget(self.show_password_button)

        self.login_button = QPushButton("Войти")
        self.login_button.clicked.connect(self.login)

        self.register_button = QPushButton("Регистрация")
        self.register_button.clicked.connect(self.register)

        # Вертикальный компоновщик
        layout = QVBoxLayout()
        
        # Добавляем отступы для лучшего внешнего вида
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addLayout(password_container)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)

        self.setLayout(layout)
        
        # Устанавливаем минимальный размер для предотвращения слишком маленького окна
        self.setMinimumSize(300, 200)
        
        # Вычисляем оптимальный размер на основе содержимого
        self.adjustSize()

        # Обработка Enter для каждого поля
        self.username_input.returnPressed.connect(self.login)
        self.password_input.returnPressed.connect(self.login)

        logger.debug("Login UI components created.")

    def set_loading_state(self, loading: bool):
        """Set loading state for UI elements."""
        self.login_button.setEnabled(not loading)
        self.register_button.setEnabled(not loading)
        self.username_input.setEnabled(not loading)
        self.password_input.setEnabled(not loading)
        self.show_password_button.setEnabled(not loading)
        if loading:
            self.login_button.setText("Вход...")
        else:
            self.login_button.setText("Войти")

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Ошибка", "Введите имя пользователя и пароль")
            return

        try:
            success, message = self.controller.login(username, password)
            if success:
                logger.info(f"User {username} logged in successfully.")
                user_id = self.user_model.get_user_id()
                username = self.user_model.get_username()
                if self.parent_window and user_id is not None:
                    self.parent_window.go_to_dashboard(user_id, username)
                else:
                    log_and_notify('error', "Parent window or user_id is not set")
                    QMessageBox.critical(self, "Ошибка", "Внутренняя ошибка приложения. Попробуйте перезапустить.")
            else:
                logger.warning(f"Failed login attempt for {username}: {message}")
                QMessageBox.warning(self, "Ошибка входа", message)
        except Exception as e:
            log_and_notify('error', f"An error occurred during login: {e}")
            QMessageBox.critical(self, "Критическая ошибка", "Произошла непредвиденная ошибка.")

    def register(self):
        try:
            if self.parent_window:
                self.parent_window.go_to_registration()
            else:
                log_and_notify('error', "Parent window is not set")
                QMessageBox.critical(self, "Ошибка", "Внутренняя ошибка приложения. Попробуйте перезапустить.")
        except (ValueError, KeyError, AttributeError, ImportError, sqlite3.Error, OSError) as e:
            log_and_notify('error', f"Error opening registration window: {e}")
            QMessageBox.critical(self, "Ошибка", "Не удалось открыть окно регистрации. Попробуйте позже.")

    def keyPressEvent(self, a0):
        # Удаляем дублирующий обработчик Enter, так как он уже обрабатывается
        # через returnPressed сигналы полей ввода
        super().keyPressEvent(a0)

    def toggle_password_visibility(self):
        """Переключает видимость пароля"""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_password_button.setText("🙈")
            self.show_password_button.setToolTip("Скрыть пароль")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_password_button.setText("👁")
            self.show_password_button.setToolTip("Показать пароль")

