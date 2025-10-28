from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox
from PyQt5.QtCore import pyqtSignal
from typing import Optional
from utils.logger import logger
import os


class ModeSelectionWindow(QWidget):
    mode_selected = pyqtSignal(str, int, str)  # mode, user_id, username

    def __init__(self, user_id: int, username: str, parent: Optional['QWidget'] = None):
        super().__init__(parent)
        self.user_id = user_id
        self.username = username
        self.init_ui()
        self.load_styles()
        logger.info("ModeSelectionWindow initialized.")

    def load_styles(self):
        """Загрузка стилей из файла styles.qss"""
        try:
            from main import resource_path
            style_path = resource_path("styles.qss")
            if os.path.exists(style_path):
                with open(style_path, 'r', encoding='utf-8') as f:
                    self.setStyleSheet(f.read())
                logger.info("Стили успешно загружены для окна выбора режима")
            else:
                logger.warning(f"Файл стилей styles.qss не найден: {style_path}")
        except Exception as e:
            logger.error(f"Ошибка при загрузке стилей: {e}")

    def init_ui(self):
        self.setWindowTitle("Выбор режима работы")
        self.setMinimumSize(400, 300)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Заголовок
        title = QLabel("Выберите режим работы")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)

        # Информация о пользователе
        user_info = QLabel(f"Вы вошли как: {self.username}")
        user_info.setStyleSheet("font-style: italic; margin-bottom: 20px;")
        layout.addWidget(user_info)

        # Описание режимов
        gui_desc = QLabel("GUI режим: Графический интерфейс для удобного использования сканера")
        gui_desc.setWordWrap(True)
        layout.addWidget(gui_desc)

        cli_desc = QLabel("CLI режим: Интерфейс командной строки для автоматизации и скриптинга")
        cli_desc.setWordWrap(True)
        layout.addWidget(cli_desc)

        # Кнопки выбора режима
        self.gui_button = QPushButton("GUI режим")
        self.gui_button.clicked.connect(self.select_gui_mode)
        self.gui_button.setMinimumHeight(40)
        layout.addWidget(self.gui_button)

        self.cli_button = QPushButton("CLI режим")
        self.cli_button.clicked.connect(self.select_cli_mode)
        self.cli_button.setMinimumHeight(40)
        layout.addWidget(self.cli_button)

        self.setLayout(layout)

    def select_gui_mode(self):
        logger.info(f"User {self.username} selected GUI mode")
        self.mode_selected.emit("gui", self.user_id, self.username)

    def select_cli_mode(self):
        # Подтверждение перехода в CLI режим
        reply = QMessageBox.question(
            self, 
            "Подтверждение", 
            "Вы уверены, что хотите перейти в CLI режим? Графический интерфейс будет закрыт.",
            QMessageBox.StandardButtons(QMessageBox.StandardButton.Yes) | (QMessageBox.StandardButton.No)
        )

        if reply == QMessageBox.StandardButton.Yes:
            logger.info(f"User {self.username} selected CLI mode")
            self.mode_selected.emit("cli", self.user_id, self.username)
