"""
Миксин для функциональности экспорта данных
"""
from typing import Optional, Any
from PyQt5.QtWidgets import QWidget
from utils import error_handler
from utils.database import db
from utils.export_utils import ExportUtils


class ExportMixin:
    """Миксин, предоставляющий функциональность экспорта данных"""

    def __init__(self, user_id: Optional[int] = None):
        """
        Инициализация миксина

        Args:
            user_id: Идентификатор пользователя (опционально)
        """
        self.user_id = user_id

    def _export_data(self, format_name: str, file_extension: str) -> None:
        """
        Общий метод для экспорта данных в различные форматы

        Args:
            format_name: Название формата (JSON, CSV и т.д.)
            file_extension: Расширение файла (json, csv и т.д.)
        """
        try:
            # Если user_id не указан, пытаемся получить его из родительского класса
            user_id = self.user_id
            parent_widget: Optional[QWidget] = None
            
            # Проверяем, является ли сам экземпляр виджетом
            if isinstance(self, QWidget):
                parent_widget = self
            # Если нет, пытаемся получить родительский виджет
            elif hasattr(self, "parent") and callable(getattr(self, "parent", None)):
                parent = getattr(self, "parent")()
                if isinstance(parent, QWidget):
                    parent_widget = parent
            # Если user_id не указан, пытаемся получить его из родительского класса
            if user_id is None and parent_widget is not None and hasattr(parent_widget, "user_id"):
                user_id = getattr(parent_widget, "user_id", None)
            
            if user_id is not None:
                scans = db.get_scans_by_user(user_id)
                ExportUtils.export_data(parent_widget, scans, format_name, file_extension, user_id)
            else:
                # Если user_id так и не был найден, показываем сообщение об ошибке
                error_handler.show_error_message("Ошибка экспорта", "Не удалось определить идентификатор пользователя")
        except Exception as e:
            error_handler.handle_file_error(e, f"export_to_{file_extension}")

    def export_to_json(self) -> None:
        """Экспорт данных в формат JSON"""
        self._export_data("JSON", "json")

    def export_to_csv(self) -> None:
        """Экспорт данных в формат CSV"""
        self._export_data("CSV", "csv")

    def export_to_pdf(self) -> None:
        """Экспорт данных в формат PDF"""
        self._export_data("PDF", "pdf")

    def export_to_html(self) -> None:
        """Экспорт данных в формат HTML"""
        self._export_data("HTML", "html")
