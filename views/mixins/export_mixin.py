"""
Миксин для функциональности экспорта данных
"""
from PyQt5.QtWidgets import QWidget
from utils import error_handler
from utils.database import db
from utils.export_utils import ExportUtils


class ExportMixin(QWidget):
    """Миксин, предоставляющий функциональность экспорта данных"""

    def __init__(self, user_id: int):
        super().__init__()
        """
        Инициализация миксина

        Args:
            user_id: Идентификатор пользователя
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
            scans = db.get_scans_by_user(self.user_id)
            ExportUtils.export_data(self, scans, format_name, file_extension, self.user_id)
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
