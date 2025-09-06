"""
Утилиты для экспорта данных в различные форматы
"""
from typing import List, Dict, Any
from PyQt5.QtWidgets import QFileDialog, QWidget
from utils.performance import get_local_timestamp
from utils import error_handler


class ExportUtils:
    """Класс с утилитами для экспорта данных"""

    @staticmethod
    def export_data(parent_widget: QWidget, scans: List[Dict[str, Any]], format_name: str, 
                   file_extension: str, user_id: int) -> bool:
        """
        Общий метод для экспорта данных в различные форматы

        Args:
            parent_widget: Родительский виджет для диалогов
            scans: Данные для экспорта
            format_name: Название формата (JSON, CSV и т.д.)
            file_extension: Расширение файла (json, csv и т.д.)
            user_id: ID пользователя

        Returns:
            bool: Успешность операции
        """
        if not scans:
            error_handler.show_warning_message("Нет данных", "Нет данных для экспорта")
            return False

        timestamp = get_local_timestamp().replace(':', '').replace(' ', '_')
        default_filename = f"security_report_{timestamp}.{file_extension}"

        path, _ = QFileDialog.getSaveFileName(
            parent_widget, "Сохранить отчет", default_filename, 
            f"{format_name} Files (*.{file_extension})"
        )

        if not path:
            return False

        # Динамический импорт нужной функции экспорта
        try:
            module = __import__('export.export', fromlist=[f'export_to_{file_extension}'])
            export_func = getattr(module, f'export_to_{file_extension}')

            if export_func(scans, path, user_id):
                error_handler.show_info_message(
                    "Экспорт завершён", 
                    f"Файл {format_name} успешно сохранён."
                )
                return True
            else:
                error_handler.show_error_message(
                    "Ошибка экспорта", 
                    f"Не удалось сохранить файл {format_name}."
                )
                return False
        except Exception as e:
            error_handler.handle_file_error(e, f"export_to_{file_extension}")
            return False
