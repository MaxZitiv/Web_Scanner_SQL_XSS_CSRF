#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import traceback
from typing import Optional, Callable, Any, Dict, TypedDict
from collections import deque
import time
from utils.logger import logger, log_and_notify


class ErrorEntry(TypedDict):
    """Структура записи об ошибке в кэше"""
    type: str
    message: str
    context: str
    timestamp: float


class ErrorHandler:
    """Централизованный обработчик ошибок"""

    def __init__(self):
        self.error_callbacks: Dict[str, Callable[..., Any]] = {}
        self.error_cache: deque[ErrorEntry] = deque(maxlen=100)  # Кэш последних 100 ошибок
        self.max_message_length = 1000  # Максимальная длина сообщения об ошибке
        self.setup_global_exception_handler()

    def setup_global_exception_handler(self):
        """Устанавливает глобальный обработчик исключений"""
        def global_exception_handler(exctype: type, value: BaseException, tb: Any):
            error_msg = ''.join(traceback.format_exception(exctype, value, tb))
            log_and_notify('error', f"Unhandled exception: {error_msg}")
            self.show_error_message("Критическая ошибка", str(value))
            sys.__excepthook__(exctype, value, tb)

        sys.excepthook = global_exception_handler

    def register_error_callback(self, error_type: str, callback: Callable[..., Any]):
        """Регистрирует callback для определенного типа ошибки"""
        self.error_callbacks[error_type] = callback

    def _truncate_message(self, message: str) -> str:
        """Обрезает сообщение до максимальной длины"""
        return message[:self.max_message_length] + "..." if len(message) > self.max_message_length else message

    def _add_to_cache(self, error_type: str, message: str, context: str = ""):
        """Добавляет ошибку в кэш"""
        self.error_cache.append({
            'type': error_type,
            'message': self._truncate_message(message),
            'context': context,
            'timestamp': time.time()
        })

    def clear_error_cache(self) -> None:
        """Очищает кэш ошибок"""
        self.error_cache.clear()
        logger.info("Error cache cleared")

    def get_error_statistics(self) -> Dict[str, int | Dict[str, int] | float]:
        """Возвращает статистику ошибок"""
        if not self.error_cache:
            return {'total_errors': 0, 'error_types': {}}

        error_types: Dict[str, int] = {}
        for error in self.error_cache:
            error_types[error['type']] = error_types.get(error['type'], 0) + 1

        return {
            'total_errors': len(self.error_cache),
            'error_types': error_types,
            'oldest_error': min(self.error_cache, key=lambda x: x['timestamp'])['timestamp'],
            'newest_error': max(self.error_cache, key=lambda x: x['timestamp'])['timestamp']
        }

    def handle_database_error(self, error: Exception, context: str = "") -> bool:
        """Обрабатывает ошибки базы данных"""
        msg = f"Database error in {context}: {str(error)}"
        log_and_notify('error', msg)

        err_str = str(error).lower()
        if "database is locked" in err_str:
            self.show_error_message("Ошибка базы данных", "База данных заблокирована. Попробуйте позже.")
            return True
        elif "no such table" in err_str:
            self.show_error_message("Ошибка базы данных", "Структура базы данных повреждена. Перезапустите приложение.")
            return True
        elif "disk full" in err_str:
            self.show_error_message("Ошибка базы данных", "Недостаточно места на диске.")
            return True
        elif "unique constraint" in err_str:
            self.show_error_message("Ошибка базы данных", "Запись с такими данными уже существует.")
            return True
        elif "foreign key constraint" in err_str:
            self.show_error_message("Ошибка базы данных", "Нарушение целостности данных. Проверьте связанные записи.")
            return True
        elif "database corrupted" in err_str or "malformed" in err_str:
            self.show_error_message("Ошибка базы данных", "База данных повреждена. Требуется восстановление.")
            return True
        elif "permission denied" in err_str:
            self.show_error_message("Ошибка базы данных", "Недостаточно прав для выполнения операции.")
            return True

        self.show_error_message("Ошибка базы данных", "Произошла ошибка при работе с базой данных.")
        return False

    def handle_network_error(self, error: Exception, context: str = "") -> bool:
        """Обрабатывает сетевые ошибки"""
        msg = f"Network error in {context}: {str(error)}"
        log_and_notify('error', msg)

        err_str = str(error).lower()
        if "timeout" in err_str:
            self.show_error_message("Ошибка сети", "Превышено время ожидания ответа от сервера.")
            return True
        elif "connection refused" in err_str:
            self.show_error_message("Ошибка сети", "Соединение отклонено сервером.")
            return True
        elif "dns" in err_str:
            self.show_error_message("Ошибка сети", "Не удалось разрешить имя сервера.")
            return True
        elif "ssl" in err_str or "certificate" in err_str:
            self.show_error_message("Ошибка сети", "Проблема с SSL-сертификатом сервера.")
            return True
        elif "too many redirects" in err_str:
            self.show_error_message("Ошибка сети", "Слишком много перенаправлений.")
            return True
        elif "connection reset" in err_str:
            self.show_error_message("Ошибка сети", "Соединение было сброшено.")
            return True

        self.show_error_message("Ошибка сети", "Произошла ошибка при подключении к сети.")
        return False

    def handle_validation_error(self, error: Exception, context: str = "") -> bool:
        """Обрабатывает ошибки валидации"""
        logger.warning(f"Validation error in {context}: {str(error)}")
        self.show_error_message("Ошибка валидации", str(error))
        return True

    def handle_permission_error(self, error: Exception, context: str = "") -> bool:
        """Обрабатывает ошибки прав доступа"""
        log_and_notify('error', f"Permission error in {context}: {str(error)}")
        self.show_error_message("Ошибка прав доступа", "Недостаточно прав для выполнения операции.")
        return True

    def handle_file_error(self, error: Exception, context: str = "") -> bool:
        """Обрабатывает ошибки файловой системы"""
        log_and_notify('error', f"File error in {context}: {str(error)}")

        err_str = str(error).lower()
        if "no such file" in err_str:
            self.show_error_message("Ошибка файла", "Файл не найден.")
            return True
        elif "permission denied" in err_str:
            self.show_error_message("Ошибка файла", "Нет прав доступа к файлу.")
            return True
        elif "disk full" in err_str:
            self.show_error_message("Ошибка файла", "Недостаточно места на диске.")
            return True

        self.show_error_message("Ошибка файла", "Произошла ошибка при работе с файлом.")
        return False
    
    def handle_error(self, error: Exception, context: str = "") -> bool:
        """Обрабатывает общие ошибки"""
        log_and_notify('error', f"Error in {context}: {str(error)}")
        self.show_error_message("Ошибка", str(error))
        return True

    def show_error_message(self, title: str, message: str, details: str = ""):
        """Показывает сообщение об ошибке пользователю"""
        try:
            from PyQt5.QtWidgets import QApplication, QMessageBox

            app = QApplication.instance()
            if app is None:
                log_and_notify('error', f"{title}: {message}")
                if details:
                    log_and_notify('error', f"Details: {details}")
                return

            msg: QMessageBox = QMessageBox()
            msg.setIcon(QMessageBox.Icon.Critical)
            msg.setWindowTitle(title)
            msg.setText(message)
            if details:
                msg.setDetailedText(details)
            msg.exec_()
        except Exception as e:
            log_and_notify('error', f"Unexpected error showing error message: {e}")

    def show_warning_message(self, title: str, message: str):
        """Показывает предупреждение пользователю"""
        logger.warning(f"{title}: {message}")

    def show_info_message(self, title: str, message: str):
        """Показывает информационное сообщение пользователю"""
        logger.info(f"{title}: {message}")

    def safe_execute(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Optional[Any]:
        """Безопасно выполняет функцию с обработкой ошибок"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log_and_notify('error', f"Error in safe_execute for {func.__name__}: {e}")
            logger.warning(f"{func.__name__} returned None due to exception.")
            return None

# Глобальный экземпляр обработчика ошибок
error_handler = ErrorHandler()

def handle_exception(func: Callable[..., Any]) -> Callable[..., Any]:
    """Декоратор для обработки исключений в функциях"""
    def wrapper(*args: Any, **kwargs: Any):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log_and_notify('error', f"Exception in {func.__name__}: {e}")
            error_handler.show_error_message("Ошибка", f"Произошла ошибка в {func.__name__}")
            return None
    return wrapper
