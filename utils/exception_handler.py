#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Универсальный обработчик ошибок и исключений для веб-сканера
"""

import sys
import time
from typing import Optional, Callable, Any, Dict, Awaitable
from functools import wraps
from contextlib import contextmanager
from collections import deque
from PyQt5.QtWidgets import QApplication, QMessageBox
from utils.logger import logger, log_and_notify

class UnifiedErrorHandler:
    """Централизованный обработчик ошибок с GUI и стратегиями восстановления"""
    
    def __init__(self, max_cache: int = 100, max_retries: int = 3):
        self.error_cache: deque[Dict[str, Any]] = deque(maxlen=max_cache)  # последние N ошибок
        self.error_counts: Dict[str, int] = {}
        self.recovery_strategies: Dict[str, Callable[..., Any]] = {}
        self.max_retries = max_retries
        self.max_message_length = 1000
        self.setup_default_strategies()
        self.setup_global_exception_handler()
    
    # -------------------- GUI сообщения -------------------- #
    def show_error_message(self, title: str, message: str, details: str = ""):
        try:
            app = QApplication.instance()
            if app is None:
                logger.error(f"{title}: {message}")
                if details:
                    logger.error(f"Details: {details}")
                return
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Icon.Critical)
            msg.setWindowTitle(title)
            msg.setText(message)
            if details:
                msg.setDetailedText(details)
            msg.exec_()
        except Exception as e:
            logger.error(f"Failed to show error message: {e}", exc_info=True)
            log_and_notify("error", f"{title}: {message}\nDetails: {details}")

    def show_warning_message(self, title: str, message: str):
        logger.warning(f"{title}: {message}")

    def show_info_message(self, title: str, message: str):
        logger.info(f"{title}: {message}")
    
    # -------------------- Стратегии восстановления -------------------- #
    def setup_default_strategies(self):
        self.recovery_strategies.update({
            'ConnectionError': self._retry_strategy,
            'TimeoutError': self._retry_strategy,
            'OSError': self._retry_strategy,
            'IOError': self._retry_strategy,
            'FileNotFoundError': self._create_file_if_missing,
            'PermissionError': self._log_permission_error,
            'ValueError': self._log_and_continue,
            'TypeError': self._log_and_continue,
            'AttributeError': self._log_and_continue,
            'KeyError': self._log_and_continue,
            'IndexError': self._log_and_continue,
        })
    
    def _retry_strategy(self, exc: Exception, context: str, attempt: int) -> bool:
        if attempt < self.max_retries:
            delay = min(2 ** attempt, 10)
            logger.info(f"Retrying {context} after {delay}s (attempt {attempt+1})")
            time.sleep(delay)
            return True
        logger.error(f"Max retries exceeded for {context}")
        return False

    def _log_and_continue(self, exc: Exception, context: str, attempt: int) -> bool:
        logger.warning(f"Continuing after {type(exc).__name__} in {context}")
        return True

    def _create_file_if_missing(self, exc: Exception, context: str, attempt: int) -> bool:
        import os
        if "No such file" in str(exc):
            try:
                file_path = str(exc).split("'")[1] if "'" in str(exc) else ""
                if file_path and not os.path.exists(file_path):
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    logger.info(f"Created missing directory for {file_path}")
                    return True
            except Exception as e:
                logger.error(f"Failed to create missing file: {e}", exc_info=True)
        return False

    def _log_permission_error(self, exc: Exception, context: str, attempt: int) -> bool:
        logger.error(f"Permission denied in {context}: {exc}")
        return False
    
    # -------------------- Обработка исключений -------------------- #
    def handle_exception(self, exc: Exception, context: str = "", attempt: int = 0) -> bool:
        exc_type = type(exc).__name__
        self.error_counts[exc_type] = self.error_counts.get(exc_type, 0) + 1
        self._add_to_cache(exc_type, str(exc), context)
        logger.error(f"Exception in {context}: {exc_type}: {exc}", exc_info=True)

        strategy = self.recovery_strategies.get(exc_type, self._default_strategy)
        try:
            return strategy(exc, context, attempt)
        except Exception as e:
            logger.error(f"Error in recovery strategy for {exc_type}: {e}", exc_info=True)
            return False

    def _default_strategy(self, exc: Exception, context: str, attempt: int) -> bool:
        logger.error(f"Unhandled exception type {type(exc).__name__} in {context}")
        return False
    
    # -------------------- Кэш ошибок -------------------- #
    def _add_to_cache(self, exc_type: str, message: str, context: str):
        self.error_cache.append({
            'type': exc_type,
            'message': message[:self.max_message_length],
            'context': context,
            'timestamp': time.time()
        })

    def get_error_statistics(self) -> Dict[str, Any]:
        most_common = max(self.error_counts.items(), key=lambda x: x[1]) if self.error_counts else None
        return {
            'total_errors': sum(self.error_counts.values()),
            'error_counts': self.error_counts.copy(),
            'most_common': most_common,
            'cached_errors': list(self.error_cache)
        }

    def clear_statistics(self):
        self.error_counts.clear()
        self.error_cache.clear()
        logger.info("Error statistics cleared")
    
    # -------------------- Контекстные менеджеры / декораторы -------------------- #
    def safe_execute(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Optional[Any]:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.handle_exception(e, f"safe_execute({func.__name__})")
            return None

    def retry_on_exception(self, max_retries: int = 3, exceptions: tuple[type[Exception], ...] = (Exception,)):
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                for attempt in range(max_retries + 1):
                    try:
                        return func(*args, **kwargs)
                    except exceptions as e:
                        handled = self.handle_exception(e, f"{func.__name__}", attempt)
                        if attempt == max_retries or not handled:
                            raise
                return None
            return wrapper
        return decorator

    @contextmanager
    def exception_context(self, context_name: str):
        try:
            yield
        except Exception as e:
            self.handle_exception(e, context_name)
            raise

    def handle_async_exception(self, coro: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await coro(*args, **kwargs)
            except Exception as e:
                self.handle_exception(e, f"async_{coro.__name__}")
                return None
        return wrapper
    
    # -------------------- Глобальный обработчик -------------------- #
    def setup_global_exception_handler(self):
        def global_handler(exctype: type[BaseException], value: BaseException, tb: Any):
            if isinstance(value, Exception):
                self.handle_exception(value, "global_handler")
            else:
                # Для системных исключений (KeyboardInterrupt, SystemExit) просто логируем
                logger.error(f"Unhandled system exception: {type(value).__name__}: {value}")
            sys.__excepthook__(exctype, value, tb)
        sys.excepthook = global_handler
        logger.info("Global exception handler configured")

# -------------------- Глобальный экземпляр -------------------- #
error_handler = UnifiedErrorHandler()
