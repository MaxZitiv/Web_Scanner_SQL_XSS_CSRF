#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import faulthandler
import traceback
import signal
import argparse
from typing import Optional, Type, Any
import types
from PyQt5.QtWidgets import QApplication
from qasync import QEventLoop
import asyncio
import logging

# Добавляем корневую директорию проекта в sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui.main_window import MainWindow
from utils.logger import logger, log_and_notify
from utils.performance import performance_monitor, resource_manager
from utils.error_handler import error_handler
from models.user_model import UserModel

# Перенаправление stdout/stderr если они None
for stream_name, stream in [('stdout', sys.stdout), ('stderr', sys.stderr)]:
    if stream is None:
        setattr(sys, stream_name, open(os.devnull, 'w', encoding='utf-8'))

faulthandler.enable()
logger.info('FAULTHANDLER ENABLED, MAIN.PY START')

# Глобальные переменные
app_instance: Optional[QApplication] = None
main_window_instance: Optional[MainWindow] = None
event_loop: Any = None


def resource_path(relative_path: str) -> str:
    """Получить абсолютный путь к ресурсу (для PyInstaller и обычного запуска)."""
    base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base_path, relative_path)


def load_styles(app: QApplication) -> None:
    """Загрузка стилей из styles.qss."""
    style_path = resource_path("styles.qss")
    if os.path.exists(style_path):
        try:
            with open(style_path, "r", encoding="utf-8") as f:
                app.setStyleSheet(f.read())
            logger.info(f"Стили успешно загружены из: {style_path}")
        except Exception as e:
            logger.warning(f"Ошибка загрузки стилей: {e}")
    else:
        logger.warning(f"Файл стилей не найден: {style_path}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Web Scanner')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        default='INFO', help='Set logging level')
    parser.add_argument('--profile', action='store_true', help='Enable performance profiling')
    parser.add_argument('--url', type=str, help='URL to scan (CLI mode)')
    parser.add_argument('--username', type=str, help='Username for login (CLI mode)')
    parser.add_argument('--cli', action='store_true', help='Start in CLI mode after login')
    return parser.parse_args()


def excepthook(exc_type: Type[BaseException], exc_value: BaseException, exc_tb: Optional[types.TracebackType]) -> None:
    """Глобальный обработчик необработанных исключений."""
    try:
        with open("fatal_error.log", "a", encoding="utf-8") as f:
            f.write("\n--- Unhandled Exception ---\n")
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
    except Exception as e:
        log_and_notify('error', f"Failed to write fatal_error.log: {e}")

    logger.critical(f"Unhandled exception: {exc_type.__name__}: {exc_value}", exc_info=True)
    sys.__excepthook__(exc_type, exc_value, exc_tb)


sys.excepthook = excepthook


def graceful_shutdown(exit_code: int) -> int:
    global event_loop, app_instance

    logger.info("Starting graceful shutdown...")
    
    if event_loop is not None:
        try:
            # Простая проверка на существование методов
            if (hasattr(event_loop, 'is_closed') and 
                hasattr(event_loop, 'stop') and 
                not event_loop.is_closed()):
                event_loop.stop()
                logger.info("Event loop stopped gracefully")
        except Exception as e:
            logger.warning(f"Error stopping event loop: {e}")

    # Завершение приложения
    if app_instance is not None:
        try:
            app_instance.quit()
            logger.info("Application quit successfully")
        except Exception as e:
            logger.warning(f"Error quitting application: {e}")

    # Освобождение ресурсов
    try:
        from utils.database import db
        db.close_connection()
        logger.info("Database connection closed")
    except Exception as e:
        logger.warning(f"Error closing database connection: {e}")

    logger.info(f"Shutdown complete with exit code: {exit_code}")
    return exit_code


def signal_handler(signum: int, _: Any) -> None:
    """Обработчик сигналов для корректного завершения приложения"""
    logger.info(f"Received signal {signum}")
    graceful_shutdown(0)


def setup_signal_handlers() -> None:
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, signal_handler)
        logger.info("Signal handlers set up")
    except Exception as e:
        log_and_notify('error', f"Failed to set up signal handlers: {e}")


def setup_performance_monitoring(enable_profiling: bool = False) -> None:
    try:
        if enable_profiling:
            import cProfile
            profiler = cProfile.Profile()
            profiler.enable()
            resource_manager.register_resource('profiler', profiler, lambda p: p.disable())
            logger.info("Performance profiling enabled")
        else:
            logger.info("Performance monitoring enabled (basic)")
    except Exception as e:
        log_and_notify('error', f"Failed to enable profiling: {e}")


def run_cli_mode(url: Optional[str] = None, username: Optional[str] = None) -> int:
    """Запуск CLI режима"""
    try:
        from cli.cli_mode import run_cli_mode as cli_run
        return cli_run(url, username)
    except ImportError as e:
        logger.error(f"Failed to import CLI mode: {e}")
        print(f"Ошибка импорта CLI режима: {e}")
        return 1


def main() -> int:
    global app_instance, main_window_instance, event_loop

    args = parse_arguments()
    logger.setLevel(getattr(logging, args.log_level.upper()))
    if args.debug:
        logger.debug("Debug mode enabled")

    setup_signal_handlers()
    setup_performance_monitoring(args.profile)

    if args.url:
        return run_cli_mode(args.url, args.username)

    # Если указан флаг --cli, запускаем CLI режим после авторизации
    if args.cli:
        return run_cli_mode(None, args.username)

    exit_code = 0
    try:
        logger.info("Starting GUI application...")
        start_time = performance_monitor.start_timer()

        app_candidate = QApplication.instance()
        if not isinstance(app_candidate, QApplication):
            app_candidate = QApplication(sys.argv)
        app_instance = app_candidate
        load_styles(app_instance)

        loop = QEventLoop(app_instance)
        asyncio.set_event_loop(loop)
        event_loop = loop

        user_model = UserModel()
        main_window = MainWindow(user_model)
        main_window_instance = main_window
        main_window.show()

        startup_time = performance_monitor.end_timer("startup", start_time)
        logger.info(f"Startup complete in {startup_time:.2f}s")

        with loop:
            try:
                loop.run_forever()
            except Exception as e:
                logger.error(f"Exception in event loop: {e}")
                if not loop.is_closed():
                    try:
                        loop.stop()
                        logger.info("Event loop stopped gracefully")
                    except RuntimeError as runtime_error:
                        logger.warning(f"Event loop already stopped or closed: {runtime_error}")
            finally:
                if not loop.is_closed():
                    try:
                        loop.stop()
                        logger.info("Event loop stopped gracefully")
                    except RuntimeError as runtime_error:
                        logger.warning(f"Event loop already stopped or closed: {runtime_error}")

    except SystemExit as e:
        logger.info(f"SystemExit with code: {getattr(e, 'code', None)}")
        exit_code = int(getattr(e, 'code', 0) or 0)
    except Exception as e:
        logger.critical(f"Exception in main loop: {e}", exc_info=True)
        if app_instance:
            try:
                error_handler.show_error_message("Критическая ошибка", str(e))
            except Exception as e_msg:
                log_and_notify('error', f"Failed to show error dialog: {e_msg}")
        exit_code = 1
    finally:
        exit_code = graceful_shutdown(exit_code)

    return exit_code


if __name__ == "__main__":
    code = main()
    sys.exit(code)