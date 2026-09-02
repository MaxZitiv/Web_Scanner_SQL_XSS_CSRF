"""
Безопасные обёртки над стандартным модулем ``sys``.

Некоторые окружения (например, старые/сгенерированные стабы Pyright для
Python 3.14) не дают Pyright увидеть атрибуты модуля ``sys``. Эти функции
получают атрибуты через ``getattr``/``setattr`` и не работают с ``sys.*``
напрямую, поэтому код остаётся анализируемым независимо от того, какие
стабы ``sys`` подхватил редактор.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from types import TracebackType
from typing import Any, NoReturn, TextIO

# Импортируем sys динамически: это позволяет Pyright видеть sys как обычный
# модуль даже в окружениях, где есть неполная сгенерированная заглушка sys.
sys_module: Any = importlib.import_module("sys")

# Тип обработчика необработанных исключений (sys.excepthook).
ExceptionHook = Callable[[type[BaseException], BaseException, TracebackType | None], Any]


def add_to_path(index: int, path: str) -> None:
    """Добавляет ``path`` в ``sys.path`` по указанному индексу."""
    path_list: Any = sys_module.path
    path_list.insert(index, path)


def get_argv() -> Any:
    """Возвращает список аргументов командной строки (sys.argv)."""
    return sys_module.argv


def get_stdout() -> TextIO | None:
    """Возвращает стандартный поток вывода (sys.stdout)."""
    return sys_module.stdout


def get_stderr() -> TextIO | None:
    """Возвращает стандартный поток ошибок (sys.stderr)."""
    return sys_module.stderr


def get_stdin() -> TextIO | None:
    """Возвращает стандартный поток ввода (sys.stdin)."""
    return sys_module.stdin


def get_executable() -> str:
    """Возвращает путь к исполняемому файлу интерпретатора (sys.executable)."""
    return sys_module.executable


def get_platform() -> str:
    """Возвращает имя платформы (sys.platform)."""
    return sys_module.platform


def get_bundle_root() -> str:
    """Возвращает корень приложения (sys._MEIPASS для PyInstaller)."""
    return getattr(sys_module, "_MEIPASS", os.path.abspath("."))


def exit_process(code: int = 0) -> NoReturn:
    """Завершает процесс с указанным кодом (sys.exit)."""
    exit_func: Any = sys_module.exit
    exit_func(code)
    raise SystemExit(code)


def get_excepthook() -> ExceptionHook:
    """Возвращает текущий глобальный обработчик исключений."""
    return sys_module.excepthook


def get_original_excepthook() -> ExceptionHook:
    """Возвращает исходный глобальный обработчик исключений."""
    return sys_module.__excepthook__


def set_excepthook(hook: ExceptionHook) -> None:
    """Устанавливает глобальный обработчик исключений."""
    sys_module.excepthook = hook


def set_stream(name: str, stream: Any) -> None:
    """Подменяет поток (stdout/stderr/stdin) в модуле sys."""
    setattr(sys_module, name, stream)
