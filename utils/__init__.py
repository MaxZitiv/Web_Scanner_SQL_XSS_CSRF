"""
Утилиты для веб-сканера уязвимостей.

Этот модуль содержит вспомогательные функции и классы:
- database: работа с базой данных
- logger: система логирования
- error_handler: обработка ошибок
- performance: мониторинг производительности
- security: функции безопасности
- vulnerability_scanner: сканеры уязвимостей
- init_db: инициализация базы данных
"""

from .database import db
from .logger import logger, log_and_notify
from .error_handler import error_handler
from .performance import (
    measure_time, 
    performance_monitor, 
    get_local_timestamp,
    measure_async_time,
    format_duration
)
from .security import validate_password_strength, is_safe_url, sanitize_filename
from .vulnerability_scanner import scan_sql_injection, scan_xss, scan_csrf
from .init_db import create_base_tables as init_database
from .cache_cleanup import cleanup_on_exit

__all__ = [
    'logger', 'log_and_notify', 'error_handler', 'measure_time', 'performance_monitor', 'get_local_timestamp', 'measure_async_time', 'format_duration',
    'validate_password_strength', 'is_safe_url', 'sanitize_filename',
    'scan_sql_injection', 'scan_xss', 'scan_csrf', 'init_database',
    'cleanup_on_exit',
]
