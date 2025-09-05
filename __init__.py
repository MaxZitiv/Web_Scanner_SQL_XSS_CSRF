"""
Web Scanner SQL XSS CSRF - Веб-сканер для поиска уязвимостей

Этот проект представляет собой комплексное решение для сканирования веб-приложений
на предмет уязвимостей SQL Injection, Cross-Site Scripting (XSS) и Cross-Site Request Forgery (CSRF).

Основные возможности:
- Сканирование SQL Injection уязвимостей
- Обнаружение XSS уязвимостей
- Проверка CSRF защиты
- Графический интерфейс на PyQt5
- Асинхронное сканирование
- Шифрование чувствительных данных
- Подробное логирование
- Экспорт результатов

Версия: 1.0.0
Автор: Manokuz
"""

__version__ = "1.0.0"
__author__ = "Web Scanner Team"
__email__ = "support@webscanner.com"

# Основные константы
APP_NAME = "Web Scanner SQL XSS CSRF"
APP_VERSION = __version__
DEFAULT_TIMEOUT = 30
MAX_CONCURRENT_REQUESTS = 10
MAX_SCAN_DEPTH = 3

# Типы уязвимостей
VULNERABILITY_TYPES = {
    'sql': 'SQL Injection',
    'xss': 'Cross-Site Scripting',
    'csrf': 'Cross-Site Request Forgery'
}

# Уровни логирования
LOG_LEVELS = {
    'DEBUG': 10,
    'INFO': 20,
    'WARNING': 30,
    'ERROR': 40,
    'CRITICAL': 50
}

# Настройки базы данных
DB_SETTINGS = {
    'timeout': 20,
    'max_connections': 10,
    'backup_count': 5,
    'max_size_mb': 10
}

# Настройки шифрования
ENCRYPTION_SETTINGS = {
    'algorithm': 'AES-256-GCM',
    'key_length': 32,
    'salt_length': 16
}

# Настройки сканера
SCANNER_SETTINGS = {
    'max_payloads_per_url': 40,
    'max_forms_per_url': 20,
    'request_delay': 0.1,
    'retry_attempts': 3
}

def get_version():
    """Возвращает версию приложения"""
    return __version__

def get_app_info():
    """Возвращает информацию о приложении"""
    return {
        'name': APP_NAME,
        'version': APP_VERSION,
        'author': __author__,
        'email': __email__
    }

def validate_config():
    """Проверяет корректность конфигурации"""
    try:
        # Проверяем основные настройки
        if DEFAULT_TIMEOUT <= 0:
            raise ValueError("DEFAULT_TIMEOUT должен быть положительным")
        if MAX_CONCURRENT_REQUESTS <= 0:
            raise ValueError("MAX_CONCURRENT_REQUESTS должен быть положительным")
        if MAX_SCAN_DEPTH <= 0:
            raise ValueError("MAX_SCAN_DEPTH должен быть положительным")
        
        # Проверяем типы уязвимостей
        if not all(isinstance(k, str) and isinstance(v, str) 
                  for k, v in VULNERABILITY_TYPES.items()):
            raise TypeError("VULNERABILITY_TYPES должен содержать строки")
        
        # Проверяем уровни логирования
        if not all(isinstance(k, str) and isinstance(v, int) 
                  for k, v in LOG_LEVELS.items()):
            raise TypeError("LOG_LEVELS должен содержать строки и числа")
        
        return True
    except (ValueError, TypeError) as e:
        print(f"Ошибка конфигурации: {e}")
        return False
    except Exception as e:
        print(f"Неожиданная ошибка при проверке конфигурации: {e}")
        return False

# Проверяем конфигурацию при импорте
if not validate_config():
    raise RuntimeError("Некорректная конфигурация приложения") 