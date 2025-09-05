import re
import hashlib
import secrets
from typing import Optional, Tuple, Dict, Set
from urllib.parse import urlparse
import ipaddress
import sqlite3
import time
from collections import defaultdict
from utils.logger import logger, log_and_notify

# Кэш для частых проверок
_validation_cache = {}
_cache_ttl = 300  # 5 минут
_cache_timestamps = {}

# Известные опасные домены и паттерны
DANGEROUS_DOMAINS = {
    'localhost', '127.0.0.1', '::1', '255.255.255.255',
    'example.com', 'test.com', 'invalid.com'
}

# Особо опасные адреса, требующие дополнительной проверки
# ВНИМАНИЕ: Использование 0.0.0.0 может создать угрозу безопасности
# Закомментировано для предотвращения случайного использования в продакшене
# CRITICAL_BIND_ADDRESSES = {
#     '0.0.0.0'  # Привязка ко всем интерфейсам (требует дополнительной проверки безопасности)
# }

# Безопасные адреса для привязки по умолчанию
SAFE_BIND_ADDRESSES = {
    '127.0.0.1',  # Только локальный интерфейс
    'localhost'   # Только локальный хост
}

# Функция для проверки безопасности при использовании критических адресов
def is_bind_address_safe(bind_address, config=None):
    """
    Проверяет, безопасно ли использование указанного адреса для привязки.

    Args:
        bind_address (str): Адрес для проверки
        config (dict, optional): Дополнительные параметры конфигурации

    Returns:
        tuple: (bool, str) - (безопасно ли использовать, сообщение с предупреждением)
    """
    # Проверка на использование безопасных адресов
    if bind_address in SAFE_BIND_ADDRESSES:
        return True, "Используется безопасный адрес привязки"

    # Проверка на использование критических адресов (раскомментированных при необходимости)
    try:
        # Проверяем, определена ли переменная CRITICAL_BIND_ADDRESSES
        critical_addresses = globals().get('CRITICAL_BIND_ADDRESSES', set())
        if bind_address in critical_addresses:
            # Для 0.0.0.0 требуются дополнительные проверки безопасности
            if config and config.get('firewall_enabled', False) and config.get('explicit_auth_enabled', False):
                return True, "Используется привязка ко всем интерфейсам с включенными защитными мерами"
            return False, "Использование привязки ко всем интерфейсам без должных мер безопасности небезопасно"
    except NameError:
        # CRITICAL_BIND_ADDRESSES закомментирован, считаем все адреса кроме SAFE_BIND_ADDRESSES небезопасными
        pass

    # Все остальные адреса считаем небезопасными
    return False, f"Адрес привязки '{bind_address}' не входит в список разрешенных и может быть небезопасен"

DANGEROUS_PATTERNS = [
    r'javascript:', r'data:', r'vbscript:', r'file:', r'ftp:',
    r'<script', r'<iframe', r'<object', r'<embed',
    r'javascript\s*:', r'on\w+\s*=', r'expression\s*\('
]

def _get_cached_result(key: str) -> Optional[bool]:
    """Получает результат из кэша"""
    if key in _validation_cache:
        if time.time() - _cache_timestamps.get(key, 0) < _cache_ttl:
            return _validation_cache[key]
        else:
            # Удаляем устаревший результат
            del _validation_cache[key]
            if key in _cache_timestamps:
                del _cache_timestamps[key]
    return None

def _cache_result(key: str, result: bool) -> None:
    """Сохраняет результат в кэш"""
    _validation_cache[key] = result
    _cache_timestamps[key] = time.time()
    
    # Очищаем старые записи, если кэш слишком большой
    if len(_validation_cache) > 1000:
        oldest_key = min(_cache_timestamps.keys(), key=lambda k: _cache_timestamps[k])
        del _validation_cache[oldest_key]
        del _cache_timestamps[oldest_key]

def validate_input_length(text: str, min_length: int = 1, max_length: int = 255) -> bool:
    """
    Проверяет длину входных данных.
    
    Args:
        text: Текст для проверки
        min_length: Минимальная длина (по умолчанию 1)
        max_length: Максимальная длина (по умолчанию 255)
    
    Returns:
        bool: True если длина корректна
    """
    if not isinstance(text, str):
        return False
    
    # Проверяем кэш
    cache_key = f"length_{hash(text)}_{min_length}_{max_length}"
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    result = min_length <= len(text) <= max_length
    _cache_result(cache_key, result)
    return result

def sanitize_filename(filename: str) -> str:
    """
    Очищает имя файла от потенциально опасных символов.
    
    Args:
        filename: Исходное имя файла
    
    Returns:
        str: Очищенное имя файла
    """
    if not filename:
        return ""
    
    # Удаляем опасные символы
    filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '', filename)
    
    # Ограничиваем длину
    if len(filename) > 255:
        filename = filename[:255]
    
    # Удаляем точки в начале и конце
    filename = filename.strip('.')
    
    # Заменяем множественные пробелы на один
    filename = re.sub(r'\s+', ' ', filename)
    
    return filename

def validate_ip_address(ip: str) -> bool:
    """
    Проверяет валидность IP адреса.
    
    Args:
        ip: IP адрес для проверки
    
    Returns:
        bool: True если IP адрес валиден
    """
    if not isinstance(ip, str):
        return False
    
    # Проверяем кэш
    cache_key = f"ip_{ip}"
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        ipaddress.ip_address(ip)
        result = True
    except ValueError:
        result = False
    
    _cache_result(cache_key, result)
    return result

def is_safe_url(url: str) -> bool:
    """
    Проверяет безопасность URL.
    
    Args:
        url: URL для проверки
    
    Returns:
        bool: True если URL безопасен
    """
    if not url or not isinstance(url, str):
        return False
    
    # Проверяем кэш
    cache_key = f"url_{hash(url)}"
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        parsed = urlparse(url)
        
        # Проверяем протокол
        if parsed.scheme not in ['http', 'https']:
            _cache_result(cache_key, False)
            return False
        
        # Проверяем домен
        if not parsed.netloc:
            _cache_result(cache_key, False)
            return False
        
        # Проверяем на опасные домены
        if parsed.netloc.lower() in DANGEROUS_DOMAINS:
            _cache_result(cache_key, False)
            return False
        
        # Проверяем на приватные IP адреса
        try:
            ip = ipaddress.ip_address(parsed.netloc)
            if ip.is_private:
                _cache_result(cache_key, False)
                return False
        except ValueError:
            # Это не IP адрес, проверяем домен
            logger.debug(f"Value {parsed.netloc} is not a valid IP address, checking as domain")
        
        # Проверяем на опасные паттерны в URL
        url_lower = url.lower()
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, url_lower):
                _cache_result(cache_key, False)
                return False
        
        result = True
        _cache_result(cache_key, result)
        return result
    except (ValueError, sqlite3.Error, KeyError, AttributeError) as e:
        log_and_notify('error', f"Error validating URL {url}: {e}")
        _cache_result(cache_key, False)
        return False

def generate_secure_token(length: int = 32) -> str:
    """
    Генерирует безопасный токен.
    
    Args:
        length: Длина токена (по умолчанию 32)
    
    Returns:
        str: Безопасный токен
    """
    if length <= 0 or length > 1024:
        raise ValueError("Token length must be between 1 and 1024")
    
    return secrets.token_urlsafe(length)

def hash_sensitive_data(data: str) -> str:
    """
    Хеширует чувствительные данные.
    
    Args:
        data: Данные для хеширования
    
    Returns:
        str: SHA-256 хеш данных
    """
    if not isinstance(data, str):
        raise ValueError("Data must be a string")
    
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def validate_password_strength(password: str) -> int:
    """
    Проверяет сложность пароля и возвращает балл от 0 до 5.
    
    Args:
        password: Пароль для проверки
    
    Returns:
        int: Балл от 0 до 5
    """
    if not password or not isinstance(password, str):
        return 0
    
    score = 0
    
    # Базовый балл за длину
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    
    # Проверяем наличие заглавных букв
    if re.search(r'[A-Z]', password):
        score += 1
    
    # Проверяем наличие строчных букв
    if re.search(r'[a-z]', password):
        score += 1
    
    # Проверяем наличие цифр
    if re.search(r'\d', password):
        score += 1
    
    # Проверяем наличие специальных символов
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        score += 1
    
    # Дополнительные проверки
    # Штраф за повторяющиеся символы
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 1)
    
    # Штраф за последовательности
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        score = max(0, score - 1)
    
    return min(score, 5)  # Максимальный балл 5

def rate_limit_check(identifier: str, attempts: dict, max_attempts: int = 5, window_seconds: int = 300) -> bool:
    """
    Проверяет ограничение скорости запросов.
    
    Args:
        identifier: Идентификатор (IP, пользователь и т.д.)
        attempts: Словарь с попытками
        max_attempts: Максимальное количество попыток
        window_seconds: Временное окно в секундах
    
    Returns:
        bool: True если запрос разрешен
    """
    current_time = time.time()
    
    # Очищаем старые попытки
    if identifier in attempts:
        attempts[identifier] = [
            attempt_time for attempt_time in attempts[identifier]
            if current_time - attempt_time < window_seconds
        ]
        
        # Проверяем количество попыток
        if len(attempts[identifier]) >= max_attempts:
            logger.warning(f"Rate limit exceeded for {identifier}: {len(attempts[identifier])} attempts")
            return False
        
        attempts[identifier].append(current_time)
    else:
        attempts[identifier] = [current_time]
    
    return True

def sanitize_sql_input(text: str) -> str:
    """
    Очищает входные данные для SQL запросов.
    
    Args:
        text: Текст для очистки
    
    Returns:
        str: Очищенный текст
    """
    if not text or not isinstance(text, str):
        return ""
    
    # Удаляем потенциально опасные SQL символы
    dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_', 'union', 'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'exec', 'execute']
    sanitized = text
    
    for char in dangerous_chars:
        sanitized = re.sub(re.escape(char), '', sanitized, flags=re.IGNORECASE)
    
    return sanitized.strip()

def validate_email_format(email: str) -> bool:
    """
    Проверяет формат email адреса.
    
    Args:
        email: Email для проверки
    
    Returns:
        bool: True если email валиден
    """
    if not email or not isinstance(email, str):
        return False
    
    # Проверяем кэш
    cache_key = f"email_{hash(email)}"
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    # Более строгая проверка email
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    result = bool(re.match(pattern, email)) and len(email) <= 254
    
    _cache_result(cache_key, result)
    return result

def check_file_extension(filename: str, allowed_extensions: list) -> bool:
    """
    Проверяет расширение файла.
    
    Args:
        filename: Имя файла
        allowed_extensions: Список разрешенных расширений
    
    Returns:
        bool: True если расширение разрешено
    """
    if not filename or not isinstance(filename, str):
        return False
    
    file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
    return file_ext in allowed_extensions

def clear_security_cache() -> None:
    """Очищает кэш безопасности"""
    global _validation_cache, _cache_timestamps
    _validation_cache.clear()
    _cache_timestamps.clear()
    logger.info("Security cache cleared")

def get_security_cache_stats() -> Dict[str, int]:
    """Возвращает статистику кэша безопасности"""
    return {
        'cache_size': len(_validation_cache),
        'timestamp_size': len(_cache_timestamps)
    }