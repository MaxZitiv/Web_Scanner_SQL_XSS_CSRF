import asyncio
import gc
import hashlib
import os
import re
import sqlite3
import time
from datetime import datetime
from functools import lru_cache
from typing import Dict, Set, Tuple, List, Optional, Any, Union, cast
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import aiohttp
from PyQt5.QtCore import pyqtSignal, QObject
from bs4 import BeautifulSoup, Tag

from utils.database import db
from utils.logger import logger, log_and_notify
from utils.performance import get_local_timestamp
from .TTL_cache import TTLCache

if TYPE_CHECKING:
    pass

# Вспомогательный класс для имитации ответа сервера
class EmptyResponse:
    """Класс для имитации ответа aiohttp.ClientResponse"""
    def __init__(self, status: int = 200):
        self.status = status

    @staticmethod
    async def text(errors: Optional[str] = None):
        return ""

# Кэши для оптимизации
HTML_CACHE: TTLCache = TTLCache(maxsize=100, ttl=300)
DNS_CACHE: TTLCache = TTLCache(maxsize=100, ttl=300)
FORM_HASH_CACHE: TTLCache = TTLCache(maxsize=100, ttl=300)
URL_PROCESSING_CACHE: TTLCache = TTLCache(maxsize=100, ttl=300)

# Очистка кэша каждые 1000 операций
CACHE_CLEANUP_THRESHOLD: int = 1000
cache_operations: int = 0

def cleanup_caches() -> None:
    """Очищает кэши для предотвращения утечек памяти"""
    global HTML_CACHE, DNS_CACHE, FORM_HASH_CACHE, URL_PROCESSING_CACHE, cache_operations
    if cache_operations > CACHE_CLEANUP_THRESHOLD:
        HTML_CACHE.clear()
        DNS_CACHE.clear()
        FORM_HASH_CACHE.clear()
        URL_PROCESSING_CACHE.clear()
        cache_operations = 0

def cleanup_cache_if_needed():
    """Добавляем очистку кэша при достижении порога"""
    global cache_operations
    cache_operations += 1
    cleanup_caches()
    logger.debug("Caches cleaned up")


# Оптимизированные настройки для BeautifulSoup
BS4_OPTIMIZATIONS: Dict[str, Union[str, List[str]]] = {
    'parser': 'html.parser',
    'features': 'html.parser',
    'exclude_parser': ['lxml', 'xml'],  # Исключаем медленные парсеры
}

# Кэшируем результат парсинга
@lru_cache(maxsize=100)
def parse_html_cached(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, parser='html.parser')

class Scanner(QObject):
    # Определение сигналов
    scan_started: pyqtSignal = pyqtSignal(str)
    scan_finished: pyqtSignal = pyqtSignal(str)
    error_occurred: pyqtSignal = pyqtSignal(str)
    vulnerability_found: pyqtSignal = pyqtSignal(str, str, str)


    def __init__(self) -> None:
        super().__init__()
        self._scan_in_progress: bool = False
        self._scan_results: List[Dict[str, Any]] = []
        self._current_url: str = ""
        self._scan_id: str = ""
        self._scan_options: Dict[str, Any] = {}
        self._scan_start_time: Optional[datetime] = None
        self._scan_end_time: Optional[datetime] = None
        self.should_stop: bool = False
        self._is_paused: bool = False

    async def _test_csrf_protection(self) -> None:
        # Тестирование CSRF защиты
        for payload in SAFE_CSRF_PAYLOADS:
            await self._test_payload(payload, "CSRF")

    @property
    def scan_in_progress(self) -> bool:
        return self._scan_in_progress

    @scan_in_progress.setter
    def scan_in_progress(self, value: bool) -> None:
        self._scan_in_progress = value

    @property
    def scan_results(self) -> List[Dict[str, Any]]:
        return self._scan_results

    @scan_results.setter
    def scan_results(self, value: List[Dict[str, Any]]) -> None:
        self._scan_results = value

    @property
    def current_url(self) -> str:
        # Инициализируем _current_url при первом использовании
        if not hasattr(self, '_current_url'):
            self._current_url = ""
        return self._current_url

    @current_url.setter
    def current_url(self, value: str) -> None:
        self._current_url = value

    @property
    def scan_id(self) -> str:
        return self._scan_id

    @scan_id.setter
    def scan_id(self, value: str) -> None:
        self._scan_id = value

    @property
    def scan_options(self) -> Dict[str, Any]:
        return self._scan_options

    @scan_options.setter
    def scan_options(self, value: Dict[str, Any]) -> None:
        self._scan_options = value

    def stop(self) -> None:
        """Останавливает сканирование."""
        self.should_stop = True

    def pause(self) -> None:
        """Приостанавливает сканирование."""
        self._is_paused = True

    def resume(self) -> None:
        """Возобновляет сканирование."""
        self._is_paused = False

    def is_paused(self) -> bool:
        """Проверяет, находится ли сканирование на паузе."""
        return self._is_paused

    @property
    def scan_start_time(self) -> Optional[datetime]:
        return self._scan_start_time

    @scan_start_time.setter
    def scan_start_time(self, value: datetime) -> None:
        self._scan_start_time = value

    @property
    def scan_end_time(self) -> Optional[datetime]:
        return self._scan_end_time

    @scan_end_time.setter
    def scan_end_time(self, value: datetime) -> None:
        self._scan_end_time = value

    async def start_scan(self, url: str, options: Dict[str, Any]) -> None:
        if self._scan_in_progress:
            raise Exception("Scan is already in progress")
        self._scan_in_progress = True
        self._scan_results = []
        self._current_url = url
        self._scan_options = options
        self._scan_id = self._generate_scan_id()
        self._scan_start_time = datetime.now()
        self.scan_started.emit(f"Scan started for {url}")
        try:
            await self._perform_scan()
        except Exception as e:
            self.error_occurred.emit(f"Error during scan: {str(e)}")
        finally:
            self._scan_in_progress = False
            self._scan_end_time = datetime.now()
            self.scan_finished.emit(f"Scan finished for {url}")

    async def _perform_scan(self) -> None:
        # Проверка на валидность URL
        if not db.is_valid_url(self._current_url):
            raise ValueError("Invalid URL")

        # Основные проверки на уязвимости
        await self._check_sql_injections()
        await self._check_xss_reflected()
        await self._check_csrf_vulnerabilities()

    async def _check_sql_injections(self) -> None:
        # Проверка на SQL инъекции
        for payload in SAFE_SQL_PAYLOADS:
            await self._test_payload(payload, "SQL Injection")

    async def _check_xss_reflected(self) -> None:
        # Проверка на отраженный XSS
        for payload in SAFE_XSS_PAYLOADS:
            await self._test_payload(payload, "Reflected XSS")

    async def _check_csrf_vulnerabilities(self) -> None:
        # Проверка на CSRF уязвимости
        # Проверяем флаги перед началом проверки
        if self.should_stop or self._is_paused:
            return
        await self._test_csrf_protection()

    async def _test_payload(self, payload: str, vulnerability_type: str) -> None:
        # Тестирование конкретного пэйлоада
        try:
            response = await self._send_request_with_payload(payload)
            # Ответ всегда не None, т.к. метод возвращает Union[aiohttp.ClientResponse, EmptyResponse]
            # Проверяем тип ответа перед передачей в _is_vulnerable
            if isinstance(response, aiohttp.ClientResponse):
                is_vulnerable = await self._is_vulnerable(response, payload)
            else:
                # Для EmptyResponse считаем, что уязвимостей нет
                is_vulnerable = False

                if is_vulnerable:
                    # Используем current_url вместо _current_url
                    current_url = getattr(self, 'current_url', '')
                    if current_url:
                        self.vulnerability_found.emit(current_url, payload, vulnerability_type)
                # Обновляем статистику после нахождения уязвимости
                # Метод update_stats может быть определен в дочерних классах
                try:
                    # Проверяем наличие метода через getattr для избежания предупреждений Pylance
                    update_stats_method = getattr(self, 'update_stats', None)
                    if update_stats_method and callable(update_stats_method):
                        update_stats_method()
                except Exception as e:
                    logger.debug(f"Error updating stats: {e}")
        except Exception as e:
            logger.error(f"Error testing payload {payload}: {str(e)}")

    async def _send_request_with_payload(self, payload: str) -> Union[aiohttp.ClientResponse, EmptyResponse]:
        # Отправка HTTP запроса с пэйлоадом
        # Проверяем флаги остановки и паузы перед отправкой запроса
        if self.should_stop or self._is_paused:
            # Используем глобальный класс EmptyResponse вместо None
            return EmptyResponse()

        # Используем current_url вместо _current_url
        current_url = getattr(self, 'current_url', '')
        if not current_url:
            # Используем глобальный класс EmptyResponse вместо None
            return EmptyResponse()

        async with aiohttp.ClientSession() as session:
            if '?' in current_url:
                url = f"{current_url}&payload={payload}"
            else:
                url = f"{current_url}?payload={payload}"
            async with session.get(url) as response:
                return response

    @staticmethod
    async def _is_vulnerable(response: aiohttp.ClientResponse, payload: str) -> bool:
        # Проверка ответа на наличие уязвимости
        # Проверка на None удалена, т.к. response имеет тип aiohttp.ClientResponse
        content = await response.text()
        if payload in content:
            return True
        return False

    @staticmethod
    def _generate_scan_id() -> str:
        # Генерация уникального ID сканирования
        return hashlib.sha256(str(time.time()).encode()).hexdigest()

    async def save_scan_results(self) -> None:
        # Сохранение результатов сканирования в базу данных
        try:
            db.save_scan_async(
                user_id=int(self._scan_id, 16),  # Преобразуем scan_id в целое число
                url=self._current_url,
                results=self._scan_results,
                scan_type=self._scan_options.get('type', 'general'),  # Получаем тип сканирования из опций
                scan_duration=(self._scan_end_time - self._scan_start_time).total_seconds() if self._scan_end_time and self._scan_start_time else 0.0
            )
        except Exception as e:
            logger.error(f"Error saving scan results: {str(e)}")

SAFE_XSS_PAYLOADS: List[str] = [
    # ===== ГРУППА 1: Базовые script теги =====
    "<script>alert('XSS')</script>",              # Классический XSS пэйлоад

    # ===== ГРУППА 2: Event handlers (обработчики событий) =====
    '<img src=x onerror=alert(1)>',               # onerror в img теге
    '<svg/onload=alert(1)>',                      # onload в SVG
    '<body onload=alert(1)>',                     # onload в body
    '<input onfocus=alert(1) autofocus>',         # onfocus в input
    '<details open ontoggle=alert(1)>',           # ontoggle в details

    # ===== ГРУППА 3: JavaScript протокол в атрибутах =====
    '<iframe src=javascript:alert(1)>',           # javascript: в src
    '<a href=javascript:alert(1)>Click</a>',      # javascript: в href
    '<math href="javascript:alert(1)">X</math>',  # javascript: в math

    # ===== ГРУППА 4: Встраиваемые объекты =====
    '<object data="javascript:alert(1)">',        # javascript: в object
    '<embed src="javascript:alert(1)">',          # javascript: в embed

    # ===== ГРУППА 5: Form-based XSS =====
    '<form><button formaction="javascript:alert(1)">X</button></form>',  # formaction

    # ===== ГРУППА 6: Сложные event handlers =====
    '<img src=x:confirm(1) onerror=eval(src)>',   # eval() с src
    '<svg><script>alert(1)</script>',             # script внутри SVG

    # ===== ГРУППА 7: CDATA и специальные символы =====
    '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',  # CDATA bypass

    # ===== ГРУППА 8: Кодирование и обфускация =====
    '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',  # String.fromCharCode
    '<svg><g onload=alert(1)></g></svg>',         # Вложенные SVG элементы
    '<img src=x onerror=alert(/XSS/.source)>',    # Регулярные выражения

    # ===== ГРУППА 9: Информационные XSS =====
    '<img src=x onerror=alert(document.domain)>',     # Домен страницы
    '<img src=x onerror=alert(window.location)>',     # URL страницы
    '<img src=x onerror=alert(document.cookie)>',     # Куки пользователя

    # ===== ГРУППА 10: SVG с XLink =====
    '<svg><a xlink:href="javascript:alert(1)">X</a></svg>',  # XLink в SVG

    # ===== ГРУППА 11: Устаревшие HTML теги =====
    '<marquee onstart=alert(1)>',                 # Устаревший marquee

    # ===== ГРУППА 12: CSS-based скрытие =====
    '<img src=x onerror=alert(1) style="display:none">',      # display:none
    '<img src=x onerror=alert(1) style="visibility:hidden">', # visibility:hidden
    '<img src=x onerror=alert(1) style="opacity:0">',          # opacity:0
    '<img src=x onerror=alert(1) style="position:absolute;left:-9999px">']  # Позиционирование за пределы экрана

SAFE_SQL_PAYLOADS: List[str] = [
    # ===== ГРУППА 1: Базовые кавычки для проверки синтаксиса =====
    "'",  # Одиночная кавычка - проверяет обработку незакрытых кавычек
    '"',  # Двойная кавычка - проверяет обработку двойных кавычек

    # ===== ГРУППА 2: Boolean-based инъекции (логические операции) =====
    "1' OR '1'='1 -- ",      # Классическая boolean-based инъекция с комментарием
    '1" OR "1"="1" -- ',     # Boolean-based с двойными кавычками
    "1' OR 1=1--",           # Упрощенная boolean-based инъекция
    '1" OR 1=1--',           # Boolean-based с двойными кавычками
    "1' OR 'a'='a' -- ",     # Boolean-based с строковым сравнением
    '1" OR "a"="a" -- ',     # Boolean-based с двойными кавычками

    # ===== ГРУППА 3: Парные кавычки для сложных запросов =====
    "1') OR ('1'='1' -- ",   # Для запросов с парными скобками
    '1") OR ("1"="1" -- ',   # Парные скобки с двойными кавычками

    # ===== ГРУППА 4: Аутентификация bypass пэйлоады =====
    "admin' -- ",            # Попытка обхода аутентификации
    "admin' #",              # MySQL комментарий
    "admin'/*",              # Многострочный комментарий

    # ===== ГРУППА 5: Различные типы комментариев =====
    "' OR '' = '",           # Пустое сравнение
    "' OR 1=1#",             # MySQL комментарий
    "' OR 1=1--",            # Стандартный SQL комментарий
    "' OR 1=1/*",            # Многострочный комментарий

    # ===== ГРУППА 6: Сложные boolean-based инъекции =====
    "') OR ('1'='1--",       # С парными скобками
    "') OR ('1'='1'#",       # С MySQL комментарием
    "') OR ('1'='1'/*",      # С многострочным комментарием

    # ===== ГРУППА 7: Time-based инъекции =====
    "' OR SLEEP(5)--",       # Проверка time-based уязвимостей

    # ===== ГРУППА 8: UNION-based инъекции =====
    "' OR 1=1 UNION SELECT NULL,NULL--",           # UNION инъекция с NULL
    "' UNION SELECT username, password FROM users--",  # UNION для извлечения данных

    # ===== ГРУППА 9: Error-based инъекции =====
    "' AND (SELECT COUNT(*) FROM users) > 0--",    # Проверка существования таблицы
    "' AND 1=0 UNION ALL SELECT NULL,NULL--",      # UNION ALL для ошибок

    # Time-based (MySQL, MSSQL, PostgreSQL)
    "' OR SLEEP(10)-- ",
    "' OR 1=1 WAITFOR DELAY '0:0:5'-- ",
    "' OR pg_sleep(5)-- ",

    # Stacked queries (если поддерживается)
    "'; SELECT version();-- ",
    "'; DROP TABLE users;-- ",

    # Blind
    "' AND 1=(SELECT COUNT(*) FROM tabname);-- ",

    # Hex
    "' OR 0x50=0x50-- ",

    # Out-of-band
    "' UNION SELECT load_file('/etc/passwd')-- ",

    # Error-based
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT user()), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)-- ",

    # Boolean
    "' OR TRUE-- ",
    '" OR TRUE-- ',

    # PostgreSQL
    "' OR 1=1;-- ",

    # MSSQL
    "' OR 1=1-- ",
    "' OR 1=1;-- ",

    # Oracle
    "' OR 1=1-- ",

    # SQLite
    "' OR 1=1-- ",

    # Разные типы кавычек
    "` OR 1=1-- ",

    # UNION расширенные
    "' UNION SELECT NULL,NULL,NULL-- ",
    "' UNION SELECT 1,2,3-- ",

    # Комментарии
    "'/**/OR/**/1=1-- ",

    # AND
    "' AND 1=1-- ",

    # OR
    "' OR 'a'='a'-- ",

    # Out-of-band DNS
    "' UNION SELECT 1 INTO OUTFILE '/tmp/test.txt'-- "
]

HTTP_OPTIMIZATIONS: Dict[str, Dict[str, Any]] = {
    'connector': {
        'limit': 100,  # Увеличиваем лимит соединений
        'limit_per_host': 20,  # Больше соединений на хост
        'keepalive_timeout': 30,  # Keep-alive соединения
        'enable_cleanup_closed': True,  # Автоочистка закрытых соединений
        'force_close': False,  # Не закрывать соединения принудительно
        'use_dns_cache': True,  # Кэширование DNS
        'ttl_dns_cache': 300,  # TTL для DNS кэша
    },
    'timeout': {
        'total': 30,
        'connect': 10,
        'sock_read': 30,
        'sock_connect': 10
    },
    'headers': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
}

XSS_REFLECTED_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"<script>alert\('XSS'\)</script>", re.IGNORECASE),  # Классический XSS
    re.compile(r"<svg/onload=alert\('XSS'\)>", re.IGNORECASE)       # SVG-based XSS
]

SQL_ERROR_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"sql", re.IGNORECASE),                    # Общие упоминания SQL
    re.compile(r"mysql", re.IGNORECASE),                  # Специфичные для MySQL ошибки
    re.compile(r"unclosed quotation mark", re.IGNORECASE), # Незакрытые кавычки
    re.compile(r"syntax error", re.IGNORECASE),           # Синтаксические ошибки
    re.compile(r"database error", re.IGNORECASE),         # Ошибки базы данных
    re.compile(r"invalid query", re.IGNORECASE)           # Неверные запросы
]

# =============================================================================
# CSRF (CROSS-SITE REQUEST FORGERY) PAYLOADS - Пэйлоады для CSRF атак
# =============================================================================

SAFE_CSRF_PAYLOADS: List[str] = [
    # ===== ГРУППА 1: Автоматические формы =====
    # Формы, которые автоматически отправляются без взаимодействия пользователя
    '<form action="/target" method="POST"><input type="hidden" name="amount" value="1000"></form>',
    '<form action="/target" method="POST"><input type="hidden" name="to" value="attacker"></form>',
    
    # ===== ГРУППА 2: Скрытые запросы через изображения =====
    # GET-запросы через img src (автоматически загружаются браузером)
    '<img src="http://target.site/transfer?amount=1000&to=attacker">',
    
    # ===== ГРУППА 3: JavaScript fetch запросы =====
    # Современный способ выполнения CSRF через JavaScript
    '<script>fetch("/target",{method:"POST",body:"amount=1000"})</script>',
    
    # ===== ГРУППА 4: iframe-based атаки =====
    # Скрытые iframe для выполнения запросов
    '<iframe src="http://target.site/transfer?amount=1000&to=attacker"></iframe>',
    
    # ===== ГРУППА 5: CSS-based атаки =====
    # Запросы через CSS @import или link
    '<link rel="stylesheet" href="http://target.site/transfer?amount=1000&to=attacker">',
    
    # ===== ГРУППА 6: Автоматическая отправка форм =====
    # Формы с автоматической отправкой через onload
    '<body onload="document.forms[0].submit()">',
    
    # ===== ГРУППА 7: Пустые CSRF токены =====
    # Попытки обойти CSRF защиту с пустыми токенами
    '<form action="/target" method="POST"><input type="hidden" name="csrf_token" value=""></form>',
    '<form action="/target" method="POST"><input type="hidden" name="token" value=""></form>',
    '<form action="/target" method="POST"><input type="hidden" name="authenticity_token" value=""></form>',
    '<form action="/target" method="POST"><input type="hidden" name="_csrf" value=""></form>',
    '<form action="/target" method="POST"><input type="hidden" name="_token" value=""></form>',
    '<form action="/target" method="POST"><input type="hidden" name="csrfmiddlewaretoken" value=""></form>',
    '<form action="/target" method="POST"><input type="hidden" name="__RequestVerificationToken" value=""></form>',
]

# Константы для сканирования
FORM_INPUT_TYPES: Set[str] = {'text', 'textarea', 'password', 'email', 'search', 'url', 'tel', 'number'}
EXCLUDED_EXTENSIONS: Set[str] = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.gz', '.rar', '.xml', '.rss'}
MAX_PAYLOADS_PER_URL: int = 40

SKIP_EXTENSIONS: Set[str] = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv',
    '.exe', '.dll', '.bin', '.iso'
}

def is_file_url(url: str) -> bool:
    path = urlparse(url).path
    _, ext = os.path.splitext(path)
    return ext.lower() in SKIP_EXTENSIONS

class ScanWorkerSignals(QObject):
    result: pyqtSignal = pyqtSignal(dict) # Сигнал для отправки результатов сканирования
    progress: pyqtSignal = pyqtSignal(int, str) # Сигнал для обновления прогресса сканирования
    progress_updated: pyqtSignal = pyqtSignal(int) # Сигнал для обновления прогресса сканирования
    vulnerability_found: pyqtSignal = pyqtSignal(str, str, str, str) # Сигнал для отправки найденных уязвимостей
    log_event: pyqtSignal = pyqtSignal(str) # Сигнал для логирования событий
    stats_updated: pyqtSignal = pyqtSignal(str, int)  # Сигнал для обновления статистики (ключ, значение)

# --- LRU-кэш для парсинга HTML (100 последних страниц) ---
@lru_cache(maxsize=100)
def cached_parse_html(html: str, parser: str = 'html.parser') -> BeautifulSoup:
    return BeautifulSoup(html, parser)

class ScanWorker:
    """
    Асинхронный воркер для сканирования веб-сайтов на уязвимости.
    Поддерживает параллельное сканирование, паузу, остановку и возобновление.
    """
    
    def __init__(self, url: str, scan_types: List[str], user_id: int, username: Optional[str] = None,
                 max_depth: int = 3, max_concurrent: int = 10, timeout: int = 10):
        """
        Инициализирует ScanWorker.
        
        :param url: URL для сканирования
        :param scan_types: Список типов уязвимостей для проверки
        :param user_id: ID пользователя
        :param username: Имя пользователя
        :param max_depth: Максимальная глубина обхода
        :param max_concurrent: Максимальное количество параллельных запросов
        :param timeout: Таймаут для запросов
        """
        self.base_url = url
        self.current_url = ""
        self.scan_types = scan_types
        self.user_id = user_id
        self.username = username
        self.max_depth = max_depth
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        
        # Сигналы для обновления UI
        self.signals = ScanWorkerSignals()
        
        # Состояние сканирования
        self.should_stop = False
        self._is_paused = False
        
        # Счетчики и метрики
        self.start_time = 0
        self.total_links_count = 0
        self.total_forms_count = 0
        self.scanned_forms_count = 0
        self.total_scanned_count = 0
        self.max_depth_reached = 0
        self.current_depth = 0  # Текущая глубина сканирования
        self.memory_check_interval = 100
        self.operation_count = 0
        
        # Структуры данных для отслеживания
        self.visited_urls: Set[str] = set()
        self.scanned_urls: Set[str] = set()
        self.all_scanned_urls: Set[str] = set()
        self.all_found_forms: List[Dict[str, Any]] = []
        self.scanned_form_hashes: Set[str] = set()
        
        # Результаты уязвимостей
        self.vulnerabilities: Dict[str, List[Dict[str, Any]]] = {'sql': [], 'xss': [], 'csrf': []}
        
        # Очередь для URL
        self.to_visit: Optional[asyncio.Queue[Tuple[str, int]]] = None  # Будет инициализирована в методе scan()
        
        # Метрики завершения сканирования
        self.scan_completion_metrics: Dict[str, Union[Optional[float], str, int]] = {
            'scan_start_time': None,
            'scan_end_time': None,
            'completion_status': 'not_started',
            'total_urls_discovered': 0,
            'total_urls_scanned': 0,
            'total_forms_discovered': 0,
            'total_forms_scanned': 0,
            'max_depth_reached': 0,
            'errors_encountered': 0
        }
        
        self.max_coverage_mode = False  # по умолчанию выключено
        self.unscanned_urls: Set[str] = set()     # для сбора непросканированных URL

        # Инициализация сессии
        self.session = None

        # Инициализация кэшей с TTL
        self.html_cache = TTLCache(maxsize=100, ttl=300)
        self.dns_cache = TTLCache(maxsize=100, ttl=300)
        self.form_cache = TTLCache(maxsize=100, ttl=300)
        self.url_cache = TTLCache(maxsize=100, ttl=300)
        
        logger.info(f"ScanWorker initialized for {url} with types: {scan_types}")

    def _cleanup_caches(self):
        self.html_cache.clear()
        self.dns_cache.clear()
        self.form_cache.clear()
        if hasattr(self, 'url_cache'):
            self.url_cache.clear()
        self.operation_count = 0
        logger.debug("Caches cleaned up")

    def update_stats(self):
        """Обновляет статистику сканирования через сигнал stats_updated"""
        try:
            # Отправляем сигналы для обновления статистики
            self.signals.stats_updated.emit('urls_found', len(self.visited_urls))
            self.signals.stats_updated.emit('urls_scanned', len(self.all_scanned_urls))
            self.signals.stats_updated.emit('forms_found', self.total_forms_count)
            self.signals.stats_updated.emit('forms_scanned', self.scanned_forms_count)
            self.signals.stats_updated.emit('vulnerabilities', len(self.vulnerabilities.get('sql', [])) + 
                                                              len(self.vulnerabilities.get('xss', [])) + 
                                                              len(self.vulnerabilities.get('csrf', [])))
            self.signals.stats_updated.emit('requests_sent', self.total_scanned_count)
            self.signals.stats_updated.emit('errors', self.scan_completion_metrics.get('errors_encountered', 0))

            # Обновляем время сканирования
            if self.start_time > 0:
                elapsed = int(time.time() - self.start_time)
                hours = elapsed // 3600
                minutes = (elapsed % 3600) // 60
                seconds = elapsed % 60
                time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                self.signals.stats_updated.emit('scan_time', time_str)
        except Exception as e:
            logger.error(f"Error updating stats: {e}")

    def _manage_memory_usage(self):
        """Управляет использованием памяти через контроль кэшей"""

        import psutil
        memory_percent = psutil.virtual_memory().percent
        if memory_percent > 80:  # Если использование памяти > 80%
            # Уменьшаем размер кэшей
            if hasattr(self, 'html_cache'):
                self.html_cache.maxsize = max(100, self.html_cache.maxsize // 2)

            self.dns_cache.maxsize = max(500, self.dns_cache.maxsize // 2)
            self.form_cache.maxsize = max(250, self.form_cache.maxsize // 2)
            self.url_cache.maxsize = max(500, self.url_cache.maxsize // 2)
            
            # Очищаем часть кэша
            self.html_cache.clear()
            self.dns_cache.clear()
            self.form_cache.clear()
            self.url_cache.clear()
            
            logger.warning(f"Memory usage {memory_percent}% > 80%. Cache sizes reduced and cleared.")


    def _check_memory_periodically(self):
        """Периодически проверяет использование памяти"""
        self.operation_count += 1
        if hasattr(self, 'operation_count') and self.operation_count >= self.memory_check_interval:
            self._manage_memory_usage()
            self.operation_count = 0
    
    async def scan_url(self, url: str) -> Optional[str]:
        # Проверяем использование памяти периодически
        self._check_memory_periodically()

        # Проверка кэша перед обработкой URL
        cache_key = f"scan_url{url}"
        cached_result: Optional[str] = cast(Optional[str], URL_PROCESSING_CACHE.get(cache_key))
        if cached_result is not None:
            logger.debug(f"Cache hit for {url}")
            return cached_result

        # Обработка URL
        result = await self._process_url(url)

        # Сохранение в кэш
        self.html_cache.set(url, result)

        # Обновляем статистику после обработки URL
        self.update_stats()

        return result

    async def _process_url(self, url: str) -> Optional[str]:
        """Обрабатывает URL и возвращает результат"""
        try:
            # Проверяем флаги остановки и паузы перед обработкой URL
            if self.should_stop or self._is_paused:
                return None

            if self.session is None:
                logger.warning(f"Session is None for URL {url}")
                return None
            async with self.session.get(url) as response:
                return await response.text()
        except Exception as e:
            logger.error(f"Error processing URL {url}: {e}")
            return None
        

    def stop(self):
        """
        Останавливает сканирование.
        """
        self.should_stop = True
        logger.info(f"Stop signal sent for scan of {self.base_url}")

    def pause(self):
        """
        Приостанавливает сканирование.
        """
        self._is_paused = True
        logger.info(f"Pause signal sent for scan of {self.base_url}")

    def resume(self):
        """
        Возобновляет сканирование.
        """
        self._is_paused = False
        logger.info(f"Resume signal sent for scan of {self.base_url}")

    def is_paused(self):
        """
        Проверяет, находится ли сканирование на паузе.
        """
        return self._is_paused

    def calculate_progress(self, queue_size: int = 0) -> int:
        processed = self.total_scanned_count
        total = processed + queue_size
        if total == 0:
            total = 1
        progress = int((processed / total) * 100)
        return min(progress, 100)

    def update_progress(self, current_url: str = "", current_depth: Optional[int] = None, queue_size: Optional[int] = None):
        # Если queue_size не передан, пытаемся получить из очереди
        if queue_size is None:
            if self.to_visit is not None and hasattr(self.to_visit, 'qsize'):
                try:
                    queue_size = self.to_visit.qsize()
                except (AttributeError, RuntimeError) as e:
                    logger.warning(f"Error getting queue size for {self.base_url}: {e} ")
                    queue_size = 0
            else:
                queue_size = 0
        
        # Убедимся, что queue_size является целым числом
        actual_queue_size = int(queue_size)

        progress = self.calculate_progress(actual_queue_size)

        # Обновляем максимальную достигнутую глубину
        if current_depth is not None and current_depth > self.max_depth_reached:
            self.max_depth_reached = current_depth
            logger.info(f"PROGRESS: New max depth reached: {self.max_depth_reached} at URL: {current_url}")

        depth_info = f"{current_depth if current_depth is not None else self.current_depth}/{self.max_depth}"
        url_info = f"{len(self.all_scanned_urls)}/{self.total_links_count}"
        
        # Убеждаемся, что scanned_forms_count не превышает total_forms_count
        if self.scanned_forms_count > self.total_forms_count:
            self.scanned_forms_count = self.total_forms_count
        
        form_info = f"{self.scanned_forms_count}/{self.total_forms_count}"
        
        # Добавляем отладочную информацию
        if self.total_forms_count > 0 or self.scanned_forms_count > 0:
            logger.debug(f"Form counters: scanned={self.scanned_forms_count}, total={self.total_forms_count}")
            logger.info(f"Forms progress: {self.scanned_forms_count}/{self.total_forms_count} ({len(self.scanned_form_hashes)} unique forms scanned)")
        
        progress_info = (
            f"Progress: {progress}% | "
            f"Depth: {depth_info} | "
            f"URL: {url_info} | "
            f"Forms: {form_info}"
        )
        if current_url:
            progress_info += f" | Processed URL: {current_url}"
        
        # Отправляем информацию в лог
        self.signals.log_event.emit(progress_info)

        # Дополнительное логирование для отладки
        logger.info(f"DEBUG: Progress update - current_depth: {current_depth}, max_depth_reached: {self.max_depth_reached}, queue_size: {actual_queue_size}")
        
        # Отправляем прогресс в UI (обновляем каждые 5% или при каждом URL)
        if progress % 5 == 0 or current_url:
            self.signals.progress.emit(progress, current_url or self.base_url)
        
        # Принудительно обновляем прогресс каждые 10 обработанных URL
        if len(self.all_scanned_urls) % 10 == 0 and len(self.all_scanned_urls) > 0:
            self.signals.progress.emit(progress, current_url or self.base_url)

    async def crawl(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> None:
        """
        ЭТАП 1: Краулинг — обход сайта, сбор всех ссылок и форм.
        Обновляет внутренние структуры self.visited_urls, self.all_found_forms и т.д.
        """
        try:
            logger.info(f"Starting crawl for URL: {self.base_url}")
            self.signals.log_event.emit(f"🔍 Начинаем обход сайта: {self.base_url}")

            # Очистка кэшей и инициализация очереди
            self.visited_urls.clear()
            self.scanned_urls.clear()
            self.all_scanned_urls.clear()
            self.all_found_forms.clear()
            self.scanned_form_hashes.clear()
            self.to_visit = asyncio.Queue()
            await self.to_visit.put((self.base_url, 0))
            self.total_links_count = 1

            # Инициализируем results_by_type перед использованием
            results_by_type: Dict[str, List[str]] = {'sql': [], 'xss': [], 'csrf': []}

            # Запуск обхода с параллелизмом
            await self.crawl_and_scan_parallel(session, semaphore, self.base_url,
                                            results_by_type=results_by_type,
                                            visited_urls=self.visited_urls,
                                            scanned_urls=self.scanned_urls)
            logger.info(f"Crawling completed. Total URLs found: {len(self.visited_urls)}")
            self.signals.log_event.emit(f"✅ Обход завершён. Найдено URL: {len(self.visited_urls)}")

        except Exception as e:
            log_and_notify('error', f"Error in crawl: {e}")
            self.signals.log_event.emit(f"❌ Ошибка обхода: {str(e)}")
            raise

    async def crawl_and_scan_parallel(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                                      start_url: str, results_by_type: Dict[str, List[str]], visited_urls: Set[str], scanned_urls: Set[str]):
        """
        Параллельное сканирование с обходом ссылок.
        """
        try:
            logger.info(f"Starting crawl_and_scan_parallel for {start_url}")

            # Проверяем, что очередь создана
            if self.to_visit is None:
                log_and_notify('error', "Queue to_visit is None! Cannot proceed with scanning.")
                return

            logger.info(f"Queue size at start: {self.to_visit.qsize()}")
            # Проверяем, что очередь не пуста
            if self.to_visit.qsize() == 0:
                logger.warning("Queue is empty at start of crawl_and_scan_parallel!")
            processed_count = 0

            # Обрабатываем URL из очереди
            logger.info(f"Starting to process URLs from queue. Queue size: {self.to_visit.qsize()}")
            while not self.to_visit.empty() and not self.should_stop:
                try:
                    # Проверяем паузу перед обработкой URL
                    if self._is_paused:
                        await asyncio.sleep(0.1)  # Чаще проверяем статус паузы
                        continue

                    url, current_depth = await self.to_visit.get()
                    processed_count += 1
                    logger.info(f"Processing URL {processed_count}: {url} at depth {current_depth} (max_depth: {self.max_depth})")
                    logger.info(f"Queue size after getting URL: {self.to_visit.qsize()}")

                    if self.should_stop:
                        logger.info("Received request to stop scanning. Finishing...")
                        break

                    if current_depth > self.max_depth:
                        logger.info(f"Reached maximum depth {self.max_depth} for {url} - SKIPPING")
                        continue

                    # Обрабатываем URL с использованием одного метода для всех глубин
                    logger.info(f"Processing URL {url} at depth {current_depth} using _process_and_scan_url")
                    await self._process_and_scan_url(session, semaphore, url, visited_urls, scanned_urls,
                                                     set(), results_by_type, self.to_visit, current_depth)

                    # Обновляем статистику после обработки каждого URL
                    self.update_stats()

                except asyncio.CancelledError:
                    logger.info("Scanning task cancelled.")
                    break
                except Exception as e:
                    log_and_notify('error', f"Error in scanning task: {e}")

            logger.info(f"Main scanning loop completed. Processed {processed_count} URLs.")
            logger.info(f"Final queue size: {self.to_visit.qsize()}")
            logger.info(f"Max depth reached: {self.max_depth_reached}")

        except Exception as e:
            log_and_notify('error', f"Error in crawl_and_scan_parallel: {e})")

    async def _process_and_scan_url(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        url: str,
        visited_urls: Set[str],
        scanned_urls: Set[str],
        seen_urls: Set[str],
        results_by_type: Dict[str, List[str]],
        to_visit: asyncio.Queue[Tuple[str, int]],
        current_depth: int
    ) -> Tuple[Set[str], List[Tag]]:
        """
        Обрабатывает и сканирует один URL.
        """
        links: Set[str] = set()
        forms: List[Tag] = []

        if url in visited_urls or url in seen_urls:
            return set(), []

        if self._is_paused or self.should_stop:
            return set(), []

        # Добавляем URL только в seen_urls на начальном этапе
        seen_urls.add(url)
        logger.info(f"Scanning URL: {url} at depth {current_depth}")

        try:
            links, forms = await self._extract_links_from_url(
                session, semaphore, url,
                urlparse(self.base_url).netloc,
                visited_urls,
                only_forms=False
            )

            # Добавляем новые формы в общий список
            new_forms_count = 0
            for form in forms:
                form_hash = self.get_form_hash(form)
                if form_hash not in [f.get('hash') for f in self.all_found_forms]:
                    self.all_found_forms.append({
                        'form': form,
                        'url': url,
                        'hash': form_hash
                    })
                    new_forms_count += 1

            self.total_forms_count = len(self.all_found_forms)
            logger.info(f"Added {new_forms_count} new unique forms. Total forms: {self.total_forms_count}")

            # Добавляем новые ссылки в очередь
            logger.info(f"Found {len(links)} links on {url} at current depth {current_depth}")
            new_links_added = 0
            skipped_visited = 0
            skipped_file = 0

            # Выводим первые 5 найденных ссылок для отладки
            for i, link in enumerate(list(links)[:5]):
                logger.info(f"DEBUG_LINK_{i}: {link}")

            for link in links:
                if link in visited_urls:
                    skipped_visited += 1
                    continue
                if link in seen_urls:
                    skipped_visited += 1
                    continue
                if is_file_url(link):
                    logger.info(f"SKIP_FILE: {link}")
                    skipped_file += 1
                    continue
                new_depth = current_depth + 1
                await to_visit.put((link, new_depth))
                self.total_links_count += 1
                new_links_added += 1
                logger.info(f"ADD_LINK: {link} with depth {new_depth} (total_links_count={self.total_links_count})")
                # Не добавляем ссылку в visited_urls здесь, только в seen_urls
                seen_urls.add(link)

            logger.info(f"Link processing summary: total={len(links)}, added={new_links_added}, skipped_visited={skipped_visited}, skipped_file={skipped_file}")
            logger.info(f"Added {new_links_added} new links to queue. Queue size after adding links: {to_visit.qsize()}")

            # Сканируем текущий URL
            unique_forms = [f['form'] for f in self.all_found_forms if f['url'] == url]
            logger.info(f"Found {len(unique_forms)} unique forms on {url}. Starting scan...")

            # Обновляем прогресс после обработки URL
            self.update_progress(
                url,
                current_depth,
                to_visit.qsize()
            )

            # Обновляем максимальную достигнутую глубину
            if current_depth > self.max_depth_reached:
                self.max_depth_reached = current_depth
                logger.info(f"NEW MAX DEPTH REACHED: {self.max_depth_reached} at URL: {url}")

            logger.info(f"About to scan_single_url for {url} at depth {current_depth}")
            await self.scan_single_url(
                session, semaphore, url,
                visited_urls, scanned_urls,
                results_by_type, to_visit,
                current_depth, unique_forms
            )

        except aiohttp.ClientError as e:
                log_and_notify('error', f"Client error accessing {url}: {e}")
                self.unscanned_urls.add(url)
        except asyncio.TimeoutError:
                logger.warning(f"Timeout accessing {url}")
                self.unscanned_urls.add(url)
        except (ValueError, TypeError, AttributeError) as e:
                log_and_notify('error', f"Data processing error for {url}: {e}")
                self.unscanned_urls.add(url)
        except Exception as e:
                log_and_notify('error', f"Unexpected error processing {url}: {e}")
                self.unscanned_urls.add(url)

        return links, forms

    async def scan_single_url(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                              url: str, visited_urls: set[str], scanned_urls: set[str],
                              results_by_type: Dict[str, List[str]], to_visit: asyncio.Queue[Tuple[str, int]], current_depth: int, forms_to_scan: Optional[List[Tag]] = None):
        if forms_to_scan is None:
            forms_to_scan = []
        if url in scanned_urls:
            logger.info(f"URL {url} already in scanned_urls, skipping")
            return
        if self._is_paused:
            logger.info(f"Scan is paused, skipping URL {url}")
            return
        logger.info(f"Starting to scan URL: {url} at depth {current_depth}")

        # Используем семафор для ограничения параллелизма
        async with semaphore:
            # Проверяем флаги снова перед началом обработки
            if self.should_stop or self._is_paused:
                return

            scanned_urls.add(url)
            visited_urls.add(url)
            self.all_scanned_urls.add(url)
            self.total_scanned_count += 1

            # Обновляем статистику после добавления URL в сканированные
            self.update_stats()

            # Если не достигли максимальной глубины, извлекаем ссылки с текущей страницы
            if current_depth < self.max_depth:
                logger.info(f"Extracting links from {url} at depth {current_depth} (max_depth: {self.max_depth})")
                try:
                    links, forms = await self._extract_links_from_url(
                        session, semaphore, url,
                        urlparse(self.base_url).netloc,
                        visited_urls,
                        only_forms=False
                    )

                    # Добавляем новые формы в общий список
                    new_forms_count = 0
                    for form in forms:
                        form_hash = self.get_form_hash(form)
                        if form_hash not in [f.get('hash') for f in self.all_found_forms]:
                            self.all_found_forms.append({
                                'form': form,
                                'url': url,
                                'hash': form_hash
                            })
                            new_forms_count += 1

                    self.total_forms_count = len(self.all_found_forms)
                    logger.info(f"Added {new_forms_count} new unique forms. Total forms: {self.total_forms_count}")

                    # Добавляем новые ссылки в очередь
                    logger.info(f"Found {len(links)} links on {url} at current depth {current_depth}")
                    new_links_added = 0
                    for link in links:
                        if link not in visited_urls:
                            if is_file_url(link):
                                logger.info(f"SKIP_FILE: {link}")
                                continue
                            new_depth = current_depth + 1
                            await to_visit.put((link, new_depth))
                            self.total_links_count += 1
                            new_links_added += 1
                            logger.info(f"ADD_LINK: {link} with depth {new_depth} (total_links_count={self.total_links_count})")
                            # Не добавляем ссылку в visited_urls здесь, это будет сделано при фактическом посещении
                    logger.info(f"Added {new_links_added} new links to queue. Queue size after adding links: {to_visit.qsize()}")

                    # Обновляем формы для сканирования уязвимостей
                    forms_to_scan = [f['form'] for f in self.all_found_forms if f['url'] == url]
                    logger.info(f"Found {len(forms_to_scan)} unique forms on {url}. Starting scan...")

                except Exception as e:
                    log_and_notify('error', f"Error extracting links from {url}: {e}")
            else:
                logger.info(f"Reached max depth {current_depth} for URL {url}, not extracting links")
        try:
            if forms_to_scan:
                new_forms_count = 0
                for form in forms_to_scan:
                    form_hash = self.get_form_hash(form)
                    if form_hash not in self.scanned_form_hashes:
                        self.scanned_form_hashes.add(form_hash)
                        new_forms_count += 1
                if new_forms_count > 0:
                    self.scanned_forms_count += new_forms_count
                # --- Ограничиваем количество одновременных задач (batch gather) ---
                batch_size = min(5, self.max_concurrent)  # не более 5 задач одновременно
                tasks: List[asyncio.Task[Optional[str]]] = []
                for scan_type in self.scan_types:
                    if self.should_stop:
                        return
                    if scan_type == 'sql':
                        tasks.append(asyncio.create_task(self.check_sql_injection(session, url, forms_to_scan)))
                    elif scan_type == 'xss':
                        tasks.append(asyncio.create_task(self.check_xss(session, url, forms_to_scan)))
                    elif scan_type == 'csrf':
                        tasks.append(asyncio.create_task(ScanWorker.check_csrf(url, forms_to_scan)))
                # --- Batch gather ---
                for i in range(0, len(tasks), batch_size):
                    batch = tasks[i:i+batch_size]
                    results = await asyncio.gather(*batch, return_exceptions=True)
                    for j, result in enumerate(results):
                        if isinstance(result, Exception):
                            log_and_notify('error', f"Failed to scan URL {url}: {result}")
                        elif result:
                            scan_type = self.scan_types[i+j] if (i+j) < len(self.scan_types) else 'unknown'
                            self._process_scan_results(url, [result], [scan_type], results_by_type)
            self.update_progress(url, current_depth, to_visit.qsize())
            logger.info(f"Successfully scanned URL: {url} at depth {current_depth}")
        except Exception as e:
            log_and_notify('error', f"Failed to scan URL {url}: {e}")

    def _process_scan_results(self, url: str, results: List[Any], scan_types_used: List[str], results_by_type: Dict[str, List[Any]]):
        """
        Обрабатывает результаты сканирования.
        """
        try:
            if results:
                for scan_type in scan_types_used:
                    if scan_type in results_by_type:
                        results_by_type[scan_type].append({
                            'url': url,
                            'details': str(results),
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Также сохраняем в self.vulnerabilities для корректного подсчета
                        if scan_type not in self.vulnerabilities:
                            self.vulnerabilities[scan_type] = []
                        
                        self.vulnerabilities[scan_type].append({
                            'url': url,
                            'details': str(results),
                            'timestamp': datetime.now().isoformat()
                        })
                        
        except Exception as e:
            log_and_notify('error', f"Error processing scan results: {e}")

    async def _extract_links_from_url(self, 
                                      session: aiohttp.ClientSession, 
                                      semaphore: asyncio.Semaphore,
                                      url: str, 
                                      base_domain: str, 
                                      visited_urls: Optional[set[str]] = None, 
                                      only_forms: bool = False) -> Tuple[Set[str], List[Tag]]:
        if visited_urls is None:
            visited_urls = set()
        found_links: Set[str] = set()
        found_forms: List[Tag] = []
        try:
            if self.should_stop or self._is_paused:
                return found_links, found_forms
            if not url:
                return found_links, found_forms
            async with semaphore:
                result = await self.smart_request(
                    session=session, 
                    method='GET', 
                    url=url, 
                    retries=2
                )

                # Проверяем, что результат не None
                if result is None:
                    return found_links, found_forms
                
                # Получаем только html_content из результата
                html_content = result[1]

                if not html_content:
                    return found_links, found_forms
                
                # --- Используем LRU-кэш для парсинга HTML ---
                # Получаем значение парсера из словаря, гарантируя, что это строка
                parser_value = BS4_OPTIMIZATIONS.get('parser', 'html.parser')
                if isinstance(parser_value, list):
                    parser_value = parser_value[0] if parser_value else 'html.parser'

                # Используем гарантированно строковое значение
                soup = cached_parse_html(html_content, parser_value)

                # Если only_forms=False, ищем ссылки
                if not only_forms:
                    for link in soup.find_all('a', href=True):
                        if isinstance(link, Tag):
                            href = str(link.get('href', ''))
                            absolute_url = urljoin(url, href)
                            if self.is_same_domain(absolute_url, base_domain):
                                # Проверяем, не посещали ли мы этот URL ранее
                                if absolute_url not in visited_urls:
                                    # Не добавляем в visited_urls здесь, только в found_links
                                    found_links.add(absolute_url)

                # Ищем формы
                for form in soup.find_all('form'):
                    # Явно приводим тип к Tag
                    found_forms.append(cast(Tag, form))

        except Exception as e:
            log_and_notify('error', f"Error extracting links from {url}: {e}")
        return found_links, found_forms

    @staticmethod
    def get_form_hash(form_tag: Tag) -> str:
        """
        Создает уникальный хэш для тега формы с улучшенной обработкой ошибок.
        """
        try:
            if not form_tag:
                logger.warning("Invalid or empty form tag passed for hashing")
                return hashlib.sha256(b"invalid_form", usedforsecurity=False).hexdigest()

            action = str(form_tag.get('action', '')) if form_tag else ''
            action = action.strip()
            method = str(form_tag.get('method', 'get')).lower() if form_tag else 'get'
            method = method.lower().strip()

            inputs: List[str] = []
            try:
                if form_tag:  # Добавляем проверку перед поиском полей
                    for inp in form_tag.find_all(['input', 'textarea', 'select', 'button']):
                        if isinstance(inp, Tag):
                            inp_name = inp.get('name', '')
                            inp_type = inp.get('type', 'text')  # default type
                            if inp_name and isinstance(inp_name, str):
                                inputs.append(f"{inp.name}-{inp_type}-{inp_name}")
            except Exception as e:
                logger.warning(f"Error finding form fields: {e}")

            inputs.sort()
            form_representation = f"action:{action}|method:{method}|inputs:{','.join(inputs)}"
            return hashlib.sha256(form_representation.encode('utf-8', errors='replace'), usedforsecurity=False).hexdigest()

        except Exception as e:
            log_and_notify('error', f"Critical error creating form hash: {e}")
            return hashlib.sha256(str(time.time()).encode(), usedforsecurity=False).hexdigest()


    @staticmethod
    def is_same_domain(url: str, base_domain: str) -> bool:
        """
        Проверяет, принадлежит ли URL данному домену или его поддоменам с улучшенной валидацией.
        """
        try:
            # Валидация входных данных
            if not url:
                logger.warning(f"Invalid URL for domain check: {url}")
                return False
            
            if not base_domain:
                logger.warning(f"Invalid base domain: {base_domain}")
                return False
            
            # Парсим URL
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower()
            base_domain = base_domain.lower()
            
            # Убираем порт из домена если есть
            url_domain = url_domain.split(':')[0]
            base_domain = base_domain.split(':')[0]
            
            # Проверяем точное совпадение
            if url_domain == base_domain:
                return True
            
            # Проверяем, является ли URL поддоменом базового домена
            if url_domain.endswith('.' + base_domain):
                return True
            
            # Проверяем специальные случаи (localhost, IP адреса)
            if base_domain in ['localhost', '127.0.0.1'] and url_domain in ['localhost', '127.0.0.1']:
                return True
            
            return False
            
        except Exception as e:
            log_and_notify('error', f"Error checking domain {url} against {base_domain}: {e}")
            return False

    async def smart_request(self, session: aiohttp.ClientSession, method: str, url: str, retries: int = 2, **kwargs: Any) -> Optional[Tuple[Optional[object], Optional[str]]]:
        """
        Умный HTTP запрос с улучшенной обработкой ошибок и валидацией.
        """
        global cache_operations
        cache_operations += 1
        
        # Проверяем флаги остановки и паузы в начале
        if self.should_stop or self._is_paused:
            logger.info("HTTP request stopped by user request or pause")
            return None
            
        # Проверяем валидность сессии
        if not session or not hasattr(session, 'request'):
            log_and_notify('error', f"Invalid session for request to {url}")
            return None
        
        # Валидация URL
        if not url:
            log_and_notify('error', f"Invalid URL: {url}")
            return None
        
        # Проверяем кэш
        cache_key = f"{method}:{url}:{hash(str(kwargs))}"
        if URL_PROCESSING_CACHE.get(cache_key) is not None:
            logger.debug(f"Cache hit for {url}")
            return URL_PROCESSING_CACHE.get(cache_key)
        
        attempt = 0
        last_exception = None
        max_attempts = 3 if getattr(self, 'max_coverage_mode', False) else retries
        
        while attempt < max_attempts:
            # Проверяем флаг остановки перед каждой попыткой
            if self.should_stop:
                logger.info("HTTP request stopped by user request")
                return None
                
            try:
                logger.info(f"Making {method} request to {url} (attempt {attempt + 1}/{max_attempts})")
                
                # Используем оптимизированные настройки
                timeout = aiohttp.ClientTimeout(**HTTP_OPTIMIZATIONS['timeout'])
                headers: Dict[str, str] = {**HTTP_OPTIMIZATIONS['headers'], **kwargs.get('headers', {})}
                
                async with session.request(method, url, timeout=timeout, headers=headers, **kwargs) as response:
                    logger.info(f"Response status: {response.status} for {url}")
                    
                    # Проверяем Content-Type ПЕРЕД чтением тела
                    content_type = response.headers.get('Content-Type', '').lower()
                    logger.debug(f"Content-Type: {content_type} for {url}")
                    
                    # Обрабатываем бинарные файлы
                    if not any(t in content_type for t in ['html', 'text', 'json', 'xml', 'javascript']):
                        logger.debug(f"Binary content detected for {url}, skipping")
                        await response.read()  # Потребляем тело для освобождения соединения
                        result = (response, "")  # Возвращаем пустой текст для бинарных файлов
                        URL_PROCESSING_CACHE.set(cache_key, result)
                        return result
                    
                    # Читаем тело ответа
                    try:
                        response_text = await response.text()
                    except UnicodeDecodeError:
                        logger.warning(f"Unicode decode error for {url}, trying with errors='replace'")
                        response_text = await response.text(errors='replace')
                    
                    result = (response, response_text)
                    URL_PROCESSING_CACHE.set(cache_key, result)
                    return result
                    
            except aiohttp.ClientError as e:
                last_exception = e
                logger.warning(f"Client error on attempt {attempt + 1} for {url}: {e}")
            except asyncio.TimeoutError as e:
                last_exception = e
                logger.warning(f"Timeout on attempt {attempt + 1} for {url}")
            except (ValueError, TypeError, AttributeError) as e:
                last_exception = e
                log_and_notify('error', f"Data error on attempt {attempt + 1} for {url}: {e}")
            except Exception as e:
                last_exception = e
                log_and_notify('error', f"Unexpected error on attempt {attempt + 1} for {url}: {e}")
            
            attempt += 1
            if attempt < max_attempts:
                await asyncio.sleep(1)  # задержка между попытками
        
        log_and_notify('error', f"All {max_attempts} attempts failed for {url}: {last_exception}")
        self.unscanned_urls.add(url)
        return None


    def save_vulnerability(self, url: str, vuln_type: str, details: str):
        """
        Сохраняет найденную уязвимость в базу данных.
        """
        try:
            # Проверяем наличие уязвимости в списке по URL и деталям
            if vuln_type in self.vulnerabilities:
                for vuln in self.vulnerabilities[vuln_type]:
                    if vuln.get('url') == url and vuln.get('details') == details:
                        logger.debug(f"Vulnerability {vuln_type} on {url} already saved")
                        return
            
            # Добавляем в локальный список
            if vuln_type not in self.vulnerabilities:
                self.vulnerabilities[vuln_type] = []
            
            self.vulnerabilities[vuln_type].append({
                'url': url,
                'details': details,
                'timestamp': datetime.now().isoformat()
            })
            
            # Сохраняем в базу данных
            try:
                # Получаем scan_id для текущего пользователя
                scan_id = None
                with db.get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT id FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1",
                        (self.user_id,)
                    )
                    result = cursor.fetchone()
                    if result:
                        scan_id = result[0]
                    else:
                        logger.warning(f"Scan ID not found for user {self.user_id}")
                        return
                
                # Сохраняем уязвимость
                with db.get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO vulnerabilities (scan_id, url, type, details) VALUES (?, ?, ?, ?)",
                        (scan_id, url, vuln_type, details)
                    )
                    conn.commit()
                
            except sqlite3.Error as e:
                log_and_notify('error', f"Database error saving vulnerability: {e}")
            except Exception as e:
                log_and_notify('error', f"Unexpected error saving vulnerability: {e}")
                
        except Exception as e:
            log_and_notify('error', f"Error in save_vulnerability: {e}")

    async def _submit_form(self, session: aiohttp.ClientSession, method: str, url: str, form_data: Dict[str, str]) -> Tuple[Optional[object], str]:
        """
        Отправляет форму и возвращает ответ.
        """
        try:
            # Проверяем валидность сессии
            if not session or not hasattr(session, 'request'):
                log_and_notify('error', f"Invalid session for form submission to {url}")
                return None, ""
            
            # Валидация URL
            if not url:
                log_and_notify('error', f"Invalid URL for form: {url}")
                return None, ""
            
            # Валидация данных формы
            if not form_data:
                logger.warning(f"Empty or invalid form data for {url}")
                return None, ""
            
            # Нормализуем метод
            method = method.upper()
            if method not in ['GET', 'POST']:
                logger.warning(f"Unsupported method {method}, using GET")
                method = 'GET'
            
            # Создаем timeout объект
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            # Отправляем запрос
            try:
                if method == 'GET':
                    async with session.get(url, params=form_data, timeout=timeout) as response:
                        return response, await response.text(errors='replace')
                else:  # POST
                    async with session.post(url, data=form_data, timeout=timeout) as response:
                        return response, await response.text(errors='replace')
                        
            except aiohttp.ClientError as e:
                logger.warning(f"Client error submitting form to {url}: {e}")
                return None, ""
            except asyncio.TimeoutError as e:
                logger.warning(f"Timeout submitting form to {url}: {e}")
                return None, ""
            except (ValueError, TypeError, AttributeError) as e:
                log_and_notify('error', f"Data error submitting form to {url}: {e}")
                return None, ""
            except Exception as e:
                log_and_notify('error', f"Unexpected error submitting form to {url}: {e}")
                return None, ""
                
        except Exception as e:
            log_and_notify('error', f"Error in _submit_form: {e}")
            return None, ""

    async def check_sql_injection(self, session: aiohttp.ClientSession, url: str, forms: Optional[List[Tag]] = None) -> Optional[str]:
        """
        Ультра-оптимизированная проверка на SQL-инъекции.
        Использует двухэтапное сканирование, параллелизацию и компактный код.
        """
        
        async def _test_target(target_url: str, test_method: str = 'GET', test_data: Optional[Dict[str, str]] = None) -> Optional[str]:
            """Тестирует один URL или форму на SQLi, возвращая первую найденную уязвимость."""

            async def _run_test(test_payload: str) -> Tuple[bool, Optional[str]]:
                """Запускает один тест с пейлоадом и возвращает (is_vulnerable, details)."""
                try:
                    req_url = target_url

                    if test_method == 'GET':
                        parsed = urlparse(target_url)
                        params = {k: test_payload for k in parse_qs(parsed.query)}
                        req_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                        result = await self.smart_request(session, test_method, req_url)
                        if result is None:
                            return False, None
                        _, text = result
                    else:
                       result = await self.smart_request(session, test_method, target_url, data=test_data if test_data else {})
                       if result is None:
                           return False, None
                       _, text = result

                    # Проверка time-based SQL injection
                    if "SLEEP" in test_payload.upper():
                        start_time = time.monotonic()
                        duration = 0
                        if test_method == 'POST':
                            result = await self.smart_request(session, test_method, target_url, data=test_data if test_data else {})
                            if result is None:
                                return False, None
                            _, text = result
                        else:
                            result = await self.smart_request(session, test_method, req_url)
                            if result is None:
                                return False, None
                            _, text = result
                            if text:
                                duration = time.monotonic() - start_time

                            if duration > 5:
                                return True, f"Time-based SQLi with payload: {test_payload}"
                    
                            # Проверяем, что text не None и является строкой
                            if text:
                                if self._detect_sql_vulnerability(text):
                                    return True, f"Error-based SQLi with payload: {test_payload}"
                    
                    return False, None
                    
                except Exception as e:
                    logger.debug(f"SQLi sub-check error on {target_url}: {e}")
                    return False, None

            # Этап 1: Быстрая параллельная разведка
            exploratory_results = await asyncio.gather(*[_run_test(p) for p in ["'", '"']])
            if not any(is_vuln for is_vuln, _ in exploratory_results):
                return None
                    
            # Этап 2: Полная проверка
            for payload in SAFE_SQL_PAYLOADS:
                if self.should_stop: 
                    return None
                is_vulnerable, details = await _run_test(payload)
                if is_vulnerable:
                    return details

            return None
                                
        # --- Основная логика ---
        tasks: List[asyncio.Task[Optional[str]]] = []
        if '?' in url:
            tasks.append(asyncio.create_task(_test_target(url, test_method='GET')))
            
        if forms is None:
            forms = []
        for form in forms:
            if form:
                action = urljoin(url, str(form.get('action', '')))
                method: str = str(form.get('method', 'get')).upper()
                
                form_data: Dict[str, str] = {}
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_elem in inputs:
                    # Явное указание типа с приведением
                    input_elem_tag: Tag = cast(Tag, input_elem)
                    name: str = str(input_elem_tag.get('name', ''))
                    if name:
                        form_data[name] = '1'

                if method == 'POST':
                    tasks.append(asyncio.create_task(_test_target(action, test_method='POST', test_data=form_data)))
                else:
                    if form_data:
                        form_target_url = f"{action}?{urlencode(form_data)}"
                        tasks.append(asyncio.create_task(_test_target(form_target_url, test_method='GET')))
        
        if not tasks:
            return None
        
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception):
                log_and_notify('error', f"SQLi check task failed: {res}")

        return next((res for res in results if isinstance(res, str)), None)



    @staticmethod
    def _detect_sql_vulnerability(response_text: str) -> bool:
        """
        Обнаруживает уязвимость к SQL-инъекции, анализируя текст ответа.
        """
        if not response_text:
            return False
        # Проверяем наличие паттернов ошибок в ответе
        return any(pattern.search(response_text) for pattern in SQL_ERROR_PATTERNS)

    async def check_xss(self, session: aiohttp.ClientSession, url: str, forms: List[Tag]) -> Optional[str]:
        """Ультра-оптимизированная проверка на XSS. Аналогична SQLi-сканеру."""

        async def _test_target(target_url: str, test_method: str = 'GET', data: Optional[Dict[str, str]] = None) -> Optional[str]:
            """Тестирует один URL или форму на XSS."""

            async def _run_test(test_payload: str) -> Tuple[bool, Optional[str]]:
                """Запускает один XSS-тест и возвращает результат."""
                req_data = {k: test_payload for k in data} if data and test_method == 'POST' else None
                if test_method == 'GET':
                    parsed = urlparse(target_url)
                    params = {k: test_payload for k in parse_qs(parsed.query)}
                    req_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                else:
                    req_url = target_url

                try:
                    result = await self.smart_request(session, test_method, req_url, data=req_data)
                    if result is None:
                        return False, None
                    _, text = result

                    if text:
                        if self._detect_xss_vulnerability(text, test_payload):
                            return True, f"Reflected XSS with payload: {test_payload[:50]}..."
                except Exception as e:
                    logger.debug(f"XSS sub-check error on {target_url}: {e}")
                return False, None

            # Этап 1: Быстрая разведка
            is_vuln, _ = await _run_test("<xss-probe-tag>")
            if not is_vuln:
                return None
                    
            # Этап 2: Полная проверка
            for test_payload in SAFE_XSS_PAYLOADS:
                if self.should_stop: return None
                is_vulnerable, details = await _run_test(test_payload)
                if is_vulnerable:
                    return details
            return None
                            
        # --- Основная логика ---
        tasks: List[asyncio.Task[Optional[str]]] = []
        if '?' in url:
            tasks.append(asyncio.create_task(_test_target(url, test_method='GET')))
            
        if forms:
            forms = []
        for form in forms:
            if form:
                action = urljoin(url, str(form.get('action', '')))
                method: str = str(form.get('method', 'get')).upper()
                form_data: Dict[str, str] = {}
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_elem in inputs:
                    # Явное указание типа с приведением
                    input_elem_tag: Tag = cast(Tag, input_elem)
                    name: str = str(input_elem_tag.get('name', ''))
                    if name:
                        form_data[name] = '1'
                
                if method == 'POST':
                    tasks.append(asyncio.create_task(_test_target(action, test_method='POST', data=form_data)))
                else:
                    if form_data:
                        form_target_url = f"{action}?{urlencode(form_data)}"
                        tasks.append(asyncio.create_task(_test_target(form_target_url, test_method='GET')))

        if not tasks: return None

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return next((res for res in results if isinstance(res, str)), None)

    @staticmethod
    def _detect_xss_vulnerability(response_text: str, payload: str) -> bool:
        """Обнаруживает XSS, проверяя, отражен ли пейлоад без экранирования."""
        if not response_text:
            return False
        return payload in response_text

    @staticmethod
    async def check_csrf(url: str, forms: List[Tag]) -> Optional[str]:
        """
        Оптимизированная проверка на CSRF. 
        Анализирует формы на отсутствие анти-CSRF токенов.
        """
        try:
            known_csrf_token_names = {
                'csrf_token', 'csrfmiddlewaretoken', 'authenticity_token',
                '_csrf', '_token', '__requestverificationtoken', 'xsrf_token'
            }

            vulnerable_form_actions: List[str] = []
            
            if forms:
                forms = []
            for form in forms:
                try:
                    # Проверяем, что это объект BeautifulSoup
                    if form:
                        action = urljoin(url, str(form.get('action', '')))
                        form_method: str = str(form.get('method', 'get')).upper()

                        # Проверяем только POST формы
                        if form_method == 'POST':
                            # Ищем скрытые поля в форме
                            hidden_fields = form.find_all('input', type='hidden')
                            form_has_csrf_token = False
                            
                            for field in hidden_fields:
                                field_tag: Tag = cast(Tag, field)
                                field_name: str = str(field_tag.get('name', '')).lower()
                                if field_name in known_csrf_token_names:
                                    form_has_csrf_token = True
                                    break

                            # Если форма не имеет CSRF токена, считаем её уязвимой
                            if not form_has_csrf_token:
                                vulnerable_form_actions.append(action)
                                
                except Exception as e:
                    logger.warning(f"Error processing form in CSRF check: {e}")
                    continue

            if vulnerable_form_actions:
                unique_actions = sorted(list(set(vulnerable_form_actions)))
                result = f"Potential CSRF in POST forms to: {', '.join(unique_actions)}"
                return result
            
            return None
            
        except Exception as e:
            log_and_notify('error', f"Error in check_csrf: {e}")
            return None

    async def scan(self) -> Dict[str, Any]:
        """
        Основной метод для запуска сканирования.
        ЭТАП 1: Краулинг (обход сайта, сбор всех ссылок и форм)
        ЭТАП 2: Сканирование уязвимостей по найденным целям
        :return: Словарь с результатами сканирования
        """
        try:
            logger.info(f"Starting scan for URL: {self.base_url} with types: {self.scan_types}")
            logger.info(f"Scan settings: max_depth={self.max_depth}, max_concurrent={self.max_concurrent}, timeout={self.timeout}")
            self.scan_completion_metrics['scan_start_time'] = datetime.now().isoformat()
            self.scan_completion_metrics['completion_status'] = 'in_progress'
            
            self.start_time = time.time()
            self.signals.log_event.emit(f"🚀 Начинаем сканирование: {self.base_url} (глубина: {self.max_depth})")
            
            # === ЭТАП 1: Краулинг (обход сайта) ===
            # Очищаем все счетчики и кэши
            self.visited_urls.clear()
            self.scanned_urls.clear()
            self.all_scanned_urls.clear()
            self.all_found_forms.clear()
            self.scanned_form_hashes.clear()
            
            # Создаем очередь для обхода
            if self.to_visit is None:
                self.to_visit = asyncio.Queue()
                logger.info("Created asyncio.Queue in scan method")
            else:
                logger.info("Using existing asyncio.Queue in scan method")
            
            # Добавляем начальный URL в очередь
            await self.to_visit.put((self.base_url, 0))
            self.total_links_count = 1
            logger.info(f"Added initial URL to queue: {self.base_url}")
            logger.info(f"Queue size after adding initial URL: {self.to_visit.qsize()}")
            
            # === ЭТАП 2: Сканирование уязвимостей ===
            # Создаем сессию и семафор с оптимизированными настройками
            timeout = aiohttp.ClientTimeout(**HTTP_OPTIMIZATIONS['timeout'])
            logger.info(f"Created optimized session with timeout settings: {HTTP_OPTIMIZATIONS['timeout']}")
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                semaphore = asyncio.Semaphore(self.max_concurrent)
                logger.info("Starting parallel crawl and scan with optimized settings")

                # Инициализируем сессию для использования в других методах
                self.session = session
                
                # Инициализируем структуры данных
                results_by_type: Dict[str, List[str]] = {'sql': [], 'xss': [], 'csrf': []}
                visited_urls: Set[str] = set()
                scanned_urls: Set[str] = set()
                
                # Преобразуем scan_types в правильный формат
                scan_types_lower: List[str] = []
                for scan_type in self.scan_types:
                    if 'sql' in scan_type.lower():
                        scan_types_lower.append('sql')
                    elif 'xss' in scan_type.lower():
                        scan_types_lower.append('xss')
                    elif 'csrf' in scan_type.lower():
                        scan_types_lower.append('csrf')
                # Если scan_types не определены, используем все типы
                if not scan_types_lower:
                    scan_types_lower = ['sql', 'xss', 'csrf']
                self.scan_types = scan_types_lower
                
                # Запускаем основной цикл: обход + сканирование
                # (Внутри crawl_and_scan_parallel реализован обход сайта и сканирование найденных целей)
                await self.crawl_and_scan_parallel(session, semaphore, self.base_url, 
                                                 results_by_type, visited_urls, scanned_urls)
            
            # === Завершение и метрики ===
            if self.should_stop:
                self.scan_completion_metrics['completion_status'] = 'stopped_by_user'
                logger.info(f"Scan stopped by user. Total URLs scanned: {self.total_scanned_count}")
                self.signals.log_event.emit(f"⏹️ Сканирование остановлено пользователем. Просканировано URL: {self.total_scanned_count}")
            else:
                self.scan_completion_metrics['scan_end_time'] = datetime.now().isoformat()
                self.scan_completion_metrics['completion_status'] = 'completed'
                logger.info(f"Scan completed. Total URLs scanned: {self.total_scanned_count}")
            cleanup_caches()
            self.scan_completion_metrics['total_urls_discovered'] = self.total_links_count
            self.scan_completion_metrics['total_urls_scanned'] = len(self.all_scanned_urls)
            self.scan_completion_metrics['total_forms_discovered'] = self.total_forms_count
            self.scan_completion_metrics['total_forms_scanned'] = self.scanned_forms_count
            self.scan_completion_metrics['max_depth_reached'] = self.max_depth_reached
            logger.info(f"METRICS: urls_discovered={self.total_links_count}, urls_scanned={len(self.all_scanned_urls)}, forms_discovered={self.total_forms_count}, forms_scanned={self.scanned_forms_count}, max_depth_reached={self.max_depth_reached}")
            scan_duration = time.time() - self.start_time
            result: Dict[str, Any] = {
                'url': self.base_url,
                'scan_types': self.scan_types,
                'duration': scan_duration,
                'total_urls_scanned': len(self.all_scanned_urls),
                'total_forms_scanned': self.scanned_forms_count,
                'vulnerabilities': self.vulnerabilities,  # Используем сохраненные уязвимости
                'timestamp': datetime.now().isoformat(),
                'total_urls_discovered': self.total_links_count,
                'unscanned_urls': list(self.unscanned_urls)
            }
            total_vulnerabilities = sum(len(vulns) for vulns in self.vulnerabilities.values())
            self.signals.log_event.emit(f"✅ Сканирование завершено за {scan_duration:.2f}с")
            self.signals.log_event.emit(f"📊 Просканировано URL: {len(self.all_scanned_urls)}, форм: {self.scanned_forms_count}, уязвимостей: {total_vulnerabilities}")

            # Финальное обновление статистики
            self.update_stats()

            return result
        except Exception as e:
            log_and_notify('error', f"Error in scan method: {e}")
            self.scan_completion_metrics['completion_status'] = 'failed'
            # Убедимся, что errors_encountered является числом перед инкрементом
            if isinstance(self.scan_completion_metrics['errors_encountered'], int):
                self.scan_completion_metrics['errors_encountered'] += 1
            else:
                self.scan_completion_metrics['errors_encountered'] = 1
            self.signals.log_event.emit(f"❌ Ошибка сканирования: {str(e)}")
            try:
                await self.save_results()
            except Exception as save_error:
                log_and_notify('error', f"Failed to save partial results: {save_error}")
            return {
                'url': self.base_url,
                'scan_types': self.scan_types,
                'duration': 0,
                'total_urls_scanned': 0,
                'total_forms_scanned': 0,
                'vulnerabilities': {'sql': [], 'xss': [], 'csrf': []},
                'timestamp': get_local_timestamp(),
                'error': str(e),
                'total_urls_discovered': 0,
                'unscanned_urls': list(self.unscanned_urls)
            }

    async def save_results(self):
        """
        Сохраняет результаты сканирования в базу данных.
        """
        try:
            logger.info("Saving scan results to database")
            scan_duration = time.time() - self.start_time if self.start_time > 0 else 0
            results: List[Dict[str, Any]] = []
            for vuln_type, vulns in self.vulnerabilities.items():
                for vuln in vulns:
                    results.append({
                        'type': vuln_type,
                        'url': vuln.get('url', self.base_url),
                        'details': vuln.get('details', ''),
                        'severity': vuln.get('severity', 'medium')
                    })
            scan_type = "comprehensive" if len(self.scan_types) > 1 else self.scan_types[0] if self.scan_types else "general"
            completion_status = getattr(self, 'scan_completion_metrics', {}).get('completion_status', 'unknown')
            if completion_status == 'stopped_by_user':
                scan_type += "_partial"
            # --- Batch insert (если поддерживается) ---
            # save_scan_async уже реализует batch insert, если results - список
            success = db.save_scan_async(
                user_id=self.user_id,
                url=self.base_url,
                results=results,
                scan_type=scan_type,
                scan_duration=scan_duration
            )
            if success:
                logger.info(f"Scan results saved successfully for user {self.user_id}")
            else:
                log_and_notify('error', "Failed to save scan results")
            # --- Очистка кэшей и сборка мусора после сохранения ---
            if hasattr(cached_parse_html, 'cache_clear'):
                cached_parse_html.cache_clear()
            cleanup_caches()
            gc.collect()
        except Exception as e:
            log_and_notify('error', f"Error saving scan results: {e}")
            self.signals.log_event.emit(f"❌ Ошибка сохранения результатов: {str(e)}")