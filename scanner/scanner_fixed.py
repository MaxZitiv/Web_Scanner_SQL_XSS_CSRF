"""
Основной модуль сканера уязвимостей.
Этот файл служит точкой входа и объединяет все компоненты системы.
"""

# Стандартные библиотеки
import gc
import re
import os
import time
import asyncio
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple, TypedDict, cast
from datetime import datetime
from functools import lru_cache
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

# Сторонние библиотеки
import aiohttp
from bs4 import BeautifulSoup
from bs4.element import Tag
from PyQt6.QtCore import pyqtSignal, QObject

# Внутренние модули
from .cache_manager import TTLCache, cache_manager
from utils.logger import logger
from utils.database import db
from utils.unified_error_handler import log_and_notify
from utils.performance import get_local_timestamp
from utils.security import is_safe_url, validate_input_length

__all__ = ['cache_manager', 'TTLCache', 'Scanner', 'ScanWorker', 'SQL_ERROR_PATTERNS', 'XSS_REFLECTED_PATTERNS', 'SAFE_SQL_PAYLOADS', 'SAFE_XSS_PAYLOADS']

# Очистка кэша при импорте модуля
cache_manager.cleanup_all()

# Глобальные кэши
HTML_CACHE = TTLCache(maxsize=1000, ttl=3600)
DNS_CACHE = TTLCache(maxsize=500, ttl=1800)
FORM_HASH_CACHE = TTLCache(maxsize=2000, ttl=7200)
URL_PROCESSING_CACHE = TTLCache(maxsize=5000, ttl=3600)

# Константы
DEFAULT_HTML_PARSER = 'html.parser'
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30
MAX_CONCURRENT_REQUESTS = 5
MAX_PAYLOADS_PER_URL = 40
MAX_DEPTH = 3

# Оптимизированные настройки HTTP
HTTP_OPTIMIZATIONS: Dict[str, Any] = {
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

# Паттерны для обнаружения уязвимостей
SQL_ERROR_PATTERNS = [
    re.compile(r"sql", re.IGNORECASE),
    re.compile(r"mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"syntax error", re.IGNORECASE),
    re.compile(r"database error", re.IGNORECASE),
    re.compile(r"invalid query", re.IGNORECASE)
]

XSS_REFLECTED_PATTERNS = [
    re.compile(r"<script>alert\('XSS'\)</script>", re.IGNORECASE),
    re.compile(r"<svg/onload=alert\('XSS'\)>", re.IGNORECASE)
]

# Пэйлоады для тестирования
SAFE_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '<img src=x onerror=alert(document.domain)>',
    '<img src=x onerror=alert(document.cookie)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<iframe src=javascript:alert(1)>',
    '<a href=javascript:alert(1)>Click</a>',
    '<form><button formaction="javascript:alert(1)">X</button></form>'
]

SAFE_SQL_PAYLOADS = [
    "'", '"', "`",
    "' OR '1'='1 -- ",
    '" OR "1"="1" -- ',
    "1' OR 1=1--",
    "1' OR 'a'='a' -- ",
    "admin' -- ",
    "' OR SLEEP(5)--",
    "' UNION SELECT NULL,NULL--",
    "' AND 1=(SELECT COUNT(*) FROM tabname);-- ",
    "' OR TRUE-- ",
    "'/**/OR/**/1=1-- ",
    "' OR 'a'='a'-- "
]

SAFE_CSRF_PAYLOADS = [
    '<form action="/target" method="POST"><input type="hidden" name="amount" value="1000"></form>',
    '<img src="http://target.site/transfer?amount=1000&to=attacker">',
    '<script>fetch("/target",{method:"POST",body:"amount=1000"})</script>',
    '<iframe src="http://target.site/transfer?amount=1000&to=attacker"></iframe>'
]

# Конфигурация сканирования
FORM_INPUT_TYPES = {'text', 'textarea', 'password', 'email', 'search', 'url', 'tel', 'number'}
EXCLUDED_EXTENSIONS = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2'}
SKIP_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv',
    '.exe', '.dll', '.bin', '.iso'
}

@lru_cache(maxsize=100)
def parse_html_cached(html: str, parser: str = DEFAULT_HTML_PARSER):
    """Кэшированный парсинг HTML."""
    return BeautifulSoup(html, parser)

def is_file_url(url: str) -> bool:
    """Проверяет, является ли URL файлом по расширению."""
    path = urlparse(url).path
    _, ext = os.path.splitext(path)
    return ext.lower() in SKIP_EXTENSIONS

class VulnerabilityResult(TypedDict, total=False):
    type: str
    url: str
    payload: str
    vulnerability_type: str
    description: str
    severity: str
    details: str
    timestamp: str

class ScanCompletionMetrics(TypedDict):
    errors_encountered: int
    urls_scanned: int
    vulnerabilities_found: int
    status: str

ScanResults = List[VulnerabilityResult]

class Scanner(QObject):
    """Основной класс сканера безопасности."""
    
    # Сигналы
    scan_started = pyqtSignal(str)
    scan_finished = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    vulnerability_found = pyqtSignal(str, str, str)

    def __init__(self) -> None:
        """Инициализация сканера."""
        super().__init__()
        self._initialize_state()
    
    def _initialize_state(self) -> None:
        """Инициализация состояния сканера."""
        self._scan_in_progress = False
        self._scan_results: ScanResults = []
        self._current_url = ""
        self._scan_id = hashlib.md5(str(time.time()).encode(), usedforsecurity=False).hexdigest()
        self._scan_options = {
            'max_depth': MAX_DEPTH,
            'timeout': REQUEST_TIMEOUT,
            'max_retries': MAX_RETRIES,
            'concurrent_requests': MAX_CONCURRENT_REQUESTS
        }
        self._scan_start_time = None
        self._scan_end_time = None
        self.should_stop = False
        self._is_paused = False

    @property
    def scan_in_progress(self) -> bool:
        return self._scan_in_progress

    @scan_in_progress.setter
    def scan_in_progress(self, value: bool) -> None:
        self._scan_in_progress = value

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

    async def _perform_scan(self) -> None:
        """Выполняет основное сканирование."""
        if not db.is_valid_url(self._current_url):
            raise ValueError("Invalid URL")

        # Основные проверки на уязвимости
        await self._check_sql_injections()
        await self._check_xss_reflected()
        await self._check_csrf_vulnerabilities()

    async def _check_sql_injections(self) -> None:
        """Проверка на SQL инъекции."""
        for payload in SAFE_SQL_PAYLOADS[:MAX_PAYLOADS_PER_URL]:
            if self.should_stop or self._is_paused:
                return
            await self._test_payload(payload, "SQL Injection")

    async def _check_xss_reflected(self) -> None:
        """Проверка на отраженный XSS."""
        for payload in SAFE_XSS_PAYLOADS[:MAX_PAYLOADS_PER_URL]:
            if self.should_stop or self._is_paused:
                return
            await self._test_payload(payload, "Reflected XSS")

    async def _check_csrf_vulnerabilities(self) -> None:
        """Проверка на CSRF уязвимости."""
        for payload in SAFE_CSRF_PAYLOADS[:MAX_PAYLOADS_PER_URL]:
            if self.should_stop or self._is_paused:
                return
            await self._test_payload(payload, "CSRF")

    async def _test_payload(self, payload: str, vulnerability_type: str) -> None:
        """Тестирование конкретного пэйлоада."""
        try:
            response = await self._send_request_with_payload(payload)
            if response and await self._is_vulnerable(response, payload, vulnerability_type):
                self.vulnerability_found.emit(self._current_url, payload, vulnerability_type)
                
        except Exception as e:
            logger.error(f"Error testing payload {payload}: {str(e)}")

    async def _send_request_with_payload(self, payload: str) -> Optional[aiohttp.ClientResponse]:
        """Отправка HTTP запроса с пэйлоадом."""
        if self.should_stop or self._is_paused or not self._current_url:
            return None

        timeout = aiohttp.ClientTimeout(total=self._scan_options['timeout'])
        
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if '?' in self._current_url:
                    url = f"{self._current_url}&payload={payload}"
                else:
                    url = f"{self._current_url}?payload={payload}"
                
                async with session.get(url) as response:
                    return response
        except Exception as e:
            logger.debug(f"Request failed for {payload}: {e}")
            return None


    @staticmethod
    async def _is_vulnerable(response: aiohttp.ClientResponse, payload: str, vulnerability_type: str) -> bool:
        """Проверяет, является ли ответ уязвимым."""
        content = await response.text()
        
        if vulnerability_type == "SQL Injection":
            return any(pattern.search(content) for pattern in SQL_ERROR_PATTERNS)
        elif vulnerability_type == "Reflected XSS":
            return payload in content
        elif vulnerability_type == "CSRF":
            return "csrf" not in content.lower()
            
        return False

    @staticmethod
    def _generate_scan_id() -> str:
        """Генерация уникального ID сканирования."""
        return hashlib.sha256(str(time.time()).encode()).hexdigest()

    async def save_scan_results(self) -> None:
        """Сохраняет результаты сканирования в базу данных."""
        try:
            duration = (self._scan_end_time - self._scan_start_time).total_seconds() if self._scan_end_time and self._scan_start_time else 0.0
            
            db_results: List[Dict[str, str]] = []
            
            # Если уязвимостей не найдено, добавляем запись об этом
            if not self._scan_results:
                db_results.append({
                    'type': 'info',
                    'url': self._current_url,
                    'details': 'Сканирование завершено. Уязвимости не найдены.',
                    'severity': 'info'
                })
            else:
                for result in self._scan_results:
                    db_results.append({
                        'type': result.get('vulnerability_type', 'unknown'),
                        'url': result.get('url', self._current_url),
                        'details': result.get('description', ''),
                        'severity': result.get('severity', 'medium')
                    })
                
            scan_type = self._scan_options.get('type', 'general')
            if not isinstance(scan_type, str):
                scan_type = str(scan_type)
            
            db.save_scan_async(
                user_id=int(self._scan_id, 16),
                url=self._current_url,
                results=db_results,
                scan_type=scan_type,
                scan_duration=duration
            )
        except Exception as e:
            logger.error(f"Error saving scan results: {str(e)}")

class ScanWorkerSignals(QObject):
    """Сигналы для воркера сканирования."""
    result = pyqtSignal(dict)
    progress = pyqtSignal(int, str)
    progress_updated = pyqtSignal(int)
    vulnerability_found = pyqtSignal(str, str, str)
    log_event = pyqtSignal(str)
    stats_updated = pyqtSignal(str, int)
    site_structure_updated = pyqtSignal(list, list)

class ScanWorker:
    """
    Асинхронный воркер для сканирования веб-сайтов на уязвимости.
    """

    def __init__(self, url: str, scan_types: List[str], user_id: int, username: Optional[str] = None,
                 max_depth: int = MAX_DEPTH, max_concurrent: int = 10, timeout: int = 10):
        """
        Инициализирует ScanWorker с указанными параметрами.
        """
        # Проверяем безопасность входных параметров
        if not is_safe_url(url):
            raise ValueError(f"Небезопасный URL: {url}")
        
        if not validate_input_length(url, 1, 2048):
            raise ValueError(f"URL имеет недопустимую длину: {len(url)}")
        
        if not scan_types:
            raise ValueError("Типы сканирования должны быть непустым списком")
        
        if user_id <= 0:
            raise ValueError("ID пользователя должен быть положительным числом")
        
        if username and not validate_input_length(username, 1, 50):
            raise ValueError("Имя пользователя имеет недопустимую длину")
        
        if max_depth < 1 or max_depth > 10:
            raise ValueError("Глубина сканирования должна быть в диапазоне от 1 до 10")
        
        if max_concurrent < 1 or max_concurrent > 20:
            raise ValueError("Количество одновременных запросов должно быть в диапазоне от 1 до 20")
        
        if timeout < 5 or timeout > 120:
            raise ValueError("Таймаут должен быть в диапазоне от 5 до 120 секунд")
        
        # Режимы и флаги сканирования
        self._max_coverage_mode = False
        self._should_stop = False
        
        # Очереди и множества для управления сканированием
        self.to_visit: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
        self.visited: Set[str] = set()
        self.in_progress: Set[str] = set()
        
        # Счетчики и статистика
        self.total_scanned_count = 0
        self.total_forms_count = 0
        self.total_vuln_count = 0
        self.scanned_forms_count = 0
        self.current_form_index = 0
        self.total_links_count = 0
        
        # Флаги состояния сканирования
        self.max_depth_reached = False
        self.scan_complete = False
        self.scan_started = False
        
        # Параметры сканирования
        self.url = url
        self.scan_types = scan_types
        self.user_id = user_id
        self.username = username
        self.max_depth = max_depth
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self._is_paused = False
        
        # Основные параметры
        self.base_url = url
        self.current_url = ""
        
        # Кэши и хранилища
        self.visited_urls: Set[str] = set()
        self.scanned_urls: Set[str] = set()
        self.unscanned_urls: Set[str] = set()
        self.all_scanned_urls: Set[str] = set()
        self.all_found_forms: List[Dict[str, Any]] = []
        self.scanned_form_hashes: Set[str] = set()
        self.html_cache: Dict[str, str] = {}
        self.dns_cache: Dict[str, str] = {}
        self.form_cache: Dict[str, Any] = {}
        self.url_cache: Set[str] = set()

        # Результаты и статистика
        self.vulnerabilities: Dict[str, List[Dict[str, Any]]] = {'sql': [], 'xss': [], 'csrf': []}
        self.scan_start_time = None
        self.scan_end_time = None
        self.current_depth = 0
        self.operation_count = 0
        self.memory_check_interval = 1000
        
        self.scan_completion_metrics: ScanCompletionMetrics = {
            'errors_encountered': 0,
            'urls_scanned': 0,
            'vulnerabilities_found': 0,
            'status': 'initialized'
        }

        # Сигналы и статус
        self.signals = ScanWorkerSignals()
        self._cancelled = False
        self.session = None
        self.start_time = 0

    @property
    def max_coverage_mode(self) -> bool:
        return self._max_coverage_mode

    @max_coverage_mode.setter
    def max_coverage_mode(self, value: bool) -> None:
        self._max_coverage_mode = value
        
    @property
    def should_stop(self) -> bool:
        return self._should_stop

    @should_stop.setter
    def should_stop(self, value: bool) -> None:
        self._should_stop = value

    async def _scan_sql_injection(self, url: str) -> None:
        """Сканирование на SQL-инъекции."""
        try:
            await asyncio.sleep(0.1)  # Имитация работы
            
            if any(keyword in url.lower() for keyword in ['login', 'search', 'id=', 'user=']):
                vulnerability = {
                    'type': 'sql',
                    'url': url,
                    'severity': 'high',
                    'description': 'Возможная SQL-инъекция в параметрах запроса'
                }
                
                self.vulnerabilities['sql'].append(vulnerability)
                self.scan_completion_metrics['vulnerabilities_found'] += 1
                self.signals.vulnerability_found.emit(url, 'sql', vulnerability['description'])
                
        except Exception as e:
            logger.error(f"Error during SQL injection scan: {e}")
            self.scan_completion_metrics['errors_encountered'] += 1

    async def _scan_xss(self, url: str) -> None:
        """Сканирование на XSS-уязвимости."""
        try:
            await asyncio.sleep(0.1)  # Имитация работы
            
            if any(keyword in url.lower() for keyword in ['comment', 'message', 'search', 'q=']):
                vulnerability = {
                    'type': 'xss',
                    'url': url,
                    'severity': 'medium',
                    'description': 'Потенциальная XSS-уязвимость в форме или параметрах'
                }
                
                self.vulnerabilities['xss'].append(vulnerability)
                self.scan_completion_metrics['vulnerabilities_found'] += 1
                self.signals.vulnerability_found.emit(url, 'xss', vulnerability['description'])
                
        except Exception as e:
            logger.error(f"Error during XSS scan: {e}")
            self.scan_completion_metrics['errors_encountered'] += 1

    async def _scan_csrf(self, url: str) -> None:
        """Сканирование на CSRF-уязвимости."""
        try:
            await asyncio.sleep(0.1)  # Имитация работы
            
            if any(keyword in url.lower() for keyword in ['form', 'submit', 'transfer', 'delete']):
                vulnerability = {
                    'type': 'csrf',
                    'url': url,
                    'severity': 'medium',
                    'description': 'Отсутствует CSRF-токен в форме'
                }
                
                self.vulnerabilities['csrf'].append(vulnerability)
                self.scan_completion_metrics['vulnerabilities_found'] += 1
                self.signals.vulnerability_found.emit(url, 'csrf', vulnerability['description'])
                
        except Exception as e:
            logger.error(f"Error during CSRF scan: {e}")
            self.scan_completion_metrics['errors_encountered'] += 1

    async def run_scan(self) -> Dict[str, Any]:
        """
        Выполнение полного сканирования и возврат результата.

        Делегирует основную работу методу ``scan()`` и приводит результат
        к формату, ожидаемому ScanController/UI.
        """
        try:
            raw_result = await self.scan()

            vulnerabilities: Dict[str, List[Dict[str, Any]]] = {
                'sql': [], 'xss': [], 'csrf': []
            }
            raw_vulnerabilities = raw_result.get('vulnerabilities')
            if isinstance(raw_vulnerabilities, dict):
                for key, value in cast(
                    Dict[str, List[Dict[str, Any]]], raw_vulnerabilities
                ).items():
                    vulnerabilities[key] = value

            total_vulnerabilities = sum(
                len(items) for items in vulnerabilities.values()
            )
            total_urls_scanned = int(
                raw_result.get('total_urls_scanned', len(self.all_scanned_urls))
            )
            total_forms_scanned = int(
                raw_result.get('total_forms_scanned', self.scanned_forms_count)
            )
            scan_duration = float(raw_result.get('duration', 0.0))
            unscanned_urls = list(raw_result.get('unscanned_urls', self.unscanned_urls))
            total_urls_discovered = int(
                raw_result.get('total_urls_discovered', self.total_links_count)
            )
            coverage_percent = 0.0
            if total_urls_discovered > 0:
                coverage_percent = round(
                    (total_urls_scanned / total_urls_discovered) * 100.0, 2
                )

            return {
                'url': raw_result.get('url', self.base_url),
                'scan_types': raw_result.get('scan_types', self.scan_types),
                'start_time': raw_result.get('timestamp', get_local_timestamp()),
                'end_time': get_local_timestamp(),
                'duration': scan_duration,
                'results': vulnerabilities,
                'vulnerabilities': vulnerabilities,
                'scan_duration': scan_duration,
                'total_vulnerabilities': total_vulnerabilities,
                'total_urls_scanned': total_urls_scanned,
                'total_forms_scanned': total_forms_scanned,
                'total_urls_discovered': total_urls_discovered,
                'coverage_percent': coverage_percent,
                'unscanned_urls': unscanned_urls,
                'status': raw_result.get('status', 'completed'),
                'error': raw_result.get('error')
            }

        except Exception as e:
            logger.error(f"Error during scan: {e}", exc_info=True)
            raise

    def _cleanup_caches(self):
        """Очистка кэшей для управления памятью."""
        self.html_cache.clear()
        self.dns_cache.clear()
        self.form_cache.clear()
        if hasattr(self, 'url_cache'):
            self.url_cache.clear()
        self.operation_count = 0
        logger.debug("Caches cleaned up")

    def update_stats(self):
        """Обновляет статистику сканирования."""
        try:
            # Получаем текущие значения
            urls_found = len(self.visited_urls)
            urls_scanned = len(self.all_scanned_urls)
            forms_found = len(self.all_found_forms)
            forms_scanned = self.scanned_forms_count
            
            # Подсчитываем уязвимости
            total_vulns = (
                len(self.vulnerabilities.get('sql', [])) + 
                len(self.vulnerabilities.get('xss', [])) + 
                len(self.vulnerabilities.get('csrf', []))
            )
            
            self.signals.stats_updated.emit('urls_found', urls_found)
            self.signals.stats_updated.emit('urls_scanned', urls_scanned)
            self.signals.stats_updated.emit('forms_found', forms_found)
            self.signals.stats_updated.emit('forms_scanned', forms_scanned)
            self.signals.stats_updated.emit('vulnerabilities', total_vulns)
            
            # Обновляем прогресс
            progress = self.calculate_progress()
            self.signals.progress_updated.emit(progress)
            
            # Подсчитываем ошибки
            errors = self.scan_completion_metrics.get('errors_encountered', 0)
            
            # Статистика для отправки
            stats_data = {
                'urls_found': urls_found,
                'urls_scanned': urls_scanned,
                'forms_found': forms_found,
                'forms_scanned': forms_scanned,
                'vulnerabilities': total_vulns,
                'requests_sent': self.total_scanned_count,
                'errors': errors
            }
            
            # Отправляем каждый счетчик
            for key, value in stats_data.items():
                try:
                    self.signals.stats_updated.emit(key, value)
                except Exception as signal_error:
                    logger.debug(f"Error emitting stat {key}: {signal_error}")

            # Время сканирования
            try:
                elapsed = 0
                current_time = time.time()
                
                if hasattr(self, 'start_time') and self.start_time:
                    elapsed = int(current_time - self.start_time)
                elif self.scan_start_time:
                    elapsed = int(current_time - self.scan_start_time.timestamp())
                
                # Форматируем время
                hours = elapsed // 3600
                minutes = (elapsed % 3600) // 60
                seconds = elapsed % 60
                time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                
                self.signals.stats_updated.emit('scan_time', time_str)
                
            except Exception as time_error:
                logger.debug(f"Error calculating scan time: {time_error}")
                self.signals.stats_updated.emit('scan_time', "00:00:00")
        
        except Exception as e:
            logger.error(f"Error in update_stats: {e}")

    def _manage_memory_usage(self):
        """Управляет использованием памяти через контроль кэшей."""
        try:
            import psutil
            memory_percent = psutil.virtual_memory().percent
            
            if memory_percent > 80:
                # Очищаем кэши
                cache_dicts: List[Dict[str, Any]] = [self.html_cache, self.dns_cache, self.form_cache]
                for cache_dict in cache_dicts:
                    cache_dict.clear()
                
                cache_sets = [self.url_cache]
                for cache_set in cache_sets:
                    cache_set.clear()
                
                logger.warning(f"Memory usage {memory_percent}% > 80%. Cache sizes reduced and cleared.")
        except ImportError:
            pass  # psutil не установлен
        except Exception as e:
            logger.debug(f"Error managing memory: {e}")

    def _check_memory_periodically(self):
        """Периодически проверяет использование памяти."""
        self.operation_count += 1
        if self.operation_count >= self.memory_check_interval:
            self._manage_memory_usage()
            self.operation_count = 0

    async def scan_url(self, url: str) -> Optional[str]:
        """Сканирует указанный URL."""
        self._check_memory_periodically()

        # Проверка кэша
        cache_key = f"scan_url{url}"
        cached_result = cache_manager.URL_PROCESSING_CACHE.get(cache_key)
        if cached_result is not None:
            logger.debug(f"Cache hit for {url}")
            return cached_result

        # Обработка URL
        result = await self._process_url(url)

        # Сохранение в кэш
        if result is not None:
            self.html_cache[url] = result

        self.update_stats()
        return result

    async def _process_url(self, url: str) -> Optional[str]:
        """Обрабатывает URL и возвращает результат."""
        if self.should_stop or self._is_paused:
            return None
            
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    return await response.text()
        except Exception as e:
            logger.error(f"Error processing URL {url}: {e}")
            return None

    def stop(self):
        """Останавливает сканирование."""
        self.should_stop = True
        logger.info(f"Stop signal sent for scan of {self.base_url}")

    def pause(self):
        """Приостанавливает сканирование."""
        self._is_paused = True
        logger.info(f"Pause signal sent for scan of {self.base_url}")

    def resume(self):
        """Возобновляет сканирование."""
        self._is_paused = False
        logger.info(f"Resume signal sent for scan of {self.base_url}")

    def is_paused(self):
        """Проверяет, находится ли сканирование на паузе."""
        return self._is_paused

    def calculate_progress(self) -> int:
        """Вычисляет прогресс сканирования."""
        try:
            total = self.total_links_count
            processed = len(self.all_scanned_urls)
            return int((processed / total) * 100) if total > 0 else 0
        except Exception as e:
            logger.error(f"Error calculating progress: {e}")
            return 0

    def update_progress(self, current_url: str = "", current_depth: Optional[int] = None, queue_size: Optional[int] = None):
        """Обновляет прогресс сканирования."""
        try:
            if queue_size is None:
                queue_size = self.to_visit.qsize() if self.to_visit else 0
            
            progress = self.calculate_progress()
            
            # Отправляем сигналы о прогрессе
            self.signals.progress.emit(progress, current_url)
            self.signals.progress_updated.emit(progress)
            
            # Проверяем максимальную глубину
            if current_depth is not None and current_depth >= self.max_depth:
                self.max_depth_reached = True
            
            # Формируем информацию о прогрессе
            depth_info = f"{current_depth if current_depth is not None else self.current_depth}/{self.max_depth}"
            url_info = f"{len(self.all_scanned_urls)}/{self.total_links_count}"
            form_info = f"{self.scanned_forms_count}/{len(self.all_found_forms)}"
            
            progress_info = (
                f"Progress: {progress}% | "
                f"Depth: {depth_info} | "
                f"URL: {url_info} | "
                f"Forms: {form_info}"
            )
            
            if current_url:
                progress_info += f" | Processed URL: {current_url}"
            
            self.signals.log_event.emit(progress_info)
            self.update_stats()
            
        except Exception as e:
            logger.error(f"Error in update_progress: {e}")

    @staticmethod
    def get_form_hash(form_tag: Tag) -> str:
        """Создает уникальный хэш для тега формы."""
        try:
            action = str(form_tag.get('action', '')).strip()
            method = str(form_tag.get('method', 'get')).lower().strip()

            inputs: List[str] = []
            for element in form_tag.find_all(['input', 'textarea', 'select', 'button']):
                inp_name = str(element.get('name', ''))
                inp_type = str(element.get('type', 'text'))
                if inp_name:
                    inputs.append(f"{element.name}-{inp_type}-{inp_name}")

            inputs.sort()
            form_representation = f"action:{action}|method:{method}|inputs:{','.join(inputs)}"
            return hashlib.sha256(form_representation.encode('utf-8')).hexdigest()

        except Exception as e:
            logger.error(f"Error creating form hash: {e}")
            return hashlib.sha256(str(time.time()).encode()).hexdigest()

    @staticmethod
    def is_same_domain(url: str, base_domain: str) -> bool:
        """Проверяет, принадлежит ли URL данному домену."""
        try:
            if not url or not base_domain:
                return False
            
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower().split(':')[0]
            base_domain = base_domain.lower().split(':')[0]
            
            return url_domain == base_domain or url_domain.endswith('.' + base_domain)
            
        except Exception as e:
            logger.error(f"Error checking domain {url} against {base_domain}: {e}")
            return False

    def _client_timeout(self) -> aiohttp.ClientTimeout:
        """Создаёт таймаут из параметра ScanWorker.timeout (мин. 5 сек)."""
        total = max(5, int(self.timeout))
        connect = max(5, min(10, total))
        return aiohttp.ClientTimeout(
            total=total,
            connect=connect,
            sock_connect=connect,
            sock_read=total
        )

    async def smart_request(self, session: aiohttp.ClientSession, method: str, url: str, 
                      retries: int = 2, **kwargs: Any) -> Optional[Tuple[aiohttp.ClientResponse, str]]:
        """Умный HTTP запрос с обработкой ошибок."""
        if self.should_stop or self._is_paused:
            return None

        if not session or not url:
            return None
        
        # Проверяем кэш
        cache_key = f"{method}:{url}:{hash(str(kwargs))}"
        cached_result = cache_manager.URL_PROCESSING_CACHE.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        max_attempts = 3 if self.max_coverage_mode else retries
        
        for attempt in range(max_attempts):
            if self.should_stop:
                return None
                
            try:
                timeout = self._client_timeout()
                headers = {**HTTP_OPTIMIZATIONS['headers'], **kwargs.get('headers', {})}
                
                async with session.request(method, url, timeout=timeout, headers=headers, **kwargs) as response:
                    # Проверяем Content-Type
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    if not any(t in content_type for t in ['html', 'text', 'json', 'xml', 'javascript']):
                        await response.read()
                        result = (response, "")
                    else:
                        try:
                            response_text = await response.text()
                        except UnicodeDecodeError:
                            response_text = await response.text(errors='replace')
                        
                        result = (response, response_text)
                    
                    cache_manager.URL_PROCESSING_CACHE.set(cache_key, result)
                    return result
                    
            except Exception as e:
                logger.warning(f"Request attempt {attempt + 1} failed for {url}: {e}")
                if attempt < max_attempts - 1:
                    await asyncio.sleep(1)
        
        self.unscanned_urls.add(url)
        return None

    async def crawl(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> None:
        """Краулинг — обход сайта, сбор всех ссылок и форм."""
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
            results_by_type: Dict[str, List[Dict[str, Any]]] = {'sql': [], 'xss': [], 'csrf': []}

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
                                      start_url: str, results_by_type: Dict[str, List[Dict[str, Any]]], 
                                      visited_urls: Set[str], scanned_urls: Set[str]):
        """Параллельное сканирование с обходом ссылок."""
        try:
            logger.info(f"Starting crawl_and_scan_parallel for {start_url}")
            logger.info(f"Queue size at start: {self.to_visit.qsize() if self.to_visit else 0}")
            
            processed_count = 0
            stats_update_interval = 5  # Обновляем статистику каждые 5 URL для производительности

            # Обрабатываем URL из очереди
            logger.info(f"Starting to process URLs from queue. Queue size: {self.to_visit.qsize() if self.to_visit else 0}")
            while self.to_visit and not self.to_visit.empty() and not self.should_stop:
                try:
                    # Проверяем паузу перед обработкой URL
                    if self._is_paused:
                        await asyncio.sleep(0.1)
                        continue

                    url, current_depth = await self.to_visit.get()
                    processed_count += 1
                    logger.info(f"Processing URL {processed_count}: {url} at depth {current_depth}")

                    if self.should_stop:
                        logger.info("Received request to stop scanning. Finishing...")
                        break

                    if current_depth > self.max_depth:
                        logger.info(f"Reached maximum depth {self.max_depth} for {url} - SKIPPING")
                        continue

                    # Обрабатываем URL
                    await self._process_and_scan_url(session, semaphore, url, visited_urls, scanned_urls,
                                                   set(), results_by_type, self.to_visit, current_depth)

                    # Обновляем статистику периодически для улучшения производительности
                    if processed_count % stats_update_interval == 0:
                        self.update_stats()
                        # Отправляем сигнал для обновления структуры сайта
                        self.signals.site_structure_updated.emit(list(self.all_scanned_urls), self.all_found_forms)
                        # Выполняем сборку мусора для освобождения памяти
                        gc.collect()

                except asyncio.CancelledError:
                    logger.info("Scanning task cancelled.")
                    break
                except Exception as e:
                    log_and_notify('error', f"Error in scanning task: {e}")

            logger.info(f"Main scanning loop completed. Processed {processed_count} URLs.")
            logger.info(f"Final queue size: {self.to_visit.qsize() if self.to_visit else 0}")
            logger.info(f"Max depth reached: {self.max_depth_reached}")
            
            # Финальное обновление статистики
            self.update_stats()
            self.signals.site_structure_updated.emit(list(self.all_scanned_urls), self.all_found_forms)
            # Финальная сборка мусора
            gc.collect()

        except Exception as e:
            log_and_notify('error', f"Error in crawl_and_scan_parallel: {e}")

    async def _process_and_scan_url(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                              url: str, visited_urls: Set[str], scanned_urls: Set[str],
                              seen_urls: Set[str], results_by_type: Dict[str, List[Dict[str, Any]]],
                              to_visit: asyncio.Queue[Tuple[str, int]], current_depth: int) -> Tuple[Set[str], List[Tag]]:
        """Обрабатывает и сканирует один URL."""
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
            # Извлекаем ссылки и формы с текущей страницы
            links, forms = await self._extract_links_from_url(
                session, semaphore, url,
                urlparse(self.base_url).netloc,
                visited_urls,
                only_forms=False
            )
            
            # Добавляем URL в visited_urls сразу после извлечения
            visited_urls.add(url)

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
                # Проверяем безопасность URL перед добавлением в очередь
                if not is_safe_url(link):
                    logger.warning(f"SKIP_UNSAFE_URL: {link}")
                    continue
                new_depth = current_depth + 1
                await to_visit.put((link, new_depth))
                self.total_links_count += 1
                new_links_added += 1
                logger.info(f"ADD_LINK: {link} with depth {new_depth} (total_links_count={self.total_links_count})")
                # Не добавляем ссылку в visited_urls здесь, только в seen_urls
                seen_urls.add(link)

            logger.info(f"Link processing summary: total={len(links)}, added={new_links_added}, skipped_visited={skipped_visited}, skipped_file={skipped_file}")
            logger.info(f"Added {new_links_added} new links to queue. Queue size after adding links: {to_visit.qsize() if to_visit else 0}")

            # Сканируем текущий URL
            unique_forms = [f['form'] for f in self.all_found_forms if f.get('url') == url]
            logger.info(f"Found {len(unique_forms)} unique forms on {url}. Starting scan...")

            # Обновляем прогресс после обработки URL
            self.update_progress(
                url,
                current_depth,
                to_visit.qsize() if to_visit else 0
            )

            # Проверяем, достигли ли максимальной глубины
            if current_depth >= self.max_depth:
                self.max_depth_reached = True
                logger.info(f"Maximum depth {self.max_depth} reached at URL: {url}")

            logger.info(f"About to scan_single_url for {url} at depth {current_depth}")
            await self.scan_single_url(
                session, semaphore, url,
                scanned_urls,
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

    async def _extract_links_from_url(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                                      url: str, base_domain: str, visited_urls: Optional[Set[str]] = None, 
                                      only_forms: bool = False) -> Tuple[Set[str], List[Tag]]:
        """Извлекает ссылки и формы с указанного URL."""
        if visited_urls is None:
            visited_urls = set()
            
        found_links: Set[str] = set()
        found_forms: List[Tag] = []
        
        try:
            if self.should_stop or self._is_paused:
                return found_links, found_forms
            if not url:
                logger.warning("Attempted to extract links from empty URL")
                return found_links, found_forms

            async with semaphore:
                result = await self.smart_request(
                    session=session, 
                    method='GET', 
                    url=url, 
                    retries=2
                )

                if result is None:
                    logger.debug(f"No response received for URL: {url}")
                    return found_links, found_forms
                
                html_content = result[1]
                if not html_content:
                    logger.debug(f"Empty HTML content received for URL: {url}")
                    return found_links, found_forms
                
                try:
                    # Используем LRU-кэш для парсинга HTML
                    soup = parse_html_cached(html_content)
                except Exception as parse_error:
                    log_and_notify('error', f"Failed to parse HTML from {url}: {parse_error}")
                    return found_links, found_forms

                # Если only_forms=False, ищем ссылки
                if not only_forms:
                    try:
                        for link in soup.find_all('a', href=True):
                            href = str(link.get('href', '')).strip()
                            if not href:
                                continue
                                
                            absolute_url = urljoin(url, href)
                            if self.is_same_domain(absolute_url, base_domain):
                                if absolute_url not in visited_urls:
                                    found_links.add(absolute_url)
                    except Exception as link_error:
                        log_and_notify('warning', f"Error processing links in {url}: {link_error}")

                # Ищем формы
                try:
                    for form in soup.find_all('form'):
                        found_forms.append(form)
                except Exception as form_error:
                    log_and_notify('warning', f"Error extracting forms from {url}: {form_error}")

        except aiohttp.ClientError as client_error:
            log_and_notify('error', f"Network error while processing {url}: {client_error}")
        except Exception as e:
            log_and_notify('error', f"Unexpected error processing {url}: {e}")
            
        return found_links, found_forms

    async def scan_single_url(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                        url: str, scanned_urls: Set[str],
                        results_by_type: Dict[str, List[Dict[str, Any]]], 
                        to_visit: asyncio.Queue[Tuple[str, int]], current_depth: int, 
                        forms_to_scan: Optional[List[Tag]] = None):
        """Сканирует один URL на уязвимости."""
        precollected = forms_to_scan is not None
        if forms_to_scan is None:
            forms_to_scan = []
            
        if url in scanned_urls:
            logger.info(f"URL {url} already in scanned_urls, skipping")
            return
        if self._is_paused:
            logger.info(f"Scan is paused, skipping URL {url}")
            return
            
        logger.info(f"Starting to scan URL: {url} at depth {current_depth}")
        
        # Используем self.visited_urls вместо параметра
        if url in self.visited_urls:
            logger.info(f"URL {url} already in visited_urls, skipping")
            return


        # Используем семафор для ограничения параллелизма
        async with semaphore:
            # Проверяем флаги снова перед началом обработки
            if self.should_stop or self._is_paused:
                return

            scanned_urls.add(url)
            self.visited_urls.add(url)
            self.all_scanned_urls.add(url)
            self.total_scanned_count += 1

            # Обновляем статистику после добавления URL в сканированные
            self.update_stats()

            # Если ссылки/формы ещё не собраны, извлекаем их с текущей страницы.
            # Когда данные уже переданы из _process_and_scan_url, повторно не ходим.
            if not precollected and current_depth < self.max_depth:
                logger.info(f"Extracting links from {url} at depth {current_depth} (max_depth: {self.max_depth})")
                try:
                    links, forms = await self._extract_links_from_url(
                        session, semaphore, url,
                        urlparse(self.base_url).netloc,
                        self.visited_urls,
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
                        if link not in self.visited_urls:
                            if is_file_url(link):
                                logger.info(f"SKIP_FILE: {link}")
                                continue
                            # Проверяем безопасность URL перед добавлением в очередь
                            if not is_safe_url(link):
                                logger.warning(f"SKIP_UNSAFE_URL: {link}")
                                continue
                            new_depth = current_depth + 1
                            await to_visit.put((link, new_depth))
                            self.total_links_count += 1
                            new_links_added += 1
                            logger.info(f"ADD_LINK: {link} with depth {new_depth} (total_links_count={self.total_links_count})")
                    logger.info(f"Added {new_links_added} new links to queue. Queue size after adding links: {to_visit.qsize() if to_visit else 0}")
                    # Отправляем сигнал для обновления структуры сайта
                    self.signals.site_structure_updated.emit(list(self.all_scanned_urls), self.all_found_forms)

                    # Обновляем формы для сканирования уязвимостей
                    forms_to_scan = [f['form'] for f in self.all_found_forms if f['url'] == url]
                    logger.info(f"Found {len(forms_to_scan)} unique forms on {url}. Starting scan...")

                except Exception as e:
                    log_and_notify('error', f"Error extracting links from {url}: {e}")
            else:
                logger.info(f"Reached max depth {current_depth} for URL {url}, not extracting links")
                
        try:
            # Регистрируем уникальные формы для статистики
            new_forms_count = 0
            for form in forms_to_scan:
                form_hash = self.get_form_hash(form)
                if form_hash not in self.scanned_form_hashes:
                    self.scanned_form_hashes.add(form_hash)
                    new_forms_count += 1
            if new_forms_count > 0:
                self.scanned_forms_count += new_forms_count

            # --- Ограничиваем количество одновременных задач (batch gather) ---
            batch_size = min(3, self.max_concurrent)  # уменьшено до 3 для снижения нагрузки
            tasks: List[asyncio.Task[Any]] = []
            task_scan_types: List[str] = []
            for scan_type in self.scan_types:
                if self.should_stop:
                    return
                if scan_type == 'sql':
                    tasks.append(asyncio.create_task(self.check_sql_injection(session, url, forms_to_scan)))
                    task_scan_types.append(scan_type)
                elif scan_type == 'xss':
                    tasks.append(asyncio.create_task(self.check_xss(session, url, forms_to_scan)))
                    task_scan_types.append(scan_type)
                elif scan_type == 'csrf':
                    tasks.append(asyncio.create_task(self.check_csrf(url, forms_to_scan)))
                    task_scan_types.append(scan_type)

            # --- Batch gather ---
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i+batch_size]
                results = await asyncio.gather(*batch, return_exceptions=True)
                for j, result in enumerate(results):
                    task_index = i + j
                    if isinstance(result, Exception):
                        log_and_notify('error', f"Failed to scan URL {url}: {result}")
                    elif result:
                        scan_type = task_scan_types[task_index] if task_index < len(task_scan_types) else 'unknown'
                        if isinstance(result, dict):
                            self._process_scan_results(url, [result], [scan_type], results_by_type)
                        elif isinstance(result, str):
                            self._process_scan_results(url, [{'details': result}], [scan_type], results_by_type)
                                
            self.update_progress(url, current_depth, to_visit.qsize() if to_visit else 0)
            logger.info(f"Successfully scanned URL: {url} at depth {current_depth}")
            
        except Exception as e:
            log_and_notify('error', f"Failed to scan URL {url}: {e}")

    def _process_scan_results(self, url: str, results: List[Dict[str, Any]], 
                            scan_types_used: List[str], results_by_type: Dict[str, List[Dict[str, Any]]]):
        """Обрабатывает результаты сканирования."""
        try:
            for scan_type in scan_types_used:
                if scan_type in results_by_type:
                    results_by_type[scan_type].append({
                        'url': url,
                        'details': str(results),
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    if scan_type not in self.vulnerabilities:
                        self.vulnerabilities[scan_type] = []
                    
                    details = str(results)
                    self.vulnerabilities[scan_type].append({
                        'url': url,
                        'details': details,
                        'timestamp': datetime.now().isoformat()
                    })
                    self.signals.vulnerability_found.emit(url, scan_type, details)
                    
        except Exception as e:
            logger.error(f"Error processing scan results: {e}")

    async def check_sql_injection(self, session: aiohttp.ClientSession, url: str, 
                            forms: Optional[List[Tag]] = None) -> Optional[str]:
        """Проверка на SQL-инъекции."""
        if forms is None:
            forms = []
        try:
            # Тестируем параметры URL
            if '?' in url:
                for payload in SAFE_SQL_PAYLOADS[:5]:  # Уменьшено до 5 для повышения производительности
                    if self.should_stop:
                        return None
                        
                    test_url = self._inject_payload_into_url(url, payload)
                    result = await self.smart_request(session, 'GET', test_url)
                    
                    if result:
                        _, content = result
                        if any(pattern.search(content) for pattern in SQL_ERROR_PATTERNS):
                            return f"SQL injection vulnerability detected with payload: {payload}"
            
            # Тестируем формы
            for form in forms:
                if self.should_stop:
                    return None
                    
                action = urljoin(url, str(form.get('action', '')))
                method = str(form.get('method', 'get')).upper()
                
                # Создаем тестовые данные для формы
                form_data: Dict[str, str] = {}
                # Ограничиваем количество полей формы для тестирования
                input_elements = form.find_all('input')[:3]  # Максимум 3 поля
                for input_elem in input_elements:
                    input_name = str(input_elem.get('name', ''))
                    if input_name and input_elem.get('type') in ['text', 'password', 'email', 'search', 'url']:
                        form_data[input_name] = SAFE_SQL_PAYLOADS[0]  # Используем первый пэйлоад
                
                if form_data:
                    if method == 'POST':
                        result = await self.smart_request(session, 'POST', action, data=form_data)
                    else:
                        test_url = f"{action}?{urlencode(form_data)}"
                        result = await self.smart_request(session, 'GET', test_url)
                    
                    if result:
                        _, content = result
                        if any(pattern.search(content) for pattern in SQL_ERROR_PATTERNS):
                            return f"SQL injection vulnerability detected in form to {action}"
            
            return None
            
        except Exception as e:
            logger.error(f"Error in SQL injection check: {e}")
            return None


    async def check_xss(self, session: aiohttp.ClientSession, url: str, 
                       forms: List[Tag]) -> Optional[str]:
        """Проверка на XSS-уязвимости."""
        try:
            # Тестируем параметры URL
            if '?' in url:
                for payload in SAFE_XSS_PAYLOADS[:3]:  # Уменьшено до 3 для повышения производительности
                    if self.should_stop:
                        return None
                        
                    test_url = self._inject_payload_into_url(url, payload)
                    result = await self.smart_request(session, 'GET', test_url)
                    
                    if result:
                        _, content = result
                        if payload in content:
                            # Проверяем, что пэйлоад не был экранирован
                            from bs4 import BeautifulSoup as BS
                            soup = BS(content, 'html.parser')
                            scripts = soup.find_all('script')
                            for script in scripts:
                                if script.string and payload in script.string:
                                    return f"XSS vulnerability detected with payload: {payload}"
            
            # Тестируем формы
            for form in forms:
                if self.should_stop:
                    return None
                    
                action = urljoin(url, str(form.get('action', '')))
                method = str(form.get('method', 'get')).upper()
                
                # Создаем тестовые данные для формы
                form_data: Dict[str, str] = {}
                # Ограничиваем количество полей формы для тестирования
                input_elements = form.find_all('input')[:3]  # Максимум 3 поля
                for input_elem in input_elements:
                    input_name = str(input_elem.get('name', ''))
                    if input_name and input_elem.get('type') in ['text', 'password', 'email', 'search', 'url']:
                        form_data[input_name] = SAFE_XSS_PAYLOADS[0]  # Используем первый пэйлоад
                
                if form_data:
                    if method == 'POST':
                        result = await self.smart_request(session, 'POST', action, data=form_data)
                    else:
                        test_url = f"{action}?{urlencode(form_data)}"
                        result = await self.smart_request(session, 'GET', test_url)
                    
                    if result:
                        _, content = result
                        if SAFE_XSS_PAYLOADS[0] in content:
                            return f"XSS vulnerability detected in form to {action}"
            
            return None
            
        except Exception as e:
            logger.error(f"Error in XSS check: {e}")
            return None

    async def check_csrf(self, url: str, forms: List[Tag]) -> Optional[str]:
        """Проверка на CSRF-уязвимости."""
        try:
            known_csrf_token_names = {
                'csrf_token', 'csrfmiddlewaretoken', 'authenticity_token',
                '_csrf', '_token', '__requestverificationtoken', 'xsrf_token'
            }

            vulnerable_form_actions: List[str] = []
            
            for form in forms:
                try:
                    action = urljoin(url, str(form.get('action', '')))
                    form_method = str(form.get('method', 'get')).upper()

                    # Проверяем только POST формы
                    if form_method == 'POST':
                        # Ищем скрытые поля в форме
                        hidden_fields = form.find_all('input', type='hidden')
                        form_has_csrf_token = False
                        
                        for field in hidden_fields:
                            field_name = str(field.get('name', '')).lower()
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
                result = f"Potential CSRF in POST forms to: {', '.join(unique_actions[:3])}"  # Ограничиваем вывод
                return result
            
            return None
            
        except Exception as e:
            log_and_notify('error', f"Error in check_csrf: {e}")
            return None

    def _inject_payload_into_url(self, url: str, payload: str) -> str:
        """Внедряет пэйлоад в параметры URL."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Добавляем пэйлоад к каждому параметру
        injected_params: Dict[str, List[str]] = {}
        for key, values in query_params.items():
            injected_params[key] = [f"{value}{payload}" for value in values]
        
        new_query = urlencode(injected_params, doseq=True)
        return parsed._replace(query=new_query).geturl()

    async def scan(self) -> Dict[str, Any]:
        """Основной метод для запуска сканирования."""
        try:
            logger.info(f"Starting scan for URL: {self.base_url}")
            self.scan_start_time = datetime.now()
            self.start_time = time.time()
            
            self.signals.log_event.emit(f"🚀 Начинаем сканирование: {self.base_url} (глубина: {self.max_depth})")
            
            # Инициализация (полный сброс состояния между запусками)
            self.visited_urls.clear()
            self.scanned_urls.clear()
            self.all_scanned_urls.clear()
            self.all_found_forms.clear()
            self.scanned_form_hashes.clear()
            self.unscanned_urls.clear()
            self.vulnerabilities = {'sql': [], 'xss': [], 'csrf': []}
            self.scanned_forms_count = 0
            self.total_scanned_count = 0
            self.total_forms_count = 0
            self.current_form_index = 0
            self.current_depth = 0
            self.max_depth_reached = False
            self.scan_complete = False
            self.scan_completion_metrics['errors_encountered'] = 0
            self.scan_completion_metrics['urls_scanned'] = 0
            self.scan_completion_metrics['vulnerabilities_found'] = 0

            self.to_visit = asyncio.Queue()
            
            await self.to_visit.put((self.base_url, 0))
            self.total_links_count = 1
            
            # Основное сканирование
            timeout = self._client_timeout()
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                semaphore = asyncio.Semaphore(self.max_concurrent)
                self.session = session
                
                # Преобразуем scan_types
                scan_types_lower: List[str] = []
                for scan_type in self.scan_types:
                    if 'sql' in scan_type.lower():
                        scan_types_lower.append('sql')
                    elif 'xss' in scan_type.lower():
                        scan_types_lower.append('xss')
                    elif 'csrf' in scan_type.lower():
                        scan_types_lower.append('csrf')
                
                if not scan_types_lower:
                    scan_types_lower = ['sql', 'xss', 'csrf']
                
                self.scan_types = scan_types_lower
                
                # Выполняем сканирование
                results_by_type: Dict[str, List[Dict[str, Any]]] = {'sql': [], 'xss': [], 'csrf': []}
                visited_urls: Set[str] = set()
                scanned_urls: Set[str] = set()
                
                await self.crawl_and_scan_parallel(session, semaphore, self.base_url, 
                                                 results_by_type, visited_urls, scanned_urls)
            
            # Завершение
            self.scan_end_time = datetime.now()
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
            
            if self.should_stop:
                status = 'stopped_by_user'
                self.signals.log_event.emit(f"⏹️ Сканирование остановлено пользователем. Просканировано URL: {self.total_scanned_count}")
            else:
                status = 'completed'
                self.signals.log_event.emit(f"✅ Сканирование завершено за {scan_duration:.2f}с")
            
            # Формируем результаты
            result: Dict[str, Any] = {
                'url': self.base_url,
                'scan_types': self.scan_types,
                'duration': scan_duration,
                'total_urls_scanned': len(self.all_scanned_urls),
                'total_forms_scanned': self.scanned_forms_count,
                'vulnerabilities': self.vulnerabilities,
                'timestamp': datetime.now().isoformat(),
                'total_urls_discovered': self.total_links_count,
                'unscanned_urls': list(self.unscanned_urls),
                'status': status
            }
            
            total_vulnerabilities = sum(len(vulns) for vulns in self.vulnerabilities.values())
            self.signals.log_event.emit(f"📊 Просканировано URL: {len(self.all_scanned_urls)}, форм: {self.scanned_forms_count}, уязвимостей: {total_vulnerabilities}")
            
            self.update_stats()
            return result
            
        except Exception as e:
            logger.error(f"Error in scan method: {e}")
            self.signals.log_event.emit(f"❌ Ошибка сканирования: {str(e)}")
            
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
                'unscanned_urls': list(self.unscanned_urls),
                'status': 'failed'
            }

    async def save_results(self):
        """Сохраняет результаты сканирования в базу данных."""
        try:
            scan_duration = time.time() - self.start_time if hasattr(self, 'start_time') and self.start_time > 0 else 0
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
                logger.error("Failed to save scan results")
                
            # Очистка кэшей
            if hasattr(parse_html_cached, 'cache_info') and hasattr(parse_html_cached, 'cache_clear'):
                parse_html_cached.cache_clear()
            cache_manager.cleanup_all()
            gc.collect()
            
        except Exception as e:
            logger.error(f"Error saving scan results: {e}")
            self.signals.log_event.emit(f"❌ Ошибка сохранения результатов: {str(e)}")