"""
Общие константы, кэши, типы и хелперы сканера уязвимостей.
"""

import os
import re
from functools import lru_cache
from typing import Any, TypedDict
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .cache_manager import TTLCache, cache_manager

# Очистка кэша при импорте модуля
cache_manager.cleanup_all()

# Глобальные кэши
HTML_CACHE = TTLCache(maxsize=1000, ttl=3600)
DNS_CACHE = TTLCache(maxsize=500, ttl=1800)
FORM_HASH_CACHE = TTLCache(maxsize=2000, ttl=7200)
URL_PROCESSING_CACHE = TTLCache(maxsize=5000, ttl=3600)

# Константы
DEFAULT_HTML_PARSER = "html.parser"
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30
MAX_CONCURRENT_REQUESTS = 5
MAX_PAYLOADS_PER_URL = 40
# Сканирование выполняется полностью: без ограничения глубины пользователем.
MAX_DEPTH = 10

# Оптимизированные настройки HTTP
HTTP_OPTIMIZATIONS: dict[str, Any] = {
    "timeout": {"total": 30, "connect": 10, "sock_read": 30, "sock_connect": 10},
    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    },
}

# Паттерны для обнаружения уязвимостей
SQL_ERROR_PATTERNS = [
    re.compile(r"sql", re.IGNORECASE),
    re.compile(r"mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"syntax error", re.IGNORECASE),
    re.compile(r"database error", re.IGNORECASE),
    re.compile(r"invalid query", re.IGNORECASE),
]

XSS_REFLECTED_PATTERNS = [
    re.compile(r"<script>alert\('XSS'\)</script>", re.IGNORECASE),
    re.compile(r"<svg/onload=alert\('XSS'\)>", re.IGNORECASE),
]

# Пэйлоады для тестирования
SAFE_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<iframe src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>Click</a>",
    '<form><button formaction="javascript:alert(1)">X</button></form>',
]

SAFE_SQL_PAYLOADS = [
    "'",
    '"',
    "`",
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
    "' OR 'a'='a'-- ",
]

SAFE_CSRF_PAYLOADS = [
    '<form action="/target" method="POST"><input type="hidden" name="amount" value="1000"></form>',
    '<img src="http://target.site/transfer?amount=1000&to=attacker">',
    '<script>fetch("/target",{method:"POST",body:"amount=1000"})</script>',
    '<iframe src="http://target.site/transfer?amount=1000&to=attacker"></iframe>',
]

# Конфигурация сканирования
FORM_INPUT_TYPES = {"text", "textarea", "password", "email", "search", "url", "tel", "number"}
EXCLUDED_EXTENSIONS = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2"}
SKIP_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".svg",
    ".ico",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".mp3",
    ".wav",
    ".mp4",
    ".avi",
    ".mov",
    ".mkv",
    ".exe",
    ".dll",
    ".bin",
    ".iso",
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
    parameter: str
    method: str
    action: str
    field: str
    test_url: str
    location: str


class ScanCompletionMetrics(TypedDict):
    errors_encountered: int
    urls_scanned: int
    vulnerabilities_found: int
    status: str


ScanResults = list[VulnerabilityResult]
