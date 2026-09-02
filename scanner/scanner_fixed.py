"""
Основной модуль сканера уязвимостей.

Точка входа, которая реэкспортирует сканер, разделённый на небольшие модули.
"""

from ._scan_worker import ScanWorker, ScanWorkerSignals
from ._scanner_config import (
    DEFAULT_HTML_PARSER,
    DNS_CACHE,
    EXCLUDED_EXTENSIONS,
    FORM_HASH_CACHE,
    FORM_INPUT_TYPES,
    HTML_CACHE,
    HTTP_OPTIMIZATIONS,
    MAX_CONCURRENT_REQUESTS,
    MAX_DEPTH,
    MAX_PAYLOADS_PER_URL,
    MAX_RETRIES,
    REQUEST_TIMEOUT,
    SAFE_CSRF_PAYLOADS,
    SAFE_SQL_PAYLOADS,
    SAFE_XSS_PAYLOADS,
    SKIP_EXTENSIONS,
    SQL_ERROR_PATTERNS,
    URL_PROCESSING_CACHE,
    XSS_REFLECTED_PATTERNS,
    ScanCompletionMetrics,
    ScanResults,
    VulnerabilityResult,
    is_file_url,
    parse_html_cached,
)
from ._scanner_core import Scanner
from .cache_manager import TTLCache, cache_manager

__all__ = [
    "DEFAULT_HTML_PARSER",
    "DNS_CACHE",
    "EXCLUDED_EXTENSIONS",
    "FORM_HASH_CACHE",
    "FORM_INPUT_TYPES",
    "HTML_CACHE",
    "HTTP_OPTIMIZATIONS",
    "MAX_CONCURRENT_REQUESTS",
    "MAX_DEPTH",
    "MAX_PAYLOADS_PER_URL",
    "MAX_RETRIES",
    "REQUEST_TIMEOUT",
    "SAFE_CSRF_PAYLOADS",
    "SAFE_SQL_PAYLOADS",
    "SAFE_XSS_PAYLOADS",
    "SKIP_EXTENSIONS",
    "SQL_ERROR_PATTERNS",
    "URL_PROCESSING_CACHE",
    "XSS_REFLECTED_PATTERNS",
    "ScanCompletionMetrics",
    "ScanResults",
    "ScanWorker",
    "ScanWorkerSignals",
    "Scanner",
    "TTLCache",
    "VulnerabilityResult",
    "cache_manager",
    "is_file_url",
    "parse_html_cached",
]
