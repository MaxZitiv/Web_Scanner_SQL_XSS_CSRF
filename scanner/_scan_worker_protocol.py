"""Протокол общего состояния всех частей ScanWorker.

Позволяет миксам воркера обращаться к атрибутам и методам друг друга,
оставаясь типизированными для Pyright.
"""

import asyncio
from datetime import datetime
from typing import Any, Protocol

import aiohttp
from bs4.element import Tag

from ._scan_worker_signals import ScanWorkerSignals
from ._scanner_config import ScanCompletionMetrics


class _ScanWorkerProtocol(Protocol):
    # Состояние и флаги
    _max_coverage_mode: bool
    _should_stop: bool
    _is_paused: bool
    _cancelled: bool

    @property
    def max_coverage_mode(self) -> bool: ...

    @max_coverage_mode.setter
    def max_coverage_mode(self, value: bool) -> None: ...

    @property
    def should_stop(self) -> bool: ...

    @should_stop.setter
    def should_stop(self, value: bool) -> None: ...

    max_depth_reached: bool
    scan_complete: bool
    scan_started: bool
    reported_progress: int

    # Очереди и множества
    to_visit: asyncio.Queue[tuple[str, int]]
    visited: set[str]
    in_progress: set[str]
    visited_urls: set[str]
    scanned_urls: set[str]
    unscanned_urls: set[str]
    all_scanned_urls: set[str]
    scanned_form_hashes: set[str]
    url_cache: set[str]

    # Счётчики
    total_scanned_count: int
    total_forms_count: int
    total_vuln_count: int
    scanned_forms_count: int
    current_form_index: int
    total_links_count: int
    operation_count: int
    memory_check_interval: int
    current_depth: int

    # Параметры
    url: str
    scan_types: list[str]
    user_id: int
    username: str | None
    max_depth: int
    max_concurrent: int
    timeout: int
    base_url: str
    current_url: str

    # Кэши и хранилища
    all_found_forms: list[dict[str, Any]]
    html_cache: dict[str, Any]
    dns_cache: dict[str, Any]
    form_cache: dict[str, Any]
    vulnerabilities: dict[str, list[dict[str, Any]]]

    # Результаты и сигналы
    scan_completion_metrics: ScanCompletionMetrics
    signals: ScanWorkerSignals
    session: aiohttp.ClientSession | None
    scan_start_time: datetime | None
    scan_end_time: datetime | None
    start_time: float

    # Методы ядра
    async def run_scan(self: _ScanWorkerProtocol) -> dict[str, Any]: ...
    async def scan_url(self: _ScanWorkerProtocol, url: str) -> str | None: ...
    async def _process_url(self: _ScanWorkerProtocol, url: str) -> str | None: ...
    def stop(self: _ScanWorkerProtocol) -> None: ...
    def pause(self: _ScanWorkerProtocol) -> None: ...
    def resume(self: _ScanWorkerProtocol) -> None: ...
    def is_paused(self: _ScanWorkerProtocol) -> bool: ...
    def calculate_progress(self: _ScanWorkerProtocol) -> int: ...
    def update_progress(
        self: _ScanWorkerProtocol,
        current_url: str,
        current_depth: int | None,
        queue_size: int | None,
    ) -> None: ...
    def _client_timeout(self: _ScanWorkerProtocol) -> aiohttp.ClientTimeout: ...
    async def smart_request(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        retries: int = 2,
        **kwargs: Any,
    ) -> tuple[aiohttp.ClientResponse, str] | None: ...
    async def _scan_sql_injection(self: _ScanWorkerProtocol, url: str) -> None: ...
    async def _scan_xss(self: _ScanWorkerProtocol, url: str) -> None: ...
    async def _scan_csrf(self: _ScanWorkerProtocol, url: str) -> None: ...
    def _cleanup_caches(self: _ScanWorkerProtocol) -> None: ...
    def update_stats(self: _ScanWorkerProtocol) -> None: ...
    def _manage_memory_usage(self: _ScanWorkerProtocol) -> None: ...
    def _check_memory_periodically(self: _ScanWorkerProtocol) -> None: ...

    # Методы обхода
    async def crawl(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
    ) -> None: ...
    async def crawl_and_scan_parallel(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        start_url: str,
        results_by_type: dict[str, list[dict[str, Any]]],
        visited_urls: set[str],
        scanned_urls: set[str],
    ) -> None: ...
    async def _process_and_scan_url(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        url: str,
        visited_urls: set[str],
        scanned_urls: set[str],
        seen_urls: set[str],
        results_by_type: dict[str, list[dict[str, Any]]],
        to_visit: asyncio.Queue[tuple[str, int]],
        current_depth: int,
    ) -> tuple[set[str], list[Tag]]: ...
    async def _extract_links_from_url(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        url: str,
        base_domain: str,
        visited_urls: set[str] | None,
        only_forms: bool,
    ) -> tuple[set[str], list[Tag]]: ...
    async def scan_single_url(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        url: str,
        scanned_urls: set[str],
        results_by_type: dict[str, list[dict[str, Any]]],
        to_visit: asyncio.Queue[tuple[str, int]],
        current_depth: int,
        forms_to_scan: list[Tag] | None,
    ) -> None: ...

    # Проверки и результаты
    def _process_scan_results(
        self: _ScanWorkerProtocol,
        url: str,
        results: list[Any],
        scan_types_used: list[str],
        results_by_type: dict[str, list[dict[str, Any]]],
    ) -> None: ...
    def _vulnerability_result(
        self: _ScanWorkerProtocol,
        url: str,
        *,
        param: str = "",
        method: str = "GET",
        action: str = "",
        field: str = "",
        payload: str = "",
        test_url: str = "",
        note: str = "",
    ) -> dict[str, Any]: ...
    async def check_sql_injection(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        url: str,
        forms: list[Tag] | None,
    ) -> dict[str, Any] | None: ...
    async def check_xss(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        url: str,
        forms: list[Tag],
    ) -> dict[str, Any] | None: ...
    async def check_csrf(self: _ScanWorkerProtocol, url: str, forms: list[Tag]) -> dict[str, Any] | None: ...
    def _inject_payload_into_url(self: _ScanWorkerProtocol, url: str, payload: str) -> str: ...
    @staticmethod
    def _query_parameter_names(url: str) -> list[str]: ...
    def _inject_payload_into_param(self: _ScanWorkerProtocol, url: str, param_name: str, payload: str) -> str: ...
    @staticmethod
    def _form_field_name(field: Tag) -> str: ...
    @staticmethod
    def get_form_hash(form_tag: Tag) -> str: ...
    @staticmethod
    def is_same_domain(url: str, base_domain: str) -> bool: ...

    # Оркестрация
    async def scan(self: _ScanWorkerProtocol) -> dict[str, Any]: ...
    async def save_results(self: _ScanWorkerProtocol) -> None: ...


__all__ = ["_ScanWorkerProtocol"]
