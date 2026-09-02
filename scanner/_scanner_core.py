import hashlib
import time

import aiohttp
from PyQt6.QtCore import QObject, pyqtSignal

from utils.database import db
from utils.logger import logger

from ._scanner_config import (
    MAX_CONCURRENT_REQUESTS,
    MAX_DEPTH,
    MAX_PAYLOADS_PER_URL,
    MAX_RETRIES,
    REQUEST_TIMEOUT,
    SAFE_CSRF_PAYLOADS,
    SAFE_SQL_PAYLOADS,
    SAFE_XSS_PAYLOADS,
    SQL_ERROR_PATTERNS,
    ScanResults,
)


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
            "max_depth": MAX_DEPTH,
            "timeout": REQUEST_TIMEOUT,
            "max_retries": MAX_RETRIES,
            "concurrent_requests": MAX_CONCURRENT_REQUESTS,
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
            logger.error(f"Error testing payload {payload}: {e!s}")

    async def _send_request_with_payload(self, payload: str) -> aiohttp.ClientResponse | None:
        """Отправка HTTP запроса с пэйлоадом."""
        if self.should_stop or self._is_paused or not self._current_url:
            return None

        timeout = aiohttp.ClientTimeout(total=self._scan_options["timeout"])

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if "?" in self._current_url:
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
            duration = (
                (self._scan_end_time - self._scan_start_time).total_seconds()
                if self._scan_end_time and self._scan_start_time
                else 0.0
            )

            db_results: list[dict[str, str]] = []

            # Если уязвимостей не найдено, добавляем запись об этом
            if not self._scan_results:
                db_results.append(
                    {
                        "type": "info",
                        "url": self._current_url,
                        "details": "Сканирование завершено. Уязвимости не найдены.",
                        "severity": "info",
                    }
                )
            else:
                db_results.extend(
                    {
                        "type": result.get("vulnerability_type", "unknown"),
                        "url": result.get("url", self._current_url),
                        "details": result.get("description", ""),
                        "severity": result.get("severity", "medium"),
                    }
                    for result in self._scan_results
                )

            scan_type = self._scan_options.get("type", "general")
            if not isinstance(scan_type, str):
                scan_type = str(scan_type)

            db.save_scan_async(
                user_id=int(self._scan_id, 16),
                url=self._current_url,
                results=db_results,
                scan_type=scan_type,
                scan_duration=duration,
            )
        except Exception as e:
            logger.error(f"Error saving scan results: {e!s}")
