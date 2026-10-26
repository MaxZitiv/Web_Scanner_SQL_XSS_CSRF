import asyncio
from types import TracebackType
from typing import Any

import aiohttp

from utils.http_safety import HTTPPolicyError, create_session, origin, request_text
from utils.logger import log_and_notify, logger


class NetworkManager:
    """Менеджер сетевых запросов"""

    def __init__(self, timeout: int = 30, max_retries: int = 3, max_concurrent: int = 5):
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self._session: aiohttp.ClientSession | None = None
        self._scope_url: str | None = None
        self._headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

    async def __aenter__(self) -> NetworkManager:
        await self.initialize()
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None
    ) -> None:
        await self.cleanup()

    async def initialize(self) -> None:
        """Инициализация сессии и семафора"""
        # Создаем новый семафор с актуальным значением max_concurrent
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        if not self._session:
            self._session = create_session(aiohttp.ClientTimeout(total=self.timeout), self._headers)

    async def cleanup(self) -> None:
        """Очистка ресурсов"""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        self._scope_url = None
        # Семафор не требует очистки

    async def request(self, method: str, url: str, **kwargs: Any) -> tuple[aiohttp.ClientResponse, str] | None:
        """Ограниченный запрос в пределах первого адреса этой сессии."""
        try:
            origin(url)
            if self._scope_url is None:
                self._scope_url = url
            if not self._session:
                await self.initialize()
            if self._session is None:
                raise RuntimeError("HTTP session is not initialized")
            options = dict(kwargs)
            options["timeout"] = aiohttp.ClientTimeout(total=self.timeout)
            attempts = max(1, self.max_retries) if method.upper() in {"GET", "HEAD"} else 1
            for attempt in range(attempts):
                try:
                    async with self.semaphore:
                        result = await request_text(self._session, method, url, scope_url=self._scope_url, **options)
                        result[0].raise_for_status()
                        return result
                except (TimeoutError, aiohttp.ClientError) as error:
                    logger.warning(f"Request attempt {attempt + 1} failed: {type(error).__name__}")
                    if attempt < attempts - 1:
                        await asyncio.sleep(attempt + 1)
            return None
        except HTTPPolicyError as error:
            logger.warning(f"Запрос пропущен: {error}")
            return None
        except Exception as error:
            log_and_notify("error", f"Network request failed: {type(error).__name__}")
            return None
