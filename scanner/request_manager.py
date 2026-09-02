import asyncio
from types import TracebackType
from typing import Any

import aiohttp

from utils.logger import logger


class RequestManager:
    """Менеджер HTTP-запросов с поддержкой повторных попыток и ограничением конкурентности"""

    def __init__(self, timeout: int = 30, max_retries: int = 3, max_concurrent: int = 5):
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_concurrent = max_concurrent
        self.semaphore: asyncio.Semaphore = asyncio.Semaphore(max_concurrent)
        self._session: aiohttp.ClientSession | None = None
        self._headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

    async def __aenter__(self) -> RequestManager:
        await self.initialize()
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None
    ) -> None:
        """Асинхронный выход из контекстного менеджера"""
        await self.cleanup()

    async def initialize(self) -> None:
        """Инициализация сессии"""
        if not self._session:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout), headers=self._headers
            )

    async def cleanup(self) -> None:
        """Очистка ресурсов"""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def get(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse | None:
        """Выполнение GET-запроса с поддержкой повторных попыток"""
        if not self._session:
            await self.initialize()

        if self._session is None:  # Добавляем дополнительную проверку
            logger.error("Failed to initialize session")
            return None

        for attempt in range(self.max_retries):
            try:
                async with self.semaphore, self._session.get(url, **kwargs) as response:
                    response.raise_for_status()
                    return response
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed for {url}: {e}")
                if attempt == self.max_retries - 1:
                    logger.error(f"All attempts failed for {url}: {e}")
                    return None
                await asyncio.sleep(1 * (attempt + 1))  # Exponential backoff
        return None

    async def post(self, url: str, data: dict[str, Any], **kwargs: Any) -> aiohttp.ClientResponse | None:
        """Выполнение POST-запроса с поддержкой повторных попыток"""
        if not self._session:
            await self.initialize()

        if self._session is None:  # Добавляем дополнительную проверку
            logger.error("Failed to initialize session")
            return None

        for attempt in range(self.max_retries):
            try:
                async with self.semaphore, self._session.post(url, data=data, **kwargs) as response:
                    response.raise_for_status()
                    return response
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed for {url}: {e}")
                if attempt == self.max_retries - 1:
                    logger.error(f"All attempts failed for {url}: {e}")
                    return None
                await asyncio.sleep(1 * (attempt + 1))  # Exponential backoff
        return None
