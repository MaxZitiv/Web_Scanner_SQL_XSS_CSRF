import asyncio
from typing import Any, Optional, Tuple, Type
from types import TracebackType
import aiohttp
from utils.logger import logger, log_and_notify
from .cache_manager import cache_manager


class NetworkManager:
    """Менеджер сетевых запросов"""
    
    def __init__(self, timeout: int = 30, max_retries: int = 3, max_concurrent: int = 5):
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self._session: Optional[aiohttp.ClientSession] = None
        self._headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
    
    async def __aenter__(self) -> 'NetworkManager':
        await self.initialize()
        return self
    
    async def __aexit__(
        self, 
        exc_type: Optional[Type[BaseException]], 
        exc_val: Optional[BaseException], 
        exc_tb: Optional[TracebackType]
    ) -> None:
        await self.cleanup()
    
    async def initialize(self) -> None:
        """Инициализация сессии и семафора"""
        # Создаем новый семафор с актуальным значением max_concurrent
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        if not self._session:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=self._headers
            )
    
    async def cleanup(self) -> None:
        """Очистка ресурсов"""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        # Семафор не требует очистки
    
    async def request(self, method: str, url: str, **kwargs: Any) -> Optional[Tuple[aiohttp.ClientResponse, str]]:
        """Выполнение HTTP запроса с поддержкой кэширования и повторных попыток"""
        cache_key = f"{method}:{url}:{hash(str(kwargs))}"
        cached_result = cache_manager.get_cached_data("URL_PROCESSING", cache_key)
        if cached_result:
            return cached_result

        if not self._session:
            await self.initialize()
            
        assert self._session

        for attempt in range(self.max_retries):
            try:
                async with self.semaphore:
                    async with self._session.request(method, url, **kwargs) as response:
                        response.raise_for_status()
                        
                        content_type = response.headers.get('Content-Type', '').lower()
                        if not any(t in content_type for t in ['html', 'text', 'json', 'xml', 'javascript']):
                            await response.read()
                            result = (response, "")
                        else:
                            try:
                                text = await response.text()
                            except UnicodeDecodeError:
                                text = await response.text(errors='replace')
                            result = (response, text)
                        
                        cache_manager.set_cached_data("URL_PROCESSING", cache_key, result)
                        return result

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed for {url}: {e}")
                if attempt == self.max_retries - 1:
                    log_and_notify('error', f"All attempts failed for {url}: {e}")
                    return None
                await asyncio.sleep(1 * (attempt + 1))
            except Exception as e:
                log_and_notify('error', f"Unexpected error on attempt {attempt + 1} for {url}: {e}")
                return None

        return None