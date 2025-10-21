import gc
from typing import Any, Dict, Optional
from utils.logger import logger

class TTLCache:
    """Кэш с временем жизни для каждой записи"""
    
    def __init__(self, maxsize: int = 100, ttl: int = 300):
        """
        Инициализация кэша
        :param maxsize: Максимальный размер кэша
        :param ttl: Время жизни записей в секундах
        """
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._maxsize = maxsize
        self._ttl = ttl
        
    def get(self, key: str) -> Optional[Any]:
        """Получение значения из кэша с проверкой TTL"""
        import time
        if key in self._cache:
            if time.time() - self._timestamps[key] < self._ttl:
                return self._cache[key]
            else:
                # Удаляем просроченную запись
                del self._cache[key]
                del self._timestamps[key]
        return None
        
    def set(self, key: str, value: Any) -> None:
        """Добавление значения в кэш"""
        import time
        # Если достигнут максимальный размер, удаляем самую старую запись
        if len(self._cache) >= self._maxsize:
            oldest_key = min(self._timestamps.keys(), key=lambda k: self._timestamps[k])
            del self._cache[oldest_key]
            del self._timestamps[oldest_key]
        
        self._cache[key] = value
        self._timestamps[key] = time.time()
        
    def clear(self) -> None:
        """Очистка кэша"""
        self._cache.clear()
        self._timestamps.clear()
        
    def __len__(self) -> int:
        """
        Возвращает текущий размер кэша
        :return: Количество элементов в кэше
        """
        return len(self._cache)

class CacheManager:
    """Менеджер кэшей с автоматической очисткой"""
    
    def __init__(self, cleanup_threshold: int = 1000):
        self.HTML_CACHE = TTLCache(maxsize=100, ttl=300)
        self.DNS_CACHE = TTLCache(maxsize=100, ttl=300)
        self.FORM_HASH_CACHE = TTLCache(maxsize=100, ttl=300)
        self.URL_PROCESSING_CACHE = TTLCache(maxsize=100, ttl=300)
        self.cleanup_threshold = cleanup_threshold
        self._operations_count = 0
        
    def get_cached_data(self, cache_type: str, key: str) -> Optional[Any]:
        """Получение данных из указанного кэша"""
        cache: Optional[TTLCache] = getattr(self, f"{cache_type}_CACHE", None)
        if cache:
            return cache.get(key)
        return None
        
    def set_cached_data(self, cache_type: str, key: str, value: Any) -> None:
        """Сохранение данных в указанный кэш"""
        cache = getattr(self, f"{cache_type}_CACHE", None)
        if cache:
            cache.set(key, value)
            self.increment_operations()
    
    def increment_operations(self) -> None:
        """Увеличивает счетчик операций и при необходимости очищает кэш"""
        self._operations_count += 1
        if self._operations_count >= self.cleanup_threshold:
            self.cleanup_all()
    
    def cleanup_all(self) -> None:
        """Очищает все кэши"""
        self.HTML_CACHE.clear()
        self.DNS_CACHE.clear()
        self.FORM_HASH_CACHE.clear()
        self.URL_PROCESSING_CACHE.clear()
        self._operations_count = 0
        gc.collect()
        logger.debug("All caches cleaned up")
    
    @property
    def operations_count(self) -> int:
        """Возвращает текущее количество операций"""
        return self._operations_count

# Глобальный экземпляр менеджера кэша
cache_manager = CacheManager()