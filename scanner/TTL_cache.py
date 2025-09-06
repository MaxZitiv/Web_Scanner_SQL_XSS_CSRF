from datetime import datetime, timedelta
from typing import Any, Optional, Dict, Tuple

class TTLCache:
    """Кэш с ограниченным временем жизни"""

    def __init__(self, maxsize: int = 1000, ttl: int = 300):
        self.cache: Dict[str, Tuple[Any, datetime]] = {}
        self.maxsize = maxsize
        self.ttl = ttl

    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            value, expire_time = self.cache[key]
            if datetime.now() < expire_time:
                return value
            else:
                del self.cache[key]
        return None
    
    def set(self, key: str, value: Any) -> None:
        if len(self.cache) >= self.maxsize:
            oldest_key = min(self.cache, 
                            key=lambda k: self.cache[k][1])
            del self.cache[oldest_key]

        expire_time = datetime.now() + timedelta(seconds=self.ttl)
        self.cache[key] = (value, expire_time)

    def clear(self) -> None:
        self.cache.clear()

    def __len__(self) -> int:
        """Возвращает количество элементов в кэше."""
        return len(self.cache)
