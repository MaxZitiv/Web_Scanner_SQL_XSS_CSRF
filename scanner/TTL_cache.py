from datetime import datetime, timedelta

class TTLCache:
    """Кэш с ограниченным временем жизни"""

    def __init__(self, maxsize=1000, ttl=300):
        self.cache = {}
        self.maxsize = maxsize
        self.ttl = ttl

    def get(self, key):
        if key in self.cache:
            value, expire_time = self.cache[key]
            if datetime.now() < expire_time:
                return value
            else:
                del self.cache[key]
        return None
    
    def set(self, key, value):
        if len(self.cache) >= self.maxsize:
            oldest_key = min(self.cache, 
                            key=lambda k: self.cache[k][1])
            del self.cache[oldest_key]

        expire_time = datetime.now() + timedelta(seconds=self.ttl)
        self.cache[key] = (value, expire_time)

    def clear(self):
        self.cache.clear()

    def __len__(self):
        """Возвращает количество элементов в кэше."""
        return len(self.cache)
