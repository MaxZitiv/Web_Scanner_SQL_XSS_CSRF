import time
import functools
import threading
from typing import Callable, Any, Dict, List, Optional
from collections import OrderedDict
import psutil
import os
from utils.logger import logger, log_and_notify
from datetime import datetime
import pytz
import gc

class LRUCache:
    """LRU (Least Recently Used) кэш для оптимизации производительности"""
    
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self.cache: OrderedDict[str, Any] = OrderedDict()
        self.lock = threading.RLock()  # Используем RLock для лучшей производительности
    
    def get(self, key: str) -> Optional[Any]:
        """Получает значение из кэша"""
        with self.lock:
            if key in self.cache:
                # Перемещаем элемент в конец (самый недавно использованный)
                self.cache.move_to_end(key)
                return self.cache[key]
            return None
    
    def put(self, key: str, value: Any) -> None:
        """Добавляет значение в кэш"""
        with self.lock:
            if key in self.cache:
                # Обновляем существующий элемент
                self.cache.move_to_end(key)
                self.cache[key] = value
            else:
                # Добавляем новый элемент
                if len(self.cache) >= self.max_size:
                    # Удаляем самый старый элемент
                    self.cache.popitem(last=False)
                self.cache[key] = value
    
    def clear(self) -> None:
        """Очищает кэш"""
        with self.lock:
            self.cache.clear()
    
    def size(self) -> int:
        """Возвращает размер кэша"""
        with self.lock:
            return len(self.cache)
    
    def keys(self) -> List[str]:
        """Возвращает список ключей"""
        with self.lock:
            return list(self.cache.keys())

class PerformanceMonitor:
    """Монитор производительности приложения"""
    
    def __init__(self):
        self.metrics: Dict[str, List[float]] = {}
        self.async_metrics: Dict[str, List[float]] = {}
        self.start_time: float = time.time()
        self.lock: threading.RLock = threading.RLock()
        self.cache: LRUCache = LRUCache(max_size=1000)
        self._system_info_cache: Dict[str, Any] = {}
        self._system_info_cache_time: float = 0
        self._system_info_ttl: int = 5  # 5 секунд
    
    @staticmethod
    def start_timer(operation: str) -> float:
        """Начинает отсчет времени для операции"""
        return time.time()
    
    def end_timer(self, operation: str, start_time: float) -> float:
        """Завершает отсчет времени для операции и возвращает длительность"""
        duration = time.time() - start_time
        with self.lock:
            if operation not in self.metrics:
                self.metrics[operation] = []
            self.metrics[operation].append(duration)
        return duration
    
    @staticmethod
    async def start_async_timer(operation: str) -> float:
        """Начинает отсчет времени для асинхронной операции"""
        return time.time()
    
    async def end_async_timer(self, operation: str, start_time: float) -> float:
        """Завершает отсчет времени для асинхронной операции"""
        duration = time.time() - start_time
        with self.lock:
            if operation not in self.async_metrics:
                self.async_metrics[operation] = []
            self.async_metrics[operation].append(duration)
        return duration
    
    def get_average_time(self, operation: str) -> float:
        """Получает среднее время выполнения операции"""
        with self.lock:
            times = self.metrics.get(operation, [])
            return sum(times) / len(times) if times else 0.0
    
    def get_async_average_time(self, operation: str) -> float:
        """Получает среднее время выполнения асинхронной операции"""
        with self.lock:
            times = self.async_metrics.get(operation, [])
            return sum(times) / len(times) if times else 0.0
    
    def get_total_time(self, operation: str) -> float:
        """Получает общее время выполнения операции"""
        with self.lock:
            return sum(self.metrics.get(operation, []))
    
    def get_operation_count(self, operation: str) -> int:
        """Получает количество выполнений операции"""
        with self.lock:
            return len(self.metrics.get(operation, []))
    
    def get_system_info(self) -> Dict[str, Any]:
        """Получает информацию о системе с кэшированием"""
        current_time = time.time()
        
        # Проверяем кэш
        if (current_time - self._system_info_cache_time < self._system_info_ttl and 
            self._system_info_cache):
            return self._system_info_cache.copy()
        
        try:
            # Получаем актуальную информацию
            info = {
                'cpu_percent': psutil.cpu_percent(interval=0.1),  # Уменьшаем интервал
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'uptime': current_time - self.start_time
            }
            
            # Обновляем кэш
            self._system_info_cache = info
            self._system_info_cache_time = current_time
            
            return info
        except Exception as e:
            log_and_notify('error', f"Error getting system info: {e}")
            return {}
    
    def clear_metrics(self) -> None:
        """Очищает все метрики"""
        with self.lock:
            self.metrics.clear()
            self.async_metrics.clear()
            self.cache.clear()
            self._system_info_cache.clear()

# Глобальный монитор производительности
performance_monitor = PerformanceMonitor()

def measure_time(func: Callable[..., Any]) -> Callable[..., Any]:
    """Декоратор для измерения времени выполнения функции"""
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = performance_monitor.start_timer(func.__name__)
        try:
            return func(*args, **kwargs)
        finally:
            performance_monitor.end_timer(func.__name__, start_time)
    return wrapper

def measure_async_time(func: Callable[..., Any]) -> Callable[..., Any]:
    """Декоратор для измерения времени выполнения асинхронной функции"""
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = await performance_monitor.start_async_timer(func.__name__)
        try:
            return await func(*args, **kwargs)
        finally:
            await performance_monitor.end_async_timer(func.__name__, start_time)
    return wrapper

def cache_result(max_size: int = 100, ttl: int = 300):
    """Декоратор для кэширования результатов функций"""
    cache = LRUCache(max_size=max_size)
    cache_times = {}
    
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any):
            # Создаем ключ кэша
            key: str = str(args) + str(sorted(kwargs.items()))
            current_time: float = time.time()
            
            # Проверяем, есть ли результат в кэше и не истек ли срок действия
            cached_result: Any = cache.get(key)
            if cached_result and key in cache_times and current_time - cache_times[key] < ttl:
                return cached_result
            
            # Выполняем функцию и сохраняем результат
            result = func(*args, **kwargs)
            
            # Сохраняем результат в кэш
            cache.put(key, result)
            cache_times[key] = current_time
            
            # Очищаем старые записи времени
            current_keys: set[str] = set(cache_times.keys())  # type: ignore
            cache_keys: set[str] = set(cache.keys())  # type: ignore
            for old_key in current_keys - cache_keys:
                del cache_times[old_key]
            
            return result
        return wrapper
    return decorator

def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Декоратор для повторных попыток выполнения функции"""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception: Optional[Exception] = None
            current_delay: float = delay
            
            for attempt in range(max_attempts):
                attempt: int
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    e: Exception
                    last_exception = e
                    if attempt < max_attempts - 1:
                        time.sleep(current_delay)
                        current_delay *= backoff
            
            if last_exception is not None:
                raise last_exception
            else:
                raise RuntimeError("Retry failed but no exception was captured")
        return wrapper
    return decorator

class ResourceManager:
    """Менеджер ресурсов для автоматической очистки"""
    
    def __init__(self):
        self.resources: Dict[str, Any] = {}
        self.cleanup_funcs: Dict[str, Callable[[Any], Any]] = {}
        self.lock: threading.RLock = threading.RLock()
    
    def register_resource(self, name: str, resource: Any, cleanup_func: Optional[Callable[[Any], Any]] = None) -> None:
        """Регистрирует ресурс с функцией очистки"""
        with self.lock:
            self.resources[name] = resource
            if cleanup_func:
                self.cleanup_funcs[name] = cleanup_func
    
    def get_resource(self, name: str) -> Optional[Any]:
        """Получает ресурс по имени"""
        with self.lock:
            return self.resources.get(name)
    
    def cleanup_resource(self, name: str) -> bool:
        """Очищает конкретный ресурс"""
        with self.lock:
            if name in self.resources:
                resource: object = self.resources[name]
                cleanup_func = self.cleanup_funcs.get(name)
                
                if cleanup_func:
                    try:
                        cleanup_func(resource)
                    except Exception as e:
                        logger.error(f"Error cleaning up resource {name}: {e}")
                
                del self.resources[name]
                if name in self.cleanup_funcs:
                    del self.cleanup_funcs[name]
                
                return True
            return False
    
    def cleanup_all(self) -> None:
        """Очищает все ресурсы"""
        with self.lock:
            for name in list(self.resources.keys()):
                self.cleanup_resource(name)
    
    @staticmethod
    def get_memory_usage() -> Dict[str, Any]:
        """Получает информацию об использовании памяти"""
        try:
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            return {
                'rss_mb': memory_info.rss / 1024 / 1024,
                'vms_mb': memory_info.vms / 1024 / 1024,
                'percent': process.memory_percent(),
                'cpu_percent': process.cpu_percent()
            }
        except Exception as e:
            log_and_notify('error', f"Error getting memory usage: {e}")
            return {'rss_mb': 0, 'vms_mb': 0, 'percent': 0, 'cpu_percent': 0}

# Глобальный менеджер ресурсов
resource_manager = ResourceManager()

def optimize_memory_usage() -> Dict[str, Any]:
    """Оптимизирует использование памяти"""
    try:
        # Принудительный сбор мусора
        collected = gc.collect()
        
        # Получаем статистику памяти
        memory_stats = resource_manager.get_memory_usage()
        
        logger.info(f"Memory optimization completed. Collected {collected} objects")
        return {
            'objects_collected': collected,
            'memory_stats': memory_stats
        }
    except Exception as e:
        log_and_notify('error', f"Error optimizing memory usage: {e}")
        return {'objects_collected': 0, 'memory_stats': {}}

def monitor_performance(func: Callable[..., Any]) -> Callable[..., Any]:
    """Декоратор для мониторинга производительности функции"""
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time: float = time.time()
        start_memory: Dict[str, Any] = resource_manager.get_memory_usage()
        
        try:
            result: Any = func(*args, **kwargs)
            return result
        finally:
            end_time: float = time.time()
            end_memory: Dict[str, Any] = resource_manager.get_memory_usage()
            
            duration: float = end_time - start_time
            memory_diff: float = end_memory['rss_mb'] - start_memory['rss_mb']
            
            logger.debug(f"Function {func.__name__} took {duration:.3f}s, memory change: {memory_diff:.2f}MB")
    
    return wrapper

def get_local_timestamp() -> str:
    """Получает локальную временную метку"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def extract_time_from_timestamp(timestamp_str: str) -> str:
    """Извлекает время из временной метки"""
    try:
        # Парсим временную метку
        if 'T' in timestamp_str:
            # ISO формат
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        else:
            # Простой формат
            dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        
        # Конвертируем в локальное время
        local_tz = pytz.timezone('Europe/Moscow')  # Можно сделать настраиваемым
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)
        
        local_dt = dt.astimezone(local_tz)
        return local_dt.strftime('%H:%M:%S')
        
    except Exception as e:
        log_and_notify('error', f"Error extracting time from timestamp {timestamp_str}: {e}")
        return "00:00:00"

def format_duration(seconds: float) -> str:
    """Форматирует длительность в читаемый вид"""
    if seconds < 60:
        return f"{seconds:.1f}с"
    elif seconds < 3600:
        minutes: int = int(seconds // 60)
        remaining_seconds: float = seconds % 60
        return f"{minutes}м {remaining_seconds:.1f}с"
    else:
        hours: int = int(seconds // 3600)
        remaining_minutes: int = int((seconds % 3600) // 60)
        return f"{hours}ч {remaining_minutes}м" 
