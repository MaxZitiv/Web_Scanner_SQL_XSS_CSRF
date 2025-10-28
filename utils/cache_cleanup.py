"""
Модуль для централизованной очистки кэшей приложения.
Обеспечивает безопасную очистку всех кэшей при выходе из программы.
"""

import gc
import time
from typing import Dict, Any, Union, cast
from utils.logger import logger, log_and_notify
from utils.performance import performance_monitor, resource_manager
from utils.security import clear_security_cache

from utils.error_handler import error_handler

# Заглушка для типа error_handler
class ErrorHandlerStub:
    def get_error_statistics(self) -> Dict[str, Any]:
        return {}
    def clear_error_cache(self) -> None:
        pass

# Явное приведение типа для error_handler
typed_error_handler: ErrorHandlerStub = cast(ErrorHandlerStub, error_handler)


class CacheCleanupManager:
    """Менеджер для очистки всех кэшей приложения"""
    
    def __init__(self):
        self.cleanup_stats: Dict[str, Dict[str, Union[bool, int]]] = {
            'security_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'performance_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'user_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'error_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'scanner_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'memory_cleanup': {'performed': False, 'memory_before': 0, 'memory_after': 0}
        }
        self.cleanup_start_time: Union[float, None] = None
        self.cleanup_end_time: Union[float, None] = None
    
    def get_cache_sizes(self) -> Dict[str, int]:
        """Получает размеры всех кэшей"""
        sizes: Dict[str, int] = {}
        
        try:
            # Размер кэша безопасности
            from utils.security import get_security_cache_stats
            security_cache_size, _ = get_security_cache_stats()
            sizes['security_cache'] = security_cache_size
        except Exception as e:
            logger.warning(f"Error getting security cache size: {e}")
            sizes['security_cache'] = 0
        
        try:
            # Размер кэша производительности
            sizes['performance_cache'] = performance_monitor.cache.size()
        except Exception as e:
            logger.warning(f"Error getting performance cache size: {e}")
            sizes['performance_cache'] = 0
        
        try:
            # Размер кэша пользователей
            from models.user_model import UserModel
            user_model: UserModel = UserModel()
            user_stats: Dict[str, Any] = user_model.get_user_cache_stats()
            sizes['user_cache'] = user_stats.get('cache_size', 0)
        except Exception as e:
            logger.warning(f"Error getting user cache size: {e}")
            sizes['user_cache'] = 0
        
        try:
            # Размер кэша ошибок
            error_stats: Dict[str, Any] = typed_error_handler.get_error_statistics()
            sizes['error_cache'] = error_stats.get('total_errors', 0)
        except Exception as e:
            logger.warning(f"Error getting error cache size: {e}")
            sizes['error_cache'] = 0
        
        try:
            # Размер кэша сканера
            from scanner.scanner_fixed import HTML_CACHE, DNS_CACHE, FORM_HASH_CACHE, URL_PROCESSING_CACHE
            scanner_cache_size: int = len(HTML_CACHE) + len(DNS_CACHE) + len(FORM_HASH_CACHE) + len(URL_PROCESSING_CACHE)
            sizes['scanner_cache'] = scanner_cache_size
        except Exception as e:
            logger.warning(f"Error getting scanner cache size: {e}")
            sizes['scanner_cache'] = 0
        
        return sizes
    
    def get_memory_usage(self) -> Dict[str, Union[int, float]]:
        """Получает информацию об использовании памяти"""
        try:
            import psutil
            import os
            process: psutil.Process = psutil.Process(os.getpid())
            memory_info: Any = process.memory_info()
            return {
                'rss': memory_info.rss,  # Resident Set Size в байтах
                'vms': memory_info.vms,  # Virtual Memory Size в байтах
                'percent': process.memory_percent()
            }
        except Exception as e:
            logger.warning(f"Error getting memory usage: {e}")
            return {'rss': 0, 'vms': 0, 'percent': 0}
    
    def clear_security_cache(self) -> bool:
        """Очищает кэш безопасности"""
        try:
            size_before: int = self.get_cache_sizes()['security_cache']
            clear_security_cache()
            size_after: int = self.get_cache_sizes()['security_cache']
            
            self.cleanup_stats['security_cache'] = {
                'cleared': True,
                'size_before': size_before,
                'size_after': size_after
            }
            
            logger.info(f"Security cache cleared: {size_before} -> {size_after} entries")
            return True
            
        except Exception as e:
            log_and_notify('error', f"Error clearing security cache: {e}")
            self.cleanup_stats['security_cache']['cleared'] = False
            return False
    
    def clear_performance_cache(self) -> bool:
        """Очищает кэш производительности"""
        try:
            size_before: int = performance_monitor.cache.size()
            performance_monitor.clear_metrics()
            size_after: int = performance_monitor.cache.size()
            
            self.cleanup_stats['performance_cache'] = {
                'cleared': True,
                'size_before': size_before,
                'size_after': size_after
            }
            
            logger.info(f"Performance cache cleared: {size_before} -> {size_after} entries")
            return True
            
        except Exception as e:
            log_and_notify('error', f"Error clearing performance cache: {e}")
            self.cleanup_stats['performance_cache']['cleared'] = False
            return False
    
    def clear_user_cache(self) -> bool:
        """Очищает кэш пользователей"""
        try:
            from models.user_model import UserModel
            user_model: UserModel = UserModel()
            size_before: int = user_model.get_user_cache_stats()['cache_size']
            user_model.clear_user_cache()
            size_after: int = user_model.get_user_cache_stats()['cache_size']
            
            self.cleanup_stats['user_cache'] = {
                'cleared': True,
                'size_before': size_before,
                'size_after': size_after
            }
            
            logger.info(f"User cache cleared: {size_before} -> {size_after} entries")
            return True
            
        except Exception as e:
            log_and_notify('error', f"Error clearing user cache: {e}")
            self.cleanup_stats['user_cache']['cleared'] = False
            return False
    
    def clear_error_cache(self) -> bool:
        """Очищает кэш ошибок"""
        try:
            size_before: int = typed_error_handler.get_error_statistics()['total_errors']
            typed_error_handler.clear_error_cache()
            size_after: int = typed_error_handler.get_error_statistics()['total_errors']
            
            self.cleanup_stats['error_cache'] = {
                'cleared': True,
                'size_before': size_before,
                'size_after': size_after
            }
            
            logger.info(f"Error cache cleared: {size_before} -> {size_after} entries")
            return True
            
        except Exception as e:
            log_and_notify('error', f"Error clearing error cache: {e}")
            self.cleanup_stats['error_cache']['cleared'] = False
            return False
    
    def clear_scanner_cache(self) -> bool:
        """Очищает кэши сканера"""
        try:
            from scanner.scanner_fixed import HTML_CACHE, DNS_CACHE, FORM_HASH_CACHE, URL_PROCESSING_CACHE
            
            size_before: int = len(HTML_CACHE) + len(DNS_CACHE) + len(FORM_HASH_CACHE) + len(URL_PROCESSING_CACHE)
            
            HTML_CACHE.clear()
            DNS_CACHE.clear()
            FORM_HASH_CACHE.clear()
            URL_PROCESSING_CACHE.clear()
            
            size_after: int = len(HTML_CACHE) + len(DNS_CACHE) + len(FORM_HASH_CACHE) + len(URL_PROCESSING_CACHE)
            
            self.cleanup_stats['scanner_cache'] = {
                'cleared': True,
                'size_before': size_before,
                'size_after': size_after
            }
            
            logger.info(f"Scanner cache cleared: {size_before} -> {size_after} entries")
            return True
            
        except Exception as e:
            log_and_notify('error', f"Error clearing scanner cache: {e}")
            self.cleanup_stats['scanner_cache']['cleared'] = False
            return False
    
    def perform_memory_cleanup(self) -> bool:
        """Выполняет очистку памяти"""
        try:
            memory_before: Dict[str, Union[int, float]] = self.get_memory_usage()
            
            # Принудительный сбор мусора
            collected: int = gc.collect()
            
            # Очистка ресурсов
            resource_manager.cleanup_all()
            
            memory_after: Dict[str, Union[int, float]] = self.get_memory_usage()
            
            self.cleanup_stats['memory_cleanup'] = {
                'performed': True,
                'memory_before': int(memory_before['rss']),
                'memory_after': int(memory_after['rss']),
                'objects_collected': collected
            }
            
            memory_freed_mb: float = (memory_before['rss'] - memory_after['rss']) / 1024 / 1024
            logger.info(f"Memory cleanup completed: {memory_freed_mb:.2f}MB freed, {collected} objects collected")
            return True
            
        except Exception as e:
            log_and_notify('error', f"Error performing memory cleanup: {e}")
            self.cleanup_stats['memory_cleanup']['performed'] = False
            return False
    
    def cleanup_all_caches(self, safe_mode: bool = True) -> Dict[str, Any]:
        """Очищает все кэши приложения"""
        self.cleanup_start_time = time.time()
        
        try:
            logger.info("Starting comprehensive cache cleanup...")
            
            # Получаем размеры кэшей до очистки
            initial_sizes: Dict[str, int] = self.get_cache_sizes()
            initial_memory: Dict[str, Union[int, float]] = self.get_memory_usage()
            
            # Очищаем все кэши
            cache_results: Dict[str, bool] = {
                'security': self.clear_security_cache(),
                'performance': self.clear_performance_cache(),
                'user': self.clear_user_cache(),
                'error': self.clear_error_cache(),
                'scanner': self.clear_scanner_cache()
            }
            
            # Выполняем очистку памяти
            memory_result: bool = self.perform_memory_cleanup()
            
            # Вычисляем статистику
            total_entries_freed: int = sum(
                initial_sizes.get(cache_name, 0) - self.get_cache_sizes().get(cache_name, 0)
                for cache_name in ['security_cache', 'performance_cache', 'user_cache', 'error_cache', 'scanner_cache']
            )
            
            memory_freed_mb: float = (initial_memory['rss'] - self.get_memory_usage()['rss']) / 1024 / 1024
            
            self.cleanup_end_time = time.time()
            duration: float = self.cleanup_end_time - self.cleanup_start_time
            
            result: Dict[str, Any] = {
                'all_successful': all(cache_results.values()) and memory_result,
                'duration_seconds': duration,
                'entries_freed': total_entries_freed,
                'memory_freed_mb': memory_freed_mb,
                'cache_results': cache_results,
                'memory_result': memory_result,
                'cleanup_stats': self.cleanup_stats
            }
            
            logger.info(f"Cache cleanup completed in {duration:.3f}s: {total_entries_freed} entries, {memory_freed_mb:.2f}MB memory")
            return result
            
        except Exception as e:
            log_and_notify('error', f"Error during cache cleanup: {e}")
            self.cleanup_end_time = time.time()
            duration: float = self.cleanup_end_time - self.cleanup_start_time
            
            return {
                'all_successful': False,
                'duration_seconds': duration,
                'entries_freed': 0,
                'memory_freed_mb': 0,
                'error': str(e),
                'cleanup_stats': self.cleanup_stats
            }

# Глобальный экземпляр менеджера очистки
cleanup_manager: CacheCleanupManager = CacheCleanupManager()

def cleanup_on_exit(safe_mode: bool = True) -> Dict[str, Any]:
    """
    Функция для очистки кэшей при выходе из приложения
    
    Args:
        safe_mode: Если True, выполняет безопасную очистку без принудительного сбора мусора
    
    Returns:
        Dict с результатами очистки
    """
    try:
        logger.info("Starting cache cleanup on exit...")
        
        if safe_mode:
            # Безопасная очистка - только кэши, без принудительного сбора мусора
            result = cleanup_manager.cleanup_all_caches(safe_mode=True)
        else:
            # Полная очистка - включая принудительный сбор мусора
            result = cleanup_manager.cleanup_all_caches(safe_mode=False)
        
        logger.info("Cache cleanup on exit completed")
        return result
        
    except Exception as e:
        log_and_notify('error', f"Error during cache cleanup on exit: {e}")
        return {
            'all_successful': False,
            'duration_seconds': 0,
            'entries_freed': 0,
            'memory_freed_mb': 0,
            'error': str(e)
        }