"""
Модуль для централизованной очистки кэшей приложения.
Обеспечивает безопасную очистку всех кэшей при выходе из программы.
"""

import gc
import time
from typing import Dict, List, Optional, Any, Union
from utils.logger import logger, log_and_notify
from utils.performance import performance_monitor, resource_manager
from utils.security import clear_security_cache
from models.user_model import UserModel
from utils.error_handler import error_handler


class CacheCleanupManager:
    """Менеджер для очистки всех кэшей приложения"""
    
    def __init__(self):
        self.cleanup_stats = {
            'security_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'performance_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'user_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'error_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'scanner_cache': {'cleared': False, 'size_before': 0, 'size_after': 0},
            'memory_cleanup': {'performed': False, 'memory_before': 0, 'memory_after': 0}
        }
        self.cleanup_start_time = None
        self.cleanup_end_time = None
    
    def get_cache_sizes(self) -> Dict[str, int]:
        """Получает размеры всех кэшей"""
        sizes = {}
        
        try:
            # Размер кэша безопасности
            from utils.security import get_security_cache_stats
            security_stats = get_security_cache_stats()
            sizes['security_cache'] = security_stats.get('cache_size', 0)
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
            user_model = UserModel()
            user_stats = user_model.get_user_cache_stats()
            sizes['user_cache'] = user_stats.get('cache_size', 0)
        except Exception as e:
            logger.warning(f"Error getting user cache size: {e}")
            sizes['user_cache'] = 0
        
        try:
            # Размер кэша ошибок
            error_stats = error_handler.get_error_statistics()
            sizes['error_cache'] = error_stats.get('total_errors', 0)
        except Exception as e:
            logger.warning(f"Error getting error cache size: {e}")
            sizes['error_cache'] = 0
        
        try:
            # Размер кэша сканера
            from scanner.scanner_fixed import HTML_CACHE, DNS_CACHE, FORM_HASH_CACHE, URL_PROCESSING_CACHE
            scanner_cache_size = len(HTML_CACHE) + len(DNS_CACHE) + len(FORM_HASH_CACHE) + len(URL_PROCESSING_CACHE)
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
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
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
            size_before = self.get_cache_sizes()['security_cache']
            clear_security_cache()
            size_after = self.get_cache_sizes()['security_cache']
            
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
            size_before = performance_monitor.cache.size()
            performance_monitor.clear_metrics()
            size_after = performance_monitor.cache.size()
            
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
            user_model = UserModel()
            size_before = user_model.get_user_cache_stats()['cache_size']
            user_model.clear_user_cache()
            size_after = user_model.get_user_cache_stats()['cache_size']
            
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
            size_before = error_handler.get_error_statistics()['total_errors']
            error_handler.clear_error_cache()
            size_after = error_handler.get_error_statistics()['total_errors']
            
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
            
            size_before = len(HTML_CACHE) + len(DNS_CACHE) + len(FORM_HASH_CACHE) + len(URL_PROCESSING_CACHE)
            
            HTML_CACHE.clear()
            DNS_CACHE.clear()
            FORM_HASH_CACHE.clear()
            URL_PROCESSING_CACHE.clear()
            
            size_after = len(HTML_CACHE) + len(DNS_CACHE) + len(FORM_HASH_CACHE) + len(URL_PROCESSING_CACHE)
            
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
            memory_before = self.get_memory_usage()
            
            # Принудительный сбор мусора
            collected = gc.collect()
            
            # Очистка ресурсов
            resource_manager.cleanup_all()
            
            memory_after = self.get_memory_usage()
            
            self.cleanup_stats['memory_cleanup'] = {
                'performed': True,
                'memory_before': memory_before['rss'],
                'memory_after': memory_after['rss'],
                'objects_collected': collected
            }
            
            memory_freed_mb = (memory_before['rss'] - memory_after['rss']) / 1024 / 1024
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
            initial_sizes = self.get_cache_sizes()
            initial_memory = self.get_memory_usage()
            
            # Очищаем все кэши
            cache_results = {
                'security': self.clear_security_cache(),
                'performance': self.clear_performance_cache(),
                'user': self.clear_user_cache(),
                'error': self.clear_error_cache(),
                'scanner': self.clear_scanner_cache()
            }
            
            # Выполняем очистку памяти
            memory_result = self.perform_memory_cleanup()
            
            # Вычисляем статистику
            total_entries_freed = sum(
                initial_sizes.get(cache_name, 0) - self.get_cache_sizes().get(cache_name, 0)
                for cache_name in ['security_cache', 'performance_cache', 'user_cache', 'error_cache', 'scanner_cache']
            )
            
            memory_freed_mb = (initial_memory['rss'] - self.get_memory_usage()['rss']) / 1024 / 1024
            
            self.cleanup_end_time = time.time()
            duration = self.cleanup_end_time - self.cleanup_start_time
            
            result = {
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
            duration = self.cleanup_end_time - self.cleanup_start_time
            
            return {
                'all_successful': False,
                'duration_seconds': duration,
                'entries_freed': 0,
                'memory_freed_mb': 0,
                'error': str(e),
                'cleanup_stats': self.cleanup_stats
            }

# Глобальный экземпляр менеджера очистки
cleanup_manager = CacheCleanupManager()

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