from scanner.scanner_fixed import ScanWorker
from utils.logger import logger, log_and_notify
import asyncio
from typing import Callable, List, Optional, Dict, Any, Tuple, cast
from utils.performance import performance_monitor, get_local_timestamp
from utils.security import is_safe_url, validate_input_length
from utils.error_handler import error_handler

class ScanController:
    def __init__(self, url: str, scan_types: List[str], user_id: int, max_depth: int = 2,
                 max_concurrent: int = 5, timeout: int = 30, username: Optional[str] = None):
        """
        Контроллер для управления сканированием.
        :param url: URL для сканирования
        :param scan_types: Список типов сканирования
        :param user_id: ID пользователя
        :param max_depth: Максимальная глубина сканирования
        :param max_concurrent: Максимальное количество параллельных запросов
        :param timeout: Таймаут в секундах
        :param username: Имя пользователя
        """
        self.url: str = url
        self.scan_types: List[str] = scan_types
        self.user_id: int = user_id
        self.max_depth: int = max_depth
        self.max_concurrent: int = max_concurrent
        self.timeout: int = timeout
        self.username: Optional[str] = username
        self.active_scans: Dict[str, ScanWorker] = {}
        self.max_active_scans: int = max_concurrent
        logger.info(f'Initialized Async ScanController for user {self.user_id} to scan {url}')

    async def scan(self) -> Dict[str, Any]:
        """Запуск сканирования и получение результатов."""
        try:
            # Создаем и запускаем новый ScanWorker
            worker = ScanWorker(
                url=self.url,
                scan_types=self.scan_types,
                user_id=self.user_id,
                max_depth=self.max_depth,
                max_concurrent=self.max_concurrent,
                timeout=self.timeout
            )

            # Сохраняем в активных сканированиях
            scan_id = get_local_timestamp()
            self.active_scans[scan_id] = worker

            # Запускаем сканирование и ждем результатов
            results = await worker.run_scan()

            # Удаляем из активных сканирований
            del self.active_scans[scan_id]

            return results

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            raise

    def _validate_scan_parameters(self, url: str, scan_types: List[str], max_depth: int, 
                                 max_concurrent: int, timeout: int) -> Tuple[bool, str]:
        """Валидация параметров сканирования."""
        try:
            # Проверка URL
            if not url:
                return False, "URL не может быть пустым"
            
            # Проверка типов сканирования
            if not scan_types:
                return False, "Должен быть указан хотя бы один тип сканирования"
            
            # Проверка max_depth
            if max_depth < 1 or max_depth > 10:
                return False, "Глубина сканирования должна быть от 1 до 10"
            
            # Проверка max_concurrent
            if max_concurrent < 1 or max_concurrent > 20:
                return False, "Количество параллельных запросов должно быть от 1 до 20"
            
            # Проверка timeout
            if timeout < 5 or timeout > 300:
                return False, "Таймаут должен быть от 5 до 300 секунд"
            
            # Проверка количества активных сканирований
            if len(self.active_scans) >= self.max_active_scans:
                return False, f"Достигнут лимит активных сканирований ({self.max_active_scans})"
            
            return True, ""
            
        except Exception as e:
            log_and_notify('error', f"Error validating scan parameters: {e}")
            return False, "Ошибка валидации параметров"

    def _cleanup_completed_scans(self) -> None:
        """Очищает завершенные сканирования из активных."""
        try:
            completed_urls: List[str] = []
            for url, worker in self.active_scans.items():
                # Проверяем наличие атрибута should_stop и его значение
                should_stop = getattr(worker, 'should_stop', None)
                if should_stop is not None and should_stop:
                    completed_urls.append(url)
            
            for url in completed_urls:
                del self.active_scans[url]
                logger.debug(f"Cleaned up completed scan for {url}")
                
        except Exception as e:
            log_and_notify('error', f"Error cleaning up completed scans: {e}")

    async def start_scan(
        self,
        url: str,
        scan_types: List[str],
        max_depth: int = 3,
        max_concurrent: int = 5,
        timeout: int = 30,
        on_progress: Optional[Callable[[float], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,
        on_vulnerability: Optional[Callable[[str, int], None]] = None,
        on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
        max_coverage_mode: bool = False
    ) -> None:
        """Запускает сканирование веб-сайта"""
        try:
            # Очищаем завершенные сканирования
            self._cleanup_completed_scans()
            
            # Валидация параметров сканирования
            is_valid, error_message = self._validate_scan_parameters(url, scan_types, max_depth, max_concurrent, timeout)
            if not is_valid:
                error_handler.show_error_message("Ошибка валидации", error_message)
                return
            
            # Валидация входных данных
            if not validate_input_length(url, 1, 2048):
                error_handler.show_error_message("Ошибка валидации", "URL слишком длинный или пустой")
                return
            
            if not is_safe_url(url):
                error_handler.show_warning_message("Предупреждение безопасности", 
                    "URL может быть небезопасным. Убедитесь, что вы сканируете только свои собственные сайты.")
            
            # Начинаем мониторинг производительности
            scan_start_time = performance_monitor.start_timer()
            
            # Логируем начало сканирования
            logger.info(f"Starting scan for URL: {url} with types: {scan_types}")
            if on_log:
                on_log(f"🚀 Начинаем сканирование: {url}", "INFO")
            
            # Выполняем сканирование
            results = await self._perform_scan(url, scan_types, max_depth, max_concurrent, timeout,
                                             on_progress, on_log, on_vulnerability, max_coverage_mode)
            
            # Завершаем мониторинг производительности
            performance_monitor.end_timer("scan_operation", scan_start_time)
            
            # Формируем результат
            scan_result: Dict[str, Any] = {
                'url': url,
                'scan_types': scan_types,
                'timestamp': get_local_timestamp(),
                'results': results.get('results', {}),
                'scan_duration': results.get('scan_duration', 0),
                'total_urls_scanned': results.get('total_urls_scanned', 0),
                'total_forms_scanned': results.get('total_forms_scanned', 0),
                'total_vulnerabilities': results.get('total_vulnerabilities', 0),
                'unscanned_urls': results.get('unscanned_urls', []),
                'coverage_percent': results.get('coverage_percent', 0),
                'performance_metrics': {
                    'scan_duration': results.get('scan_duration', 0),
                    'system_info': performance_monitor.get_system_info()
                }
            }
            
            # Вызываем callback с результатом
            if on_result:
                if asyncio.iscoroutinefunction(on_result):
                    await on_result(scan_result)
                else:
                    on_result(scan_result)
            
            logger.info(f"Scan completed for URL: {url}")
            
        except Exception as e:
            error_handler.handle_network_error(e, "start_scan")
            log_and_notify('error', f"Error in start_scan: {e}")
            if on_log:
                on_log(f"❌ Ошибка сканирования: {str(e)}", "ERROR")

    async def _perform_scan(self, url: str, scan_types: List[str], max_depth: int, 
                           max_concurrent: int, timeout: int,
                           on_progress: Optional[Callable[[float], None]] = None,
                           on_log: Optional[Callable[[str, str], None]] = None,
                           on_vulnerability: Optional[Callable[[str, int], None]] = None,
                           max_coverage_mode: bool = False) -> Dict[str, Any]:
        """Выполняет основное сканирование"""
        try:
            # Преобразуем scan_types в правильный формат для нового ScanWorker
            scan_types_lower: List[str] = []
            for scan_type in scan_types:
                # scan_type всегда имеет тип str из-за аннотации List[str]
                if 'sql' in scan_type.lower():
                    scan_types_lower.append('sql')
                elif 'xss' in scan_type.lower():
                    scan_types_lower.append('xss')
                elif 'csrf' in scan_type.lower():
                    scan_types_lower.append('csrf')
            
            # Если scan_types не определены, используем все типы
            if not scan_types_lower:
                scan_types_lower = ['sql', 'xss', 'csrf']
            
            if on_log:
                on_log(f"🔍 Начинаем сканирование: {', '.join(scan_types_lower)}", "INFO")
            
            # Создаем один ScanWorker для всех типов сканирования
            worker = ScanWorker(
                url=url,
                scan_types=scan_types_lower,
                user_id=self.user_id,
                username=self.username,
                max_depth=max_depth,
                max_concurrent=max_concurrent,
                timeout=timeout
            )
            
            # Передаем флаг максимального покрытия
            worker.max_coverage_mode = max_coverage_mode
            
            # Настраиваем callbacks
            if on_progress:
                worker.signals.progress.connect(on_progress)
            if on_log:
                worker.signals.log_event.connect(on_log)
            if on_vulnerability:
                worker.signals.vulnerability_found.connect(on_vulnerability)
            
            # Добавляем в активные сканировании
            self.active_scans[url] = worker
            
            # Запускаем сканирование
            scan_results = await worker.scan()
            
            # Удаляем из активных сканирований
            if url in self.active_scans:
                del self.active_scans[url]
            
            return scan_results
            
        except Exception as e:
            log_and_notify('error', f"Error in _perform_scan: {e}")
            # Удаляем из активных сканирований в случае ошибки
            if url in self.active_scans:
                del self.active_scans[url]
            raise

    def stop_scan(self, url: Optional[str] = None) -> None:
        """Останавливает сканирование"""
        try:
            if url:
                # Останавливаем конкретное сканирование
                if url in self.active_scans:
                    worker = self.active_scans[url]
                    worker.stop()
                    logger.info(f"Stopped scan for URL: {url}")
                else:
                    logger.warning(f"Scan for URL {url} not found in active scans")
            else:
                # Останавливаем все активные сканирования
                for url, worker in self.active_scans.items():
                    worker.stop()
                    logger.info(f"Stopped scan for URL: {url}")
                
        except Exception as e:
            log_and_notify('error', f"Error stopping scan: {e}")

    def pause_scan(self, url: Optional[str] = None) -> None:
        """Приостанавливает сканирование"""
        try:
            if url:
                # Приостанавливаем конкретное сканирование
                if url in self.active_scans:
                    worker = self.active_scans[url]
                    worker.pause()
                    logger.info(f"Paused scan for URL: {url}")
                else:
                    logger.warning(f"Scan for URL {url} not found in active scans")
            else:
                # Приостанавливаем все активные сканирования
                for url, worker in self.active_scans.items():
                    worker.pause()
                    logger.info(f"Paused scan for URL: {url}")
                
        except Exception as e:
            log_and_notify('error', f"Error pausing scan: {e}")

    def resume_scan(self, url: Optional[str] = None) -> None:
        """Возобновляет сканирование"""
        try:
            if url:
                # Возобновляем конкретное сканирование
                if url in self.active_scans:
                    worker = self.active_scans[url]
                    worker.resume()
                    logger.info(f"Resumed scan for URL: {url}")
                else:
                    logger.warning(f"Scan for URL {url} not found in active scans")
            else:
                # Возобновляем все активные сканирования
                for url, worker in self.active_scans.items():
                    worker.resume()
                    logger.info(f"Resumed scan for URL: {url}")
                
        except Exception as e:
            log_and_notify('error', f"Error resuming scan: {e}")

    async def save_scan_result(self, result: Dict[str, Any]) -> None:
        """Сохраняет результат сканирования в базу данных"""
        try:
            from utils.database import db
            
            # Извлекаем данные из результата
            url = result.get('url', '')
            scan_types = result.get('scan_types', [])
            scan_duration = result.get('scan_duration', 0.0)
            
            # Преобразуем результаты в список для сохранения
            results_list: List[Dict[str, Any]] = []
            results_dict = result.get('results', {})
            
            for vuln_type, vuln_data in results_dict.items():
                if isinstance(vuln_data, list):
                    for vuln in cast(List[Dict[str, Any]], vuln_data):
                        vuln['type'] = vuln_type
                        results_list.append(vuln)
                elif isinstance(vuln_data, dict):
                    vuln_data = cast(Dict[str, Any], vuln_data)
                    vuln_data['type'] = vuln_type
                    results_list.append(vuln_data)
            
            # Определяем тип сканирования
            if len(scan_types) > 1:
                scan_type = "comprehensive"
            elif len(scan_types) == 1:
                scan_type = scan_types[0].lower().replace(" ", "_")
            else:
                scan_type = "general"
            
            # Сохраняем результат
            success = db.save_scan_async(
                user_id=self.user_id,
                url=url,
                results=results_list,
                scan_type=scan_type,
                scan_duration=scan_duration
            )
            
            if success:
                logger.info(f"Scan result saved successfully for URL: {url}")
            else:
                log_and_notify('error', f"Failed to save scan result for URL: {url}")
                
        except Exception as e:
            log_and_notify('error', f"Error saving scan result: {e}")
