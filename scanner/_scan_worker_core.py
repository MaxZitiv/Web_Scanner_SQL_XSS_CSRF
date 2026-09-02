import asyncio
import hashlib
import time
from typing import Any, cast
from urllib.parse import urlparse

import aiohttp
from bs4.element import Tag

from utils.logger import logger
from utils.performance import get_local_timestamp
from utils.security import is_safe_url, validate_input_length
from utils.vulnerability_info import format_vulnerability_details

from ._scan_worker_protocol import _ScanWorkerProtocol
from ._scan_worker_signals import ScanWorkerSignals
from ._scanner_config import HTTP_OPTIMIZATIONS, MAX_DEPTH, ScanCompletionMetrics
from .cache_manager import cache_manager


class ScanWorkerCore(_ScanWorkerProtocol):
    """
    Асинхронный воркер для сканирования веб-сайтов на уязвимости.
    """

    def __init__(
        self: _ScanWorkerProtocol,
        url: str,
        scan_types: list[str],
        user_id: int,
        username: str | None = None,
        max_depth: int = MAX_DEPTH,
        max_concurrent: int = 5,
        timeout: int = 10,
    ):
        """
        Инициализирует ScanWorker с указанными параметрами.
        """
        # Проверяем безопасность входных параметров
        if not is_safe_url(url):
            raise ValueError(f"Небезопасный URL: {url}")

        if not validate_input_length(url, 1, 2048):
            raise ValueError(f"URL имеет недопустимую длину: {len(url)}")

        if not scan_types:
            raise ValueError("Типы сканирования должны быть непустым списком")

        if user_id <= 0:
            raise ValueError("ID пользователя должен быть положительным числом")

        if username and not validate_input_length(username, 1, 50):
            raise ValueError("Имя пользователя имеет недопустимую длину")

        if max_depth < 1 or max_depth > 10:
            raise ValueError("Глубина сканирования должна быть в диапазоне от 1 до 10")

        if max_concurrent < 1 or max_concurrent > 20:
            raise ValueError("Количество одновременных запросов должно быть в диапазоне от 1 до 20")

        if timeout < 5 or timeout > 120:
            raise ValueError("Таймаут должен быть в диапазоне от 5 до 120 секунд")

        # Режимы и флаги сканирования
        self._max_coverage_mode = False
        self._should_stop = False

        # Очереди и множества для управления сканированием
        self.to_visit: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self.visited: set[str] = set()
        self.in_progress: set[str] = set()

        # Счетчики и статистика
        self.total_scanned_count: int = 0
        self.total_forms_count: int = 0
        self.total_vuln_count: int = 0
        self.scanned_forms_count: int = 0
        self.current_form_index: int = 0
        self.total_links_count: int = 0

        # Флаги состояния сканирования
        self.max_depth_reached: bool = False
        self.scan_complete: bool = False
        self.scan_started: bool = False
        self.reported_progress: int = 0

        # Параметры сканирования
        self.url = url
        self.scan_types = scan_types
        self.user_id = user_id
        self.username = username
        self.max_depth = max_depth
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self._is_paused = False

        # Основные параметры
        self.base_url = url
        self.current_url = ""

        # Кэши и хранилища
        self.visited_urls: set[str] = set()
        self.scanned_urls: set[str] = set()
        self.unscanned_urls: set[str] = set()
        self.all_scanned_urls: set[str] = set()
        self.all_found_forms: list[dict[str, Any]] = []
        self.scanned_form_hashes: set[str] = set()
        self.html_cache: dict[str, str] = {}
        self.dns_cache: dict[str, str] = {}
        self.form_cache: dict[str, Any] = {}
        self.url_cache: set[str] = set()

        # Результаты и статистика
        self.vulnerabilities: dict[str, list[dict[str, Any]]] = {"sql": [], "xss": [], "csrf": []}
        self.scan_start_time = None
        self.scan_end_time = None
        self.current_depth = 0
        self.operation_count = 0
        self.memory_check_interval = 1000

        self.scan_completion_metrics: ScanCompletionMetrics = {
            "errors_encountered": 0,
            "urls_scanned": 0,
            "vulnerabilities_found": 0,
            "status": "initialized",
        }

        # Сигналы и статус
        self.signals = ScanWorkerSignals()
        self._cancelled = False
        self.session = None
        self.start_time = 0

    @property
    def max_coverage_mode(self: _ScanWorkerProtocol) -> bool:
        return self._max_coverage_mode

    @max_coverage_mode.setter
    def max_coverage_mode(self: _ScanWorkerProtocol, value: bool) -> None:
        self._max_coverage_mode = value

    @property
    def should_stop(self: _ScanWorkerProtocol) -> bool:
        return self._should_stop

    @should_stop.setter
    def should_stop(self: _ScanWorkerProtocol, value: bool) -> None:
        self._should_stop = value

    async def _scan_sql_injection(self: _ScanWorkerProtocol, url: str) -> None:
        """Сканирование на SQL-инъекции."""
        try:
            await asyncio.sleep(0.1)  # Имитация работы

            if any(keyword in url.lower() for keyword in ["login", "search", "id=", "user="]):
                parameter = ", ".join(self._query_parameter_names(url)) or "параметры URL"
                vulnerability = {
                    "type": "sql",
                    "url": url,
                    "severity": "high",
                    "parameter": parameter,
                    "method": "GET",
                    "field": "query-parameter",
                    "location": f"параметры запроса: {parameter}",
                    "description": format_vulnerability_details(
                        url=url,
                        parameter=parameter,
                        method="GET",
                        field="query-parameter",
                        note="Возможная SQL-инъекция в параметрах запроса",
                    ),
                }

                self.vulnerabilities["sql"].append(vulnerability)
                self.scan_completion_metrics["vulnerabilities_found"] += 1
                self.signals.vulnerability_found.emit(url, "sql", vulnerability["description"])

        except Exception as e:
            logger.error(f"Error during SQL injection scan: {e}")
            self.scan_completion_metrics["errors_encountered"] += 1

    async def _scan_xss(self: _ScanWorkerProtocol, url: str) -> None:
        """Сканирование на XSS-уязвимости."""
        try:
            await asyncio.sleep(0.1)  # Имитация работы

            if any(keyword in url.lower() for keyword in ["comment", "message", "search", "q="]):
                parameter = ", ".join(self._query_parameter_names(url)) or "параметры URL"
                vulnerability = {
                    "type": "xss",
                    "url": url,
                    "severity": "medium",
                    "parameter": parameter,
                    "method": "GET",
                    "field": "query-parameter",
                    "location": f"параметры запроса: {parameter}",
                    "description": format_vulnerability_details(
                        url=url,
                        parameter=parameter,
                        method="GET",
                        field="query-parameter",
                        note="Потенциальная XSS-уязвимость в форме или параметрах",
                    ),
                }

                self.vulnerabilities["xss"].append(vulnerability)
                self.scan_completion_metrics["vulnerabilities_found"] += 1
                self.signals.vulnerability_found.emit(url, "xss", vulnerability["description"])

        except Exception as e:
            logger.error(f"Error during XSS scan: {e}")
            self.scan_completion_metrics["errors_encountered"] += 1

    async def _scan_csrf(self: _ScanWorkerProtocol, url: str) -> None:
        """Сканирование на CSRF-уязвимости."""
        try:
            await asyncio.sleep(0.1)  # Имитация работы

            if any(keyword in url.lower() for keyword in ["form", "submit", "transfer", "delete"]):
                vulnerability = {
                    "type": "csrf",
                    "url": url,
                    "severity": "medium",
                    "parameter": "CSRF-токен",
                    "method": "POST",
                    "field": "скрытые поля формы",
                    "location": f"форма на {url}",
                    "description": format_vulnerability_details(
                        url=url,
                        parameter="CSRF-токен",
                        method="POST",
                        field="скрытые поля формы",
                        location=f"форма на {url}",
                        note="Отсутствует CSRF-токен в форме",
                    ),
                }

                self.vulnerabilities["csrf"].append(vulnerability)
                self.scan_completion_metrics["vulnerabilities_found"] += 1
                self.signals.vulnerability_found.emit(url, "csrf", vulnerability["description"])

        except Exception as e:
            logger.error(f"Error during CSRF scan: {e}")
            self.scan_completion_metrics["errors_encountered"] += 1

    async def run_scan(self: _ScanWorkerProtocol) -> dict[str, Any]:
        """
        Выполнение полного сканирования и возврат результата.

        Делегирует основную работу методу ``scan()`` и приводит результат
        к формату, ожидаемому ScanController/UI.
        """
        try:
            raw_result = await self.scan()

            vulnerabilities: dict[str, list[dict[str, Any]]] = {"sql": [], "xss": [], "csrf": []}
            raw_vulnerabilities = raw_result.get("vulnerabilities")
            if isinstance(raw_vulnerabilities, dict):
                parsed_vulnerabilities = cast(dict[str, list[dict[str, Any]]], raw_vulnerabilities)
                vulnerabilities.update(parsed_vulnerabilities)

            total_vulnerabilities = sum(len(items) for items in vulnerabilities.values())
            total_urls_scanned = int(raw_result.get("total_urls_scanned", len(self.all_scanned_urls)))
            total_forms_scanned = int(raw_result.get("total_forms_scanned", self.scanned_forms_count))
            scan_duration = float(raw_result.get("duration", 0.0))
            unscanned_urls = list(raw_result.get("unscanned_urls", self.unscanned_urls))
            total_urls_discovered = int(raw_result.get("total_urls_discovered", self.total_links_count))
            coverage_percent = 0.0
            if total_urls_discovered > 0:
                coverage_percent = round((total_urls_scanned / total_urls_discovered) * 100.0, 2)

            return {
                "url": raw_result.get("url", self.base_url),
                "scan_types": raw_result.get("scan_types", self.scan_types),
                "start_time": raw_result.get("timestamp", get_local_timestamp()),
                "end_time": get_local_timestamp(),
                "duration": scan_duration,
                "results": vulnerabilities,
                "vulnerabilities": vulnerabilities,
                "scan_duration": scan_duration,
                "total_vulnerabilities": total_vulnerabilities,
                "total_urls_scanned": total_urls_scanned,
                "total_forms_scanned": total_forms_scanned,
                "total_urls_discovered": total_urls_discovered,
                "coverage_percent": coverage_percent,
                "unscanned_urls": unscanned_urls,
                "status": raw_result.get("status", "completed"),
                "error": raw_result.get("error"),
            }

        except Exception as e:
            logger.error(f"Error during scan: {e}", exc_info=True)
            raise

    def _cleanup_caches(self: _ScanWorkerProtocol):
        """Очистка кэшей для управления памятью."""
        self.html_cache.clear()
        self.dns_cache.clear()
        self.form_cache.clear()
        if hasattr(self, "url_cache"):
            self.url_cache.clear()
        self.operation_count = 0
        logger.debug("Caches cleaned up")

    def update_stats(self: _ScanWorkerProtocol):
        """Обновляет статистику сканирования."""
        try:
            # Получаем текущие значения
            urls_found = self.total_links_count
            urls_scanned = len(self.all_scanned_urls)
            forms_found = len(self.all_found_forms)
            forms_scanned = self.scanned_forms_count

            # Подсчитываем уязвимости
            total_vulns = (
                len(self.vulnerabilities.get("sql", []))
                + len(self.vulnerabilities.get("xss", []))
                + len(self.vulnerabilities.get("csrf", []))
            )

            self.signals.stats_updated.emit("urls_found", urls_found)
            self.signals.stats_updated.emit("urls_scanned", urls_scanned)
            self.signals.stats_updated.emit("forms_found", forms_found)
            self.signals.stats_updated.emit("forms_scanned", forms_scanned)
            self.signals.stats_updated.emit("vulnerabilities", total_vulns)

            # Обновляем прогресс. Прогресс монотонный: после финального 100%
            # update_stats() не должен перезаписывать его рассчитанным значением,
            # которое может быть маленьким из-за найденных, но несканированных ссылок.
            progress = max(self.calculate_progress(), self.reported_progress)
            if progress < self.reported_progress:
                progress = self.reported_progress
            else:
                self.reported_progress = progress
            self.signals.progress_updated.emit(progress)

            # Подсчитываем ошибки
            errors = self.scan_completion_metrics.get("errors_encountered", 0)

            # Статистика для отправки
            stats_data = {
                "urls_found": urls_found,
                "urls_scanned": urls_scanned,
                "forms_found": forms_found,
                "forms_scanned": forms_scanned,
                "vulnerabilities": total_vulns,
                "requests_sent": self.total_scanned_count,
                "errors": errors,
            }

            # Отправляем каждый счетчик
            for key, value in stats_data.items():
                try:
                    self.signals.stats_updated.emit(key, value)
                except Exception as signal_error:
                    logger.debug(f"Error emitting stat {key}: {signal_error}")

            # Время сканирования
            try:
                elapsed = 0
                current_time = time.time()

                if hasattr(self, "start_time") and self.start_time:
                    elapsed = int(current_time - self.start_time)
                elif self.scan_start_time:
                    elapsed = int(current_time - self.scan_start_time.timestamp())

                # Форматируем время
                hours = elapsed // 3600
                minutes = (elapsed % 3600) // 60
                seconds = elapsed % 60
                time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

                self.signals.stats_updated.emit("scan_time", time_str)

            except Exception as time_error:
                logger.debug(f"Error calculating scan time: {time_error}")
                self.signals.stats_updated.emit("scan_time", "00:00:00")

        except Exception as e:
            logger.error(f"Error in update_stats: {e}")

    def _manage_memory_usage(self: _ScanWorkerProtocol):
        """Управляет использованием памяти через контроль кэшей."""
        try:
            import psutil

            memory_percent = psutil.virtual_memory().percent

            if memory_percent > 80:
                # Очищаем кэши
                cache_dicts: list[dict[str, Any]] = [self.html_cache, self.dns_cache, self.form_cache]
                for cache_dict in cache_dicts:
                    cache_dict.clear()

                cache_sets = [self.url_cache]
                for cache_set in cache_sets:
                    cache_set.clear()

                logger.warning(f"Memory usage {memory_percent}% > 80%. Cache sizes reduced and cleared.")
        except ImportError:
            pass  # psutil не установлен
        except Exception as e:
            logger.debug(f"Error managing memory: {e}")

    def _check_memory_periodically(self: _ScanWorkerProtocol):
        """Периодически проверяет использование памяти."""
        self.operation_count += 1
        if self.operation_count >= self.memory_check_interval:
            self._manage_memory_usage()
            self.operation_count = 0

    async def scan_url(self: _ScanWorkerProtocol, url: str) -> str | None:
        """Сканирует указанный URL."""
        self._check_memory_periodically()

        # Проверка кэша
        cache_key = f"scan_url{url}"
        cached_result = cache_manager.URL_PROCESSING_CACHE.get(cache_key)
        if cached_result is not None:
            logger.debug(f"Cache hit for {url}")
            return cached_result

        # Обработка URL
        result = await self._process_url(url)

        # Сохранение в кэш
        if result is not None:
            self.html_cache[url] = result

        self.update_stats()
        return result

    async def _process_url(self: _ScanWorkerProtocol, url: str) -> str | None:
        """Обрабатывает URL и возвращает результат."""
        if self.should_stop or self._is_paused:
            return None

        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session, session.get(url) as response:
                return await response.text()
        except Exception as e:
            logger.error(f"Error processing URL {url}: {e}")
            return None

    def stop(self: _ScanWorkerProtocol):
        """Останавливает сканирование."""
        self.should_stop = True
        logger.info(f"Stop signal sent for scan of {self.base_url}")

    def pause(self: _ScanWorkerProtocol):
        """Приостанавливает сканирование."""
        self._is_paused = True
        logger.info(f"Pause signal sent for scan of {self.base_url}")

    def resume(self: _ScanWorkerProtocol):
        """Возобновляет сканирование."""
        self._is_paused = False
        logger.info(f"Resume signal sent for scan of {self.base_url}")

    def is_paused(self: _ScanWorkerProtocol):
        """Проверяет, находится ли сканирование на паузе."""
        return self._is_paused

    def calculate_progress(self: _ScanWorkerProtocol) -> int:
        """Вычисляет прогресс сканирования (0..100)."""
        try:
            total = self.total_links_count
            processed = len(self.all_scanned_urls)
            if total <= 0:
                return 0
            return max(0, min(100, int((processed / total) * 100)))
        except Exception as e:
            logger.error(f"Error calculating progress: {e}")
            return 0

    def update_progress(
        self: _ScanWorkerProtocol,
        current_url: str = "",
        current_depth: int | None = None,
        queue_size: int | None = None,
    ):
        """Обновляет прогресс сканирования (монотонно, без отката)."""
        try:
            if queue_size is None:
                queue_size = self.to_visit.qsize() if self.to_visit else 0

            progress = self.calculate_progress()
            # Прогресс не должен уменьшаться при обнаружении новых URL.
            if progress < self.reported_progress:
                progress = self.reported_progress
            else:
                self.reported_progress = progress

            # Отправляем сигналы о прогрессе
            self.signals.progress.emit(progress, current_url)
            self.signals.progress_updated.emit(progress)

            # Глубина — внутренний предохранитель, в интерфейсе она не показывается.
            if current_depth is not None and current_depth >= self.max_depth:
                self.max_depth_reached = True

            # Формируем информацию о прогрессе
            url_info = f"{len(self.all_scanned_urls)}/{self.total_links_count}"
            form_info = f"{self.scanned_forms_count}/{len(self.all_found_forms)}"

            progress_info = f"Progress: {progress}% | URL: {url_info} | Forms: {form_info}"

            if current_url:
                progress_info += f" | Processed URL: {current_url}"

            self.signals.log_event.emit(progress_info)
            self.update_stats()

        except Exception as e:
            logger.error(f"Error in update_progress: {e}")

    @staticmethod
    def get_form_hash(form_tag: Tag) -> str:
        """Создает уникальный хэш для тега формы."""
        try:
            action = str(form_tag.get("action", "")).strip()
            method = str(form_tag.get("method", "get")).lower().strip()

            inputs: list[str] = []
            for element in form_tag.find_all(["input", "textarea", "select", "button"]):
                inp_name = str(element.get("name", ""))
                inp_type = str(element.get("type", "text"))
                if inp_name:
                    inputs.append(f"{element.name}-{inp_type}-{inp_name}")

            inputs.sort()
            form_representation = f"action:{action}|method:{method}|inputs:{','.join(inputs)}"
            return hashlib.sha256(form_representation.encode("utf-8")).hexdigest()

        except Exception as e:
            logger.error(f"Error creating form hash: {e}")
            return hashlib.sha256(str(time.time()).encode()).hexdigest()

    @staticmethod
    def is_same_domain(url: str, base_domain: str) -> bool:
        """Проверяет, принадлежит ли URL данному домену."""
        try:
            if not url or not base_domain:
                return False

            parsed = urlparse(url)
            url_domain = parsed.netloc.lower().split(":")[0]
            base_domain = base_domain.lower().split(":")[0]

            return url_domain == base_domain or url_domain.endswith("." + base_domain)

        except Exception as e:
            logger.error(f"Error checking domain {url} against {base_domain}: {e}")
            return False

    def _client_timeout(self: _ScanWorkerProtocol) -> aiohttp.ClientTimeout:
        """Создаёт таймаут из параметра ScanWorker.timeout (мин. 5 сек)."""
        total = max(5, int(self.timeout))
        connect = max(5, min(10, total))
        return aiohttp.ClientTimeout(total=total, connect=connect, sock_connect=connect, sock_read=total)

    async def smart_request(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        retries: int = 2,
        **kwargs: Any,
    ) -> tuple[aiohttp.ClientResponse, str] | None:
        """Умный HTTP запрос с обработкой ошибок."""
        if self.should_stop or self._is_paused:
            return None

        if not session or not url:
            return None

        # Проверяем кэш
        cache_key = f"{method}:{url}:{hash(str(kwargs))}"
        cached_result = cache_manager.URL_PROCESSING_CACHE.get(cache_key)
        if cached_result is not None:
            return cached_result

        max_attempts = 3 if self.max_coverage_mode else retries

        for attempt in range(max_attempts):
            if self.should_stop:
                return None

            try:
                timeout = self._client_timeout()
                headers = {**HTTP_OPTIMIZATIONS["headers"], **kwargs.get("headers", {})}

                async with session.request(method, url, timeout=timeout, headers=headers, **kwargs) as response:
                    # Проверяем Content-Type
                    content_type = response.headers.get("Content-Type", "").lower()

                    if not any(t in content_type for t in ["html", "text", "json", "xml", "javascript"]):
                        await response.read()
                        result = (response, "")
                    else:
                        try:
                            response_text = await response.text()
                        except UnicodeDecodeError:
                            response_text = await response.text(errors="replace")

                        result = (response, response_text)

                    cache_manager.URL_PROCESSING_CACHE.set(cache_key, result)
                    return result

            except Exception as e:
                logger.warning(f"Request attempt {attempt + 1} failed for {url}: {e}")
                if attempt < max_attempts - 1:
                    await asyncio.sleep(1)

        self.unscanned_urls.add(url)
        return None
