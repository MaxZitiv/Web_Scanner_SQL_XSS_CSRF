import asyncio
import gc
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4.element import Tag

from utils.logger import logger
from utils.security import is_safe_url
from utils.unified_error_handler import log_and_notify

from ._scan_worker_protocol import _ScanWorkerProtocol
from ._scanner_config import is_file_url, parse_html_cached


class ScanWorkerCrawlMixin(_ScanWorkerProtocol):
    async def crawl(self: _ScanWorkerProtocol, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> None:
        """Краулинг — обход сайта, сбор всех ссылок и форм."""
        try:
            logger.info(f"Starting crawl for URL: {self.base_url}")
            self.signals.log_event.emit(f"🔍 Начинаем обход сайта: {self.base_url}")

            # Очистка кэшей и инициализация очереди
            self.visited_urls.clear()
            self.scanned_urls.clear()
            self.all_scanned_urls.clear()
            self.all_found_forms.clear()
            self.scanned_form_hashes.clear()
            self.to_visit = asyncio.Queue()
            await self.to_visit.put((self.base_url, 0))
            self.total_links_count = 1

            # Инициализируем results_by_type перед использованием
            results_by_type: dict[str, list[dict[str, Any]]] = {"sql": [], "xss": [], "csrf": []}

            # Запуск обхода с параллелизмом
            await self.crawl_and_scan_parallel(
                session,
                semaphore,
                self.base_url,
                results_by_type=results_by_type,
                visited_urls=self.visited_urls,
                scanned_urls=self.scanned_urls,
            )
            logger.info(f"Crawling completed. Total URLs found: {len(self.visited_urls)}")
            self.signals.log_event.emit(f"✅ Обход завершён. Найдено URL: {len(self.visited_urls)}")

        except Exception as e:
            log_and_notify("error", f"Error in crawl: {e}")
            self.signals.log_event.emit(f"❌ Ошибка обхода: {e!s}")
            raise

    async def crawl_and_scan_parallel(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        start_url: str,
        results_by_type: dict[str, list[dict[str, Any]]],
        visited_urls: set[str],
        scanned_urls: set[str],
    ):
        """Параллельное сканирование с обходом ссылок."""
        try:
            logger.info(f"Starting crawl_and_scan_parallel for {start_url}")
            logger.info(f"Queue size at start: {self.to_visit.qsize() if self.to_visit else 0}")

            processed_count = 0
            stats_update_interval = 5  # Обновляем статистику каждые 5 URL для производительности

            # Обрабатываем URL из очереди
            logger.info(
                f"Starting to process URLs from queue. Queue size: {self.to_visit.qsize() if self.to_visit else 0}"
            )
            while self.to_visit and not self.to_visit.empty() and not self.should_stop:
                try:
                    # Проверяем паузу перед обработкой URL
                    if self._is_paused:
                        await asyncio.sleep(0.1)
                        continue

                    url, current_depth = await self.to_visit.get()
                    processed_count += 1
                    logger.info(f"Processing URL {processed_count}: {url} at depth {current_depth}")

                    if self.should_stop:
                        logger.info("Received request to stop scanning. Finishing...")
                        break

                    if current_depth > self.max_depth:
                        logger.info(f"Reached maximum depth {self.max_depth} for {url} - SKIPPING")
                        continue

                    # Обрабатываем URL
                    await self._process_and_scan_url(
                        session,
                        semaphore,
                        url,
                        visited_urls,
                        scanned_urls,
                        set(),
                        results_by_type,
                        self.to_visit,
                        current_depth,
                    )

                    # Обновляем статистику периодически для улучшения производительности
                    if processed_count % stats_update_interval == 0:
                        self.update_stats()
                        # Отправляем сигнал для обновления структуры сайта
                        self.signals.site_structure_updated.emit(list(self.all_scanned_urls), self.all_found_forms)
                        # Выполняем сборку мусора для освобождения памяти
                        gc.collect()

                except asyncio.CancelledError:
                    logger.info("Scanning task cancelled.")
                    break
                except Exception as e:
                    log_and_notify("error", f"Error in scanning task: {e}")

            logger.info(f"Main scanning loop completed. Processed {processed_count} URLs.")
            logger.info(f"Final queue size: {self.to_visit.qsize() if self.to_visit else 0}")
            logger.info(f"Max depth reached: {self.max_depth_reached}")

            # Финальное обновление статистики
            self.update_stats()
            self.signals.site_structure_updated.emit(list(self.all_scanned_urls), self.all_found_forms)
            # Финальная сборка мусора
            gc.collect()

        except Exception as e:
            log_and_notify("error", f"Error in crawl_and_scan_parallel: {e}")

    async def _process_and_scan_url(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        url: str,
        visited_urls: set[str],
        scanned_urls: set[str],
        seen_urls: set[str],
        results_by_type: dict[str, list[dict[str, Any]]],
        to_visit: asyncio.Queue[tuple[str, int]],
        current_depth: int,
    ) -> tuple[set[str], list[Tag]]:
        """Обрабатывает и сканирует один URL."""
        links: set[str] = set()
        forms: list[Tag] = []

        if url in visited_urls or url in seen_urls:
            return set(), []

        if self._is_paused or self.should_stop:
            return set(), []

        # Добавляем URL только в seen_urls на начальном этапе
        seen_urls.add(url)
        logger.info(f"Scanning URL: {url} at depth {current_depth}")

        try:
            # Извлекаем ссылки и формы с текущей страницы
            links, forms = await self._extract_links_from_url(
                session, semaphore, url, urlparse(self.base_url).netloc, visited_urls, only_forms=False
            )

            # Добавляем URL в visited_urls сразу после извлечения
            visited_urls.add(url)

            # Добавляем новые формы в общий список
            new_forms_count = 0
            for form in forms:
                form_hash = self.get_form_hash(form)
                if form_hash not in [f.get("hash") for f in self.all_found_forms]:
                    self.all_found_forms.append({"form": form, "url": url, "hash": form_hash})
                    new_forms_count += 1

            self.total_forms_count = len(self.all_found_forms)
            logger.info(f"Added {new_forms_count} new unique forms. Total forms: {self.total_forms_count}")

            # Добавляем новые ссылки в очередь
            logger.info(f"Found {len(links)} links on {url} at current depth {current_depth}")
            new_links_added = 0
            skipped_visited = 0
            skipped_file = 0

            for link in links:
                if link in visited_urls:
                    skipped_visited += 1
                    continue
                if link in seen_urls:
                    skipped_visited += 1
                    continue
                if is_file_url(link):
                    logger.info(f"SKIP_FILE: {link}")
                    skipped_file += 1
                    continue
                # Проверяем безопасность URL перед добавлением в очередь
                if not is_safe_url(link):
                    logger.warning(f"SKIP_UNSAFE_URL: {link}")
                    continue
                new_depth = current_depth + 1
                if new_depth > self.max_depth:
                    logger.debug(f"SKIP_OUT_OF_SCOPE: {link} (depth {new_depth} > max {self.max_depth})")
                    continue
                await to_visit.put((link, new_depth))
                self.total_links_count += 1
                new_links_added += 1
                logger.info(f"ADD_LINK: {link} with depth {new_depth} (total_links_count={self.total_links_count})")
                # Не добавляем ссылку в visited_urls здесь, только в seen_urls
                seen_urls.add(link)

            logger.info(
                "Link processing summary: "
                f"total={len(links)}, added={new_links_added}, "
                f"skipped_visited={skipped_visited}, skipped_file={skipped_file}"
            )
            logger.info(
                f"Added {new_links_added} new links to queue. "
                f"Queue size after adding links: {to_visit.qsize() if to_visit else 0}"
            )

            # Сканируем текущий URL
            unique_forms = [f["form"] for f in self.all_found_forms if f.get("url") == url]
            logger.info(f"Found {len(unique_forms)} unique forms on {url}. Starting scan...")

            # Обновляем прогресс после обработки URL
            self.update_progress(url, current_depth, to_visit.qsize() if to_visit else 0)

            # Проверяем, достигли ли максимальной глубины
            if current_depth >= self.max_depth:
                self.max_depth_reached = True
                logger.info(f"Maximum depth {self.max_depth} reached at URL: {url}")

            logger.info(f"About to scan_single_url for {url} at depth {current_depth}")
            await self.scan_single_url(
                session, semaphore, url, scanned_urls, results_by_type, to_visit, current_depth, unique_forms
            )

        except aiohttp.ClientError as e:
            log_and_notify("error", f"Client error accessing {url}: {e}")
            self.unscanned_urls.add(url)
        except TimeoutError:
            logger.warning(f"Timeout accessing {url}")
            self.unscanned_urls.add(url)
        except (ValueError, TypeError, AttributeError) as e:
            log_and_notify("error", f"Data processing error for {url}: {e}")
            self.unscanned_urls.add(url)
        except Exception as e:
            log_and_notify("error", f"Unexpected error processing {url}: {e}")
            self.unscanned_urls.add(url)

        return links, forms

    async def _extract_links_from_url(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        url: str,
        base_domain: str,
        visited_urls: set[str] | None = None,
        only_forms: bool = False,
    ) -> tuple[set[str], list[Tag]]:
        """Извлекает ссылки и формы с указанного URL."""
        if visited_urls is None:
            visited_urls = set()

        found_links: set[str] = set()
        found_forms: list[Tag] = []

        try:
            if self.should_stop or self._is_paused:
                return found_links, found_forms
            if not url:
                logger.warning("Attempted to extract links from empty URL")
                return found_links, found_forms

            async with semaphore:
                result = await self.smart_request(session=session, method="GET", url=url, retries=2)

                if result is None:
                    logger.debug(f"No response received for URL: {url}")
                    return found_links, found_forms

                html_content = result[1]
                if not html_content:
                    logger.debug(f"Empty HTML content received for URL: {url}")
                    return found_links, found_forms

                try:
                    # Используем LRU-кэш для парсинга HTML
                    soup = parse_html_cached(html_content)
                except Exception as parse_error:
                    log_and_notify("error", f"Failed to parse HTML from {url}: {parse_error}")
                    return found_links, found_forms

                # Если only_forms=False, ищем ссылки
                if not only_forms:
                    try:
                        for link in soup.find_all("a", href=True):
                            href = str(link.get("href", "")).strip()
                            if not href:
                                continue

                            absolute_url = urljoin(url, href)
                            if self.is_same_domain(absolute_url, base_domain) and absolute_url not in visited_urls:
                                found_links.add(absolute_url)
                    except Exception as link_error:
                        log_and_notify("warning", f"Error processing links in {url}: {link_error}")

                # Ищем формы
                try:
                    found_forms.extend(soup.find_all("form"))
                except Exception as form_error:
                    log_and_notify("warning", f"Error extracting forms from {url}: {form_error}")

        except aiohttp.ClientError as client_error:
            log_and_notify("error", f"Network error while processing {url}: {client_error}")
        except Exception as e:
            log_and_notify("error", f"Unexpected error processing {url}: {e}")

        return found_links, found_forms

    async def scan_single_url(
        self: _ScanWorkerProtocol,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        url: str,
        scanned_urls: set[str],
        results_by_type: dict[str, list[dict[str, Any]]],
        to_visit: asyncio.Queue[tuple[str, int]],
        current_depth: int,
        forms_to_scan: list[Tag] | None = None,
    ):
        """Сканирует один URL на уязвимости."""
        precollected = forms_to_scan is not None
        if forms_to_scan is None:
            forms_to_scan = []

        if url in scanned_urls:
            logger.info(f"URL {url} already in scanned_urls, skipping")
            return
        if self._is_paused:
            logger.info(f"Scan is paused, skipping URL {url}")
            return

        logger.info(f"Starting to scan URL: {url} at depth {current_depth}")

        # Используем self.visited_urls вместо параметра
        if url in self.visited_urls:
            logger.info(f"URL {url} already in visited_urls, skipping")
            return

        # Используем семафор для ограничения параллелизма
        async with semaphore:
            # Проверяем флаги снова перед началом обработки
            if self.should_stop or self._is_paused:
                return

            scanned_urls.add(url)
            self.visited_urls.add(url)
            self.all_scanned_urls.add(url)
            self.total_scanned_count += 1

            # Обновляем статистику после добавления URL в сканированные
            self.update_stats()

            # Если ссылки/формы ещё не собраны, извлекаем их с текущей страницы.
            # Когда данные уже переданы из _process_and_scan_url, повторно не ходим.
            if not precollected and current_depth < self.max_depth:
                logger.info(f"Extracting links from {url} at depth {current_depth} (max_depth: {self.max_depth})")
                try:
                    links, forms = await self._extract_links_from_url(
                        session, semaphore, url, urlparse(self.base_url).netloc, self.visited_urls, only_forms=False
                    )

                    # Добавляем новые формы в общий список
                    new_forms_count = 0
                    for form in forms:
                        form_hash = self.get_form_hash(form)
                        if form_hash not in [f.get("hash") for f in self.all_found_forms]:
                            self.all_found_forms.append({"form": form, "url": url, "hash": form_hash})
                            new_forms_count += 1

                    self.total_forms_count = len(self.all_found_forms)
                    logger.info(f"Added {new_forms_count} new unique forms. Total forms: {self.total_forms_count}")

                    # Добавляем новые ссылки в очередь
                    logger.info(f"Found {len(links)} links on {url} at current depth {current_depth}")
                    new_links_added = 0
                    for link in links:
                        if link not in self.visited_urls:
                            if is_file_url(link):
                                logger.info(f"SKIP_FILE: {link}")
                                continue
                            # Проверяем безопасность URL перед добавлением в очередь
                            if not is_safe_url(link):
                                logger.warning(f"SKIP_UNSAFE_URL: {link}")
                                continue
                            new_depth = current_depth + 1
                            if new_depth > self.max_depth:
                                logger.debug(f"SKIP_OUT_OF_SCOPE: {link} (depth {new_depth} > max {self.max_depth})")
                                continue
                            await to_visit.put((link, new_depth))
                            self.total_links_count += 1
                            new_links_added += 1
                            logger.info(
                                f"ADD_LINK: {link} with depth {new_depth} (total_links_count={self.total_links_count})"
                            )
                    logger.info(
                        f"Added {new_links_added} new links to queue. "
                        f"Queue size after adding links: {to_visit.qsize() if to_visit else 0}"
                    )
                    # Отправляем сигнал для обновления структуры сайта
                    self.signals.site_structure_updated.emit(list(self.all_scanned_urls), self.all_found_forms)

                    # Обновляем формы для сканирования уязвимостей
                    forms_to_scan = [f["form"] for f in self.all_found_forms if f["url"] == url]
                    logger.info(f"Found {len(forms_to_scan)} unique forms on {url}. Starting scan...")

                except Exception as e:
                    log_and_notify("error", f"Error extracting links from {url}: {e}")
            else:
                logger.info(f"Reached max depth {current_depth} for URL {url}, not extracting links")

        try:
            # Регистрируем уникальные формы для статистики
            new_forms_count = 0
            for form in forms_to_scan:
                form_hash = self.get_form_hash(form)
                if form_hash not in self.scanned_form_hashes:
                    self.scanned_form_hashes.add(form_hash)
                    new_forms_count += 1
            if new_forms_count > 0:
                self.scanned_forms_count += new_forms_count

            # --- Ограничиваем количество одновременных задач (batch gather) ---
            batch_size = min(3, self.max_concurrent)  # уменьшено до 3 для снижения нагрузки
            tasks: list[asyncio.Task[Any]] = []
            task_scan_types: list[str] = []
            for scan_type in self.scan_types:
                if self.should_stop:
                    return
                if scan_type == "sql":
                    tasks.append(asyncio.create_task(self.check_sql_injection(session, url, forms_to_scan)))
                    task_scan_types.append(scan_type)
                elif scan_type == "xss":
                    tasks.append(asyncio.create_task(self.check_xss(session, url, forms_to_scan)))
                    task_scan_types.append(scan_type)
                elif scan_type == "csrf":
                    tasks.append(asyncio.create_task(self.check_csrf(url, forms_to_scan)))
                    task_scan_types.append(scan_type)

            # --- Batch gather ---
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i : i + batch_size]
                results = await asyncio.gather(*batch, return_exceptions=True)
                for j, result in enumerate(results):
                    task_index = i + j
                    if isinstance(result, Exception):
                        log_and_notify("error", f"Failed to scan URL {url}: {result}")
                    elif result:
                        scan_type = task_scan_types[task_index] if task_index < len(task_scan_types) else "unknown"
                        if isinstance(result, dict):
                            self._process_scan_results(url, [result], [scan_type], results_by_type)
                        elif isinstance(result, str):
                            self._process_scan_results(url, [{"details": result}], [scan_type], results_by_type)

            self.update_progress(url, current_depth, to_visit.qsize() if to_visit else 0)
            logger.info(f"Successfully scanned URL: {url} at depth {current_depth}")

        except Exception as e:
            log_and_notify("error", f"Failed to scan URL {url}: {e}")
