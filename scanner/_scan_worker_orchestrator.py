import asyncio
import gc
import time
from datetime import datetime
from typing import Any

import aiohttp

from utils.database import db
from utils.logger import logger
from utils.performance import get_local_timestamp

from ._scan_worker_protocol import _ScanWorkerProtocol
from ._scanner_config import parse_html_cached
from .cache_manager import cache_manager


class ScanWorkerOrchestratorMixin(_ScanWorkerProtocol):
    async def scan(self: _ScanWorkerProtocol) -> dict[str, Any]:
        """Основной метод для запуска сканирования."""
        try:
            logger.info(f"Starting scan for URL: {self.base_url}")
            self.scan_start_time = datetime.now()
            self.start_time = time.time()

            self.signals.log_event.emit(f"🚀 Начинаем полное сканирование: {self.base_url}")

            # Инициализация (полный сброс состояния между запусками)
            self.visited_urls.clear()
            self.scanned_urls.clear()
            self.all_scanned_urls.clear()
            self.all_found_forms.clear()
            self.scanned_form_hashes.clear()
            self.unscanned_urls.clear()
            self.vulnerabilities = {"sql": [], "xss": [], "csrf": []}
            self.scanned_forms_count = 0
            self.total_scanned_count = 0
            self.total_forms_count = 0
            self.current_form_index = 0
            self.current_depth = 0
            self.max_depth_reached = False
            self.scan_complete = False
            self.reported_progress = 0
            self.scan_completion_metrics["errors_encountered"] = 0
            self.scan_completion_metrics["urls_scanned"] = 0
            self.scan_completion_metrics["vulnerabilities_found"] = 0

            self.to_visit = asyncio.Queue()

            await self.to_visit.put((self.base_url, 0))
            self.total_links_count = 1

            # Основное сканирование
            timeout = self._client_timeout()

            async with aiohttp.ClientSession(timeout=timeout) as session:
                semaphore = asyncio.Semaphore(self.max_concurrent)
                self.session = session

                # Преобразуем scan_types
                scan_types_lower: list[str] = []
                for scan_type in self.scan_types:
                    if "sql" in scan_type.lower():
                        scan_types_lower.append("sql")
                    elif "xss" in scan_type.lower():
                        scan_types_lower.append("xss")
                    elif "csrf" in scan_type.lower():
                        scan_types_lower.append("csrf")

                if not scan_types_lower:
                    scan_types_lower = ["sql", "xss", "csrf"]

                self.scan_types = scan_types_lower

                # Выполняем сканирование
                results_by_type: dict[str, list[dict[str, Any]]] = {"sql": [], "xss": [], "csrf": []}
                visited_urls: set[str] = set()
                scanned_urls: set[str] = set()

                await self.crawl_and_scan_parallel(
                    session, semaphore, self.base_url, results_by_type, visited_urls, scanned_urls
                )

            # Завершение
            self.scan_end_time = datetime.now()
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()

            if self.should_stop:
                status = "stopped_by_user"
                self.signals.log_event.emit(
                    f"⏹️ Сканирование остановлено пользователем. Просканировано URL: {self.total_scanned_count}"
                )
            else:
                status = "completed"
                self.signals.log_event.emit(f"✅ Сканирование завершено за {scan_duration:.2f}с")

            # Формируем результаты
            result: dict[str, Any] = {
                "url": self.base_url,
                "scan_types": self.scan_types,
                "duration": scan_duration,
                "total_urls_scanned": len(self.all_scanned_urls),
                "total_forms_scanned": self.scanned_forms_count,
                "vulnerabilities": self.vulnerabilities,
                "timestamp": datetime.now().isoformat(),
                "total_urls_discovered": self.total_links_count,
                "unscanned_urls": list(self.unscanned_urls),
                "status": status,
            }

            total_vulnerabilities = sum(len(vulns) for vulns in self.vulnerabilities.values())
            self.signals.log_event.emit(
                f"📊 Просканировано URL: {len(self.all_scanned_urls)}, "
                f"форм: {self.scanned_forms_count}, "
                f"уязвимостей: {total_vulnerabilities}"
            )

            # Финальный прогресс и статистика
            self.reported_progress = 100
            self.signals.progress.emit(100, "")
            self.signals.progress_updated.emit(100)
            self.update_stats()
            return result

        except Exception as e:
            logger.error(f"Error in scan method: {e}")
            self.signals.log_event.emit(f"❌ Ошибка сканирования: {e!s}")

            return {
                "url": self.base_url,
                "scan_types": self.scan_types,
                "duration": 0,
                "total_urls_scanned": 0,
                "total_forms_scanned": 0,
                "vulnerabilities": {"sql": [], "xss": [], "csrf": []},
                "timestamp": get_local_timestamp(),
                "error": str(e),
                "total_urls_discovered": 0,
                "unscanned_urls": list(self.unscanned_urls),
                "status": "failed",
            }

    async def save_results(self: _ScanWorkerProtocol):
        """Сохраняет результаты сканирования в базу данных."""
        try:
            scan_duration = time.time() - self.start_time if hasattr(self, "start_time") and self.start_time > 0 else 0
            results: list[dict[str, Any]] = [
                {
                    "type": vuln_type,
                    "url": vuln.get("url", self.base_url),
                    "details": vuln.get("details", ""),
                    "severity": vuln.get("severity", "medium"),
                }
                for vuln_type, vulns in self.vulnerabilities.items()
                for vuln in vulns
            ]

            scan_type = (
                "comprehensive" if len(self.scan_types) > 1 else self.scan_types[0] if self.scan_types else "general"
            )
            completion_status = getattr(self, "scan_completion_metrics", {}).get("completion_status", "unknown")
            if completion_status == "stopped_by_user":
                scan_type += "_partial"

            success = db.save_scan_async(
                user_id=self.user_id,
                url=self.base_url,
                results=results,
                scan_type=scan_type,
                scan_duration=scan_duration,
            )

            if success:
                logger.info(f"Scan results saved successfully for user {self.user_id}")
            else:
                logger.error("Failed to save scan results")

            # Очистка кэшей
            if hasattr(parse_html_cached, "cache_info") and hasattr(parse_html_cached, "cache_clear"):
                parse_html_cached.cache_clear()
            cache_manager.cleanup_all()
            gc.collect()

        except Exception as e:
            logger.error(f"Error saving scan results: {e}")
            self.signals.log_event.emit(f"❌ Ошибка сохранения результатов: {e!s}")
