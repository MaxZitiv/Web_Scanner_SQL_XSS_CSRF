"""Комбинирует миксы воркера сканирования в итоговый класс ScanWorker."""

from ._scan_worker_checks import ScanWorkerChecksMixin
from ._scan_worker_core import ScanWorkerCore
from ._scan_worker_crawl import ScanWorkerCrawlMixin
from ._scan_worker_orchestrator import ScanWorkerOrchestratorMixin
from ._scan_worker_signals import ScanWorkerSignals


class ScanWorker(ScanWorkerCrawlMixin, ScanWorkerChecksMixin, ScanWorkerOrchestratorMixin, ScanWorkerCore):
    """Асинхронный воркер для сканирования веб-сайтов на уязвимости."""


__all__ = ["ScanWorker", "ScanWorkerSignals"]
