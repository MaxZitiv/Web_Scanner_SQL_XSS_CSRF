"""Сигналы асинхронного воркера сканирования."""

from PyQt6.QtCore import QObject, pyqtSignal


class ScanWorkerSignals(QObject):
    """Сигналы для воркера сканирования."""

    result = pyqtSignal(dict)
    progress = pyqtSignal(int, str)
    progress_updated = pyqtSignal(int)
    vulnerability_found = pyqtSignal(str, str, str)
    log_event = pyqtSignal(str)
    stats_updated = pyqtSignal(str, object)
    site_structure_updated = pyqtSignal(list, list)


__all__ = ["ScanWorkerSignals"]
