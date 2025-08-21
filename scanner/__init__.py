"""
Модуль сканера для веб-сканера уязвимостей.

Этот модуль содержит основной сканер уязвимостей:
- scanner_fixed: исправленная версия сканера
"""

from .scanner_fixed import ScanWorker

__all__ = ['ScanWorker']
