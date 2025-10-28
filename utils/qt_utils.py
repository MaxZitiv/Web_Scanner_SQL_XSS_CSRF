from typing import Any
from PyQt5.QtCore import pyqtSignal

class SignalWrapper:
    """Обертка для pyqtSignal с явным объявлением метода emit"""
    def __init__(self, signal: pyqtSignal):
        self._signal = signal
        # Сохраняем ссылку на оригинальный метод emit
        self._emit_method = getattr(signal, 'emit', None)
    
    def emit(self, *args: Any):
        """Явно объявленный метод emit"""
        # Используем сохраненную ссылку на метод emit
        if self._emit_method is not None:
            self._emit_method(*args)