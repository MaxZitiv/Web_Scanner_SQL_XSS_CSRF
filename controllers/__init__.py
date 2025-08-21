"""
Контроллеры для веб-сканера уязвимостей.

Этот модуль содержит контроллеры для управления различными аспектами приложения:
- AuthController: управление аутентификацией пользователей
- ScanController: управление процессом сканирования
"""

from .auth_controller import AuthController
from .scan_controller import ScanController

__all__ = ['AuthController', 'ScanController'] 