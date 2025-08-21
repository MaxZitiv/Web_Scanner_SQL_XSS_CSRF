"""
Модели данных для веб-сканера уязвимостей.

Этот модуль содержит модели данных:
- UserModel: модель пользователя
- ScanModel: модель сканирования
"""

from .user_model import UserModel
from .scan_model import ScanModel

__all__ = ['UserModel', 'ScanModel']
