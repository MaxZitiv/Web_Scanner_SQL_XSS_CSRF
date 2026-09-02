"""
Модели данных для веб-сканера уязвимостей.

Этот модуль содержит модели данных:
- UserModel: модель пользователя
- ScanModel: модель сканирования
- SecurityPolicy: модель политики безопасности
- ScanResult: модель результата сканирования
- Vulnerability: модель уязвимости
- User: датакласс пользователя
"""

from .policy_model import SecurityPolicy
from .scan_model import ScanModel
from .scan_result_model import ScanResult, Vulnerability
from .user_data_model import User
from .user_model import UserModel

__all__ = ["ScanModel", "ScanResult", "SecurityPolicy", "User", "UserModel", "Vulnerability"]
