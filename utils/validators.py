"""
Валидаторы для веб-сканера

Этот модуль содержит функции для валидации различных типов данных,
используемых в приложении.
"""

import re
import ipaddress
from typing import Dict, Any
from urllib.parse import urlparse

class ValidationError(Exception):
    """Исключение для ошибок валидации"""
    pass

class DataValidator:
    """Класс для валидации данных"""
    
    def __init__(self):
        # Регулярные выражения для валидации
        self.email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        self.username_pattern = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
        self.url_pattern = re.compile(r'^https?://[^\s/$.?#][^\s]*$')
        self.ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        
        # Ограничения
        self.max_url_length = 2048
        self.max_username_length = 50
        self.max_email_length = 255
        self.min_password_length = 8
        self.max_password_length = 128
    
    def validate_email(self, email: str) -> bool:
        """
        Валидирует email адрес
        
        Args:
            email: Email для валидации
            
        Returns:
            bool: True если email валиден
        """
        if not email or not isinstance(email, str):
            return False
        
        email = email.strip()
        if len(email) > self.max_email_length:
            return False
        
        return bool(self.email_pattern.match(email))
    
    def validate_username(self, username: str) -> bool:
        """
        Валидирует имя пользователя
        
        Args:
            username: Имя пользователя для валидации
            
        Returns:
            bool: True если имя пользователя валидно
        """
        if not username or not isinstance(username, str):
            return False
        
        username = username.strip()
        if len(username) > self.max_username_length:
            return False
        
        return bool(self.username_pattern.match(username))
    
    def validate_password(self, password: str) -> Dict[str, Any]:
        """
        Валидирует пароль и возвращает оценку безопасности
        
        Args:
            password: Пароль для валидации
            
        Returns:
            Dict с результатами валидации
        """
        if not password or not isinstance(password, str):
            return {'valid': False, 'score': 0, 'issues': ['Password is empty or invalid type']}
        
        issues = []
        score = 0
        
        # Проверяем длину
        if len(password) < self.min_password_length:
            issues.append(f'Password too short (minimum {self.min_password_length} characters)')
        elif len(password) > self.max_password_length:
            issues.append(f'Password too long (maximum {self.max_password_length} characters)')
        else:
            score += 1
        
        # Проверяем наличие букв
        if re.search(r'[a-zA-Z]', password):
            score += 1
        else:
            issues.append('Password must contain letters')
        
        # Проверяем наличие цифр
        if re.search(r'\d', password):
            score += 1
        else:
            issues.append('Password must contain numbers')
        
        # Проверяем наличие специальных символов
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            issues.append('Password should contain special characters')
        
        # Проверяем смешанный регистр
        if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            score += 1
        else:
            issues.append('Password should contain both uppercase and lowercase letters')
        
        # Проверяем на простые паттерны
        if re.search(r'(.)\1{2,}', password):  # Повторяющиеся символы
            score -= 1
            issues.append('Password contains repeated characters')
        
        if re.search(r'(123|abc|qwe)', password.lower()):  # Простые последовательности
            score -= 1
            issues.append('Password contains simple sequences')
        
        return {
            'valid': score >= 3 and len(issues) <= 2,
            'score': max(0, score),
            'issues': issues,
            'strength': self._get_password_strength(score)
        }
    
    def _get_password_strength(self, score: int) -> str:
        """Определяет силу пароля по баллам"""
        if score >= 5:
            return 'strong'
        elif score >= 3:
            return 'medium'
        elif score >= 1:
            return 'weak'
        else:
            return 'very_weak'
    
    def validate_url(self, url: str) -> bool:
        """
        Валидирует URL
        
        Args:
            url: URL для валидации
            
        Returns:
            bool: True если URL валиден
        """
        if not url or not isinstance(url, str):
            return False
        
        url = url.strip()
        if len(url) > self.max_url_length:
            return False
        
        try:
            parsed = urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except ValueError:
            return False
    
    def validate_ip_address(self, ip: str) -> bool:
        """
        Валидирует IP адрес
        
        Args:
            ip: IP адрес для валидации
            
        Returns:
            bool: True если IP адрес валиден
        """
        if not ip or not isinstance(ip, str):
            return False
        
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_domain(self, domain: str) -> bool:
        """
        Валидирует доменное имя
        
        Args:
            domain: Доменное имя для валидации
            
        Returns:
            bool: True если доменное имя валидно
        """
        if not domain or not isinstance(domain, str):
            return False
        
        domain = domain.strip().lower()
        
        # Проверяем формат домена
        if not re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', domain):
            return False
        
        # Проверяем длину
        if len(domain) > 253:
            return False
        
        # Проверяем части домена
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if len(part) > 63 or len(part) == 0:
                return False
        
        return True
    
    def validate_scan_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Валидирует конфигурацию сканирования
        
        Args:
            config: Конфигурация для валидации
            
        Returns:
            Dict с результатами валидации
        """
        issues = []
        valid = True
        
        # Проверяем обязательные поля
        required_fields = ['url', 'scan_types']
        for field in required_fields:
            if field not in config:
                issues.append(f'Missing required field: {field}')
                valid = False
        
        if not valid:
            return {'valid': False, 'issues': issues}
        
        # Валидируем URL
        if not self.validate_url(config['url']):
            issues.append('Invalid URL')
            valid = False
        
        # Валидируем типы сканирования
        if not isinstance(config['scan_types'], list):
            issues.append('scan_types must be a list')
            valid = False
        else:
            valid_types = {'sql', 'xss', 'csrf'}
            for scan_type in config['scan_types']:
                if scan_type not in valid_types:
                    issues.append(f'Invalid scan type: {scan_type}')
                    valid = False
        
        # Валидируем опциональные поля
        if 'max_depth' in config:
            if not isinstance(config['max_depth'], int) or config['max_depth'] < 1:
                issues.append('max_depth must be a positive integer')
                valid = False
        
        if 'max_concurrent' in config:
            if not isinstance(config['max_concurrent'], int) or config['max_concurrent'] < 1:
                issues.append('max_concurrent must be a positive integer')
                valid = False
        
        if 'timeout' in config:
            if not isinstance(config['timeout'], (int, float)) or config['timeout'] <= 0:
                issues.append('timeout must be a positive number')
                valid = False
        
        return {'valid': valid, 'issues': issues}
    
    def sanitize_input(self, text: str, max_length: int = 255) -> str:
        """
        Очищает пользовательский ввод
        
        Args:
            text: Текст для очистки
            max_length: Максимальная длина
            
        Returns:
            str: Очищенный текст
        """
        if not text or not isinstance(text, str):
            return ""
        
        # Удаляем опасные символы
        sanitized = re.sub(r'[<>"\']', '', text.strip())
        
        # Ограничиваем длину
        return sanitized[:max_length]
    
    def validate_json_data(self, data: Any) -> bool:
        """
        Проверяет, что данные могут быть сериализованы в JSON
        
        Args:
            data: Данные для проверки
            
        Returns:
            bool: True если данные валидны для JSON
        """
        try:
            import json
            json.dumps(data)
            return True
        except (TypeError, ValueError):
            return False

# Глобальный экземпляр валидатора
validator = DataValidator()

# Функции-помощники для обратной совместимости
def is_valid_email(email: str) -> bool:
    """Проверяет валидность email"""
    return validator.validate_email(email)

def is_valid_url(url: str) -> bool:
    """Проверяет валидность URL"""
    return validator.validate_url(url)

def is_valid_username(username: str) -> bool:
    """Проверяет валидность имени пользователя"""
    return validator.validate_username(username)

def validate_password_strength(password: str) -> int:
    """Возвращает оценку силы пароля (0-5)"""
    result = validator.validate_password(password)
    return result['score']

def sanitize_input(text: str, max_length: int = 255) -> str:
    """Очищает пользовательский ввод"""
    return validator.sanitize_input(text, max_length) 