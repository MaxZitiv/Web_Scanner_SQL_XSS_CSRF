import bcrypt
import re
import time
from datetime import datetime
from typing import Optional, Dict, Tuple, List
import sqlite3

# Импортируем только нужные зависимости
from utils.database import db
from utils.logger import logger, log_and_notify
from utils.security import validate_password_strength, validate_email_format

# Кэш для пользователей
_user_cache = {}
_cache_ttl = 300  # 5 минут
_cache_timestamps = {}

class UserModel:
    """
    Модель для работы с пользователями.
    Предоставляет методы для регистрации, аутентификации и управления пользователями.
    """
    
    def __init__(self) -> None:
        logger.info("UserModel initialized.")
        self.current_user_id: Optional[int] = None
        self.current_username: Optional[str] = None
        self.current_email: Optional[str] = None

    def set_current_user(self, user_id: int, username: str, email: str) -> None:
        """Устанавливает данные текущего залогиненного пользователя."""
        self.current_user_id = user_id
        self.current_username = username
        self.current_email = email
        logger.info(f"Current user set: {username} (ID: {user_id})")

    def get_user_id(self) -> Optional[int]:
        """Возвращает ID текущего пользователя."""
        return self.current_user_id

    def get_username(self) -> Optional[str]:
        """Возвращает имя текущего пользователя."""
        return self.current_username

    def logout_user(self) -> None:
        """Сбрасывает данные текущего пользователя при выходе."""
        self.current_user_id = None
        self.current_username = None
        self.current_email = None
        logger.info("Current user data cleared (logout).")

    def _get_cached_user(self, key: str) -> Optional[Dict]:
        """Получает пользователя из кэша"""
        if key in _user_cache:
            if time.time() - _cache_timestamps.get(key, 0) < _cache_ttl:
                return _user_cache[key]
            else:
                # Удаляем устаревший результат
                del _user_cache[key]
                if key in _cache_timestamps:
                    del _cache_timestamps[key]
        return None

    def _cache_user(self, key: str, user_data: Dict) -> None:
        """Сохраняет пользователя в кэш"""
        _user_cache[key] = user_data
        _cache_timestamps[key] = time.time()
        
        # Очищаем старые записи, если кэш слишком большой
        if len(_user_cache) > 100:
            oldest_key = min(_cache_timestamps.keys(), key=lambda k: _cache_timestamps[k])
            del _user_cache[oldest_key]
            del _cache_timestamps[oldest_key]

    def _validate_registration_data(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """Валидация данных регистрации пользователя."""
        try:
            # 1. Проверка на наличие и тип данных
            if not all(isinstance(arg, str) and arg.strip() for arg in [username, email, password]):
                return False, "Неверный формат данных. Поля не могут быть пустыми."
            
            # 2. Валидация имени пользователя
            username = username.strip()
            if not (3 <= len(username) <= 50):
                return False, "Имя пользователя должно содержать от 3 до 50 символов."
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                return False, "Имя пользователя может содержать только буквы, цифры и подчеркивания."
            
            # 3. Валидация email
            email = email.strip()
            if not validate_email_format(email):
                return False, "Введите корректный email адрес."
            
            # 4. Валидация пароля
            password_score = validate_password_strength(password)
            if password_score < 3:
                return False, "Пароль слишком слабый. Используйте минимум 8 символов, включая заглавные буквы, цифры и специальные символы."
            
            # 5. Проверка уникальности в БД
            if db.get_user_by_username_or_email(username):
                return False, "Пользователь с таким именем или email уже существует."
            
            return True, ""
        except Exception as e:
            log_and_notify('error', f"Error validating registration data: {e}")
            return False, "Ошибка валидации данных. Пожалуйста, попробуйте снова."

    def is_account_locked(self, username: str) -> Tuple[bool, Optional[str]]:
        """Проверяет, заблокирован ли аккаунт из-за неудачных попыток входа."""
        try:
            user = db.get_user_by_username_or_email(username)
            if user and user.get('locked_until'):
                locked_until = datetime.fromisoformat(user['locked_until'])
                if datetime.now() < locked_until:
                    remaining = locked_until - datetime.now()
                    return True, f"Аккаунт заблокирован на {int(remaining.total_seconds() / 60)} минут"
            return False, None
        except Exception as e:
            log_and_notify('error', f"Error checking account lock status: {e}")
            return False, None

    def register_user(self, username: str, password: str, email: Optional[str] = None) -> Tuple[bool, str]:
        """Регистрирует нового пользователя."""
        if email is None:
            email = f"{username}@example.com"
        
        is_valid, error_message = self._validate_registration_data(username, email, password)
        if not is_valid:
            return False, error_message
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        success, message = db.add_user(username, email, password_hash)
        
        if success:
            logger.info(f"User registered successfully: {username}")
            return True, "Пользователь успешно зарегистрирован"
        else:
            return False, message

    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Аутентифицирует пользователя."""
        try:
            if not all(isinstance(arg, str) and arg.strip() for arg in [username, password]):
                return False, None, "Неверный формат данных"
            
            is_locked, lock_message = self.is_account_locked(username)
            if is_locked:
                return False, None, lock_message
            
            user = db.get_user_by_username_or_email(username)
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                db.update_failed_attempts(username, failed=False)
                db.update_last_login(user['id'])
                
                logger.info(f"User authenticated successfully: {username}")
                return True, user, "Успешная аутентификация"
            else:
                db.update_failed_attempts(username, failed=True)
                return False, None, "Неверное имя пользователя или пароль"
        except Exception as e:
            log_and_notify('error', f"Error authenticating user {username}: {e}")
            return False, None, "Ошибка аутентификации"

    def change_password(self, user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Изменяет пароль пользователя."""
        try:
            if not all([isinstance(user_id, int), old_password, new_password]):
                return False, "Неверные параметры"
            
            user_data = db.get_user_by_id(user_id)
            if not user_data:
                return False, "Пользователь не найден"
            
            if not bcrypt.checkpw(old_password.encode('utf-8'), user_data['password_hash'].encode('utf-8')):
                return False, "Неверный текущий пароль"
            
            password_score = validate_password_strength(new_password)
            if password_score < 3:
                return False, "Новый пароль слишком слабый"
            
            new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            success = db.update_user_password(user_id, new_password_hash)
            if success:
                logger.info(f"Password changed successfully for user {user_id}")
                return True, "Пароль успешно изменен"
            else:
                return False, "Ошибка обновления пароля в БД"
        
        except Exception as e:
            log_and_notify('error', f"Error changing password for user {user_id}: {e}")
            return False, "Ошибка изменения пароля"

    def get_user_profile(self, user_id: int) -> Optional[Dict]:
        """Получает профиль пользователя."""
        try:
            if not isinstance(user_id, int):
                return None
            
            user_data = db.get_user_by_id(user_id)
            if user_data:
                del user_data['password_hash']
                return user_data
            return None
        except Exception as e:
            log_and_notify('error', f"Error getting user profile for {user_id}: {e}")
            return None

    def update_user_profile(self, user_id: int, email: str) -> Tuple[bool, str]:
        """Обновляет профиль пользователя."""
        try:
            if not isinstance(user_id, int) or not email.strip():
                return False, "Неверные параметры"
            
            if not validate_email_format(email):
                return False, "Неверный формат email"
            
            success = db.update_user_email(user_id, email)
            if success:
                logger.info(f"Profile updated successfully for user {user_id}")
                return True, "Профиль успешно обновлен"
            else:
                return False, "Ошибка обновления профиля в БД"
        except Exception as e:
            log_and_notify('error', f"Error updating user profile for {user_id}: {e}")
            return False, "Ошибка обновления профиля"

    def get_all_users(self, limit: int = 100) -> List[Dict]:
        """Получает список всех пользователей (для административных целей)."""
        return db.get_all_users(limit)

    def delete_user(self, user_id: int) -> bool:
        """Удаляет пользователя."""
        return db.delete_user(user_id)

    def clear_user_cache(self) -> None:
        """Очищает кэш пользователей."""
        global _user_cache, _cache_timestamps
        _user_cache.clear()
        _cache_timestamps.clear()
        logger.info("User cache cleared")

    def get_user_cache_stats(self) -> Dict[str, int]:
        """Получает статистику кэша пользователей."""
        return {
            'cache_size': len(_user_cache),
            'cache_entries': len(_cache_timestamps)
        }
    
    def is_username_taken(self, username: str) -> bool:
        """Проверяет, занято ли имя пользователя."""
        try:
            user = db.get_user_by_username_or_email(username)
            return user is not None
        except Exception as e:
            log_and_notify('error', f"Error checking username availability: {e}")
            return False
        
    def is_valid_email(self, email: str) -> bool:
        """Проверяет валидность email"""
        return validate_email_format(email)
    
    def is_email_taken(self, email: str) -> bool:
        """Проверяет, используется ли уже email"""
        try:
            user = db.get_user_by_username_or_email(email)
            return user is not None
        except Exception as e:
            log_and_notify('error', f"Error checking email availability: {e}")
            return False
        
    def create_user(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """Создает нового пользователя в системе.
        
        Args:
            username: Имя пользователя
            email: Email адрес
            password: Пароль
            
        Returns:
            Tuple[bool, str]: (успех, сообщение об ошибке или None)
        """
        try:
            # Проверяем, что имя пользователя не занято
            if self.is_username_taken(username):
                return False, "Имя пользователя уже занято"
                
            # Проверяем, что email не используется
            if self.is_email_taken(email):
                return False, "Email уже используется"
                
            # Валидация имени пользователя
            if not self._validate_username(username):
                return False, "Некорректный формат имени пользователя"
                
            # Валидация email
            if not self.is_valid_email(email):
                return False, "Некорректный формат email"
                
            # Валидация пароля
            password_score = validate_password_strength(password)
            if password_score < 3:
                return False, f"Слишком слабый пароль (оценка: {password_score}/5)"
                
            # Хеширование пароля
            salt = bcrypt.gensalt(rounds=12)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
            
            # Создание пользователя в базе данных
            conn = db.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, hashed_password)
            )
            
            conn.commit()
            conn.close()
            
            logger.info(f"User {username} created successfully")
            return True, ""
            
        except sqlite3.Error as e:
            log_and_notify('error', f"Database error creating user: {e}")
            return False, "Ошибка базы данных при создании пользователя"
        except Exception as e:
            log_and_notify('error', f"Unexpected error creating user: {e}")
            return False, "Неожиданная ошибка при создании пользователя"
        
    def _validate_username(self, username: str) -> bool:
        """Валидирует имя пользователя.
        
        Args:
            username: Имя пользователя для валидации
            
        Returns:
            bool: True если имя пользователя валидно, False иначе
        """
        # Имя пользователя должно быть 3-20 символов, только буквы, цифры и подчеркивания
        import re
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return bool(re.match(pattern, username))



