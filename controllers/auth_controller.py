import sqlite3
import re
import bcrypt
from typing import Optional, Dict, Any
from utils.logger import logger, log_and_notify
from utils.database import db
from utils.security import validate_password_strength
from PyQt5.QtCore import QObject


class AuthController(QObject):
    """
    Контроллер для управления аутентификацией пользователей.
    
    Обеспечивает регистрацию, вход, валидацию данных и управление сессиями.
    """

    def __init__(self, user_model):
        """Инициализация контроллера аутентификации."""
        super().__init__()
        self.user_model = user_model
        self.db_path = 'scanner.db' # Этот путь больше не будет использоваться напрямую
        logger.info("AuthController initialized.")
    
    @staticmethod
    def _get_connection() -> sqlite3.Connection:
        """
        Возвращает соединение с базой данных, используя централизованную функцию.
        
        Returns:
            sqlite3.Connection: Соединение с базой данных
        """
        return db.get_db_connection()
    
    @staticmethod
    def _hash_password(password: str) -> str:
        """
        Хеширует пароль с использованием bcrypt.
        
        Args:
            password: Пароль для хеширования
            
        Returns:
            str: Хешированный пароль
        """
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        return hashed

    @staticmethod
    def _validate_email(email: str) -> bool:
        """
        Валидирует формат email адреса.

        Args:
            email: Email для валидации

        Returns:
            bool: True если email валиден, False иначе
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def _validate_username(username: str) -> bool:
        """
        Валидирует имя пользователя.
        
        Args:
            username: Имя пользователя для валидации
            
        Returns:
            bool: True если имя пользователя валидно, False иначе
        """
        # Имя пользователя должно быть 3-20 символов, только буквы, цифры и подчеркивания
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return bool(re.match(pattern, username))
    
    def register(self, username, password, email):
        """
        Регистрирует нового пользователя.
        """
        if not all([username, password, email]):
            return "Все поля должны быть заполнены."
        
        if not self._validate_email(email):
            return "Неверный формат email."
        
        strength = validate_password_strength(password)
        if strength < 3:
            return f"Пароль слишком слабый (оценка: {strength}/5)."

        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                return "Пользователь с таким именем или email уже существует."

            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

            cursor.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                (username, hashed_password, email) # Сохраняем как bytes
            )
            conn.commit()
            logger.info(f"User {username} registered successfully.")
            return None
        except sqlite3.Error as e:
            log_and_notify('error', f"Database error during registration: {e}")
            return "Ошибка базы данных при регистрации."

    def login(self, username, password):
        """
        Выполняет вход пользователя в систему.
        """
        try:
            user_data = db.get_user_by_username_or_email(username)
            if not user_data:
                return False, "Неверное имя пользователя или пароль."

            password_hash = user_data.get('password_hash') # Это bytes
            if not password_hash:
                return False, "Ошибка: у пользователя отсутствует хэш пароля."

            if isinstance(password_hash, str):
                password_hash = password_hash.encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), password_hash):
                self.user_model.set_current_user(
                    user_id=user_data['id'],
                    username=user_data['username'],
                    email=user_data['email']
                )
                db.update_failed_attempts(username, failed=False)
                logger.info(f"User {username} logged in successfully.")
                return True, "Успешный вход"
            else:
                db.update_failed_attempts(username, failed=True)
                logger.warning(f"Failed login attempt for user {username}.")
                return False, "Неверное имя пользователя или пароль."
        except sqlite3.Error as e:
            log_and_notify('error', f"Database error during login: {e}")
            return False, "Ошибка базы данных."

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Получает данные пользователя по ID.
        
        Args:
            user_id: ID пользователя
            
        Returns:
            Optional[Dict[str, Any]]: Данные пользователя или None если не найден
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT id, username, email, created_at, last_login FROM users WHERE id = ?",
                (user_id,)
            )
            
            user_data = cursor.fetchone()
            
            if not user_data:
                logger.warning(f"User not found with ID: {user_id}")
                return None
            
            user_id, username, email, created_at, last_login = user_data
            
            return {
                'id': user_id,
                'username': username,
                'email': email,
                'created_at': created_at,
                'last_login': last_login
            }
            
        except sqlite3.Error as e:
            log_and_notify('error', f"Database error getting user by ID: {e}")
            return None
        except (ValueError, KeyError, AttributeError, ImportError, TypeError, RuntimeError) as e:
            log_and_notify('error', f"Unexpected error getting user by ID: {e}")
            return None
    
    def update_user_profile(self, user_id: int, username: Optional[str] = None, email: Optional[str] = None) -> bool:
        """
        Обновляет профиль пользователя.
        
        Args:
            user_id: ID пользователя
            username: Новое имя пользователя (опционально)
            email: Новый email (опционально)
            
        Returns:
            bool: True при успешном обновлении, False при ошибке
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            updates = []
            params = []
            
            if username is not None:
                if not self._validate_username(username):
                    logger.warning(f"Profile update failed: Invalid username format: {username}")
                    return False
                updates.append("username = ?")
                params.append(username)
            
            if email is not None:
                if not self._validate_email(email):
                    logger.warning(f"Profile update failed: Invalid email format: {email}")
                    return False
                updates.append("email = ?")
                params.append(email)
            
            if not updates:
                logger.warning("Profile update failed: No fields to update")
                return False
            
            params.append(user_id)
            
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, params)
            
            if cursor.rowcount == 0:
                logger.warning(f"Profile update failed: User not found with ID {user_id}")
                return False
            
            conn.commit()
            logger.info(f"Profile updated successfully for user ID {user_id}")
            return True
            
        except sqlite3.Error as e:
            log_and_notify('error', f"Database error updating profile: {e}")
            return False
        except (ValueError, KeyError, AttributeError, ImportError, TypeError, RuntimeError) as e:
            log_and_notify('error', f"Unexpected error updating profile: {e}")
            return False
    
    def change_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        """
        Изменяет пароль пользователя.
        
        Args:
            user_id: ID пользователя
            current_password: Текущий пароль
            new_password: Новый пароль
            
        Returns:
            bool: True при успешном изменении, False при ошибке
        """
        try:
            # Проверка силы нового пароля
            password_score = validate_password_strength(new_password)
            if password_score < 3:
                logger.warning(f"Password change failed: Weak new password for user ID {user_id}")
                return False
            
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Получаем текущий хеш пароля
            cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
            user_data = cursor.fetchone()
            
            if not user_data:
                logger.warning(f"Password change failed: User not found with ID {user_id}")
                return False
            
            stored_hash = user_data[0]
            
            # Проверяем текущий пароль
            if self._hash_password(current_password) != stored_hash:
                logger.warning(f"Password change failed: Incorrect current password for user ID {user_id}")
                return False
            
            # Обновляем пароль
            new_hash = self._hash_password(new_password)
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user_id)
            )
            
            conn.commit()
            logger.info(f"Password changed successfully for user ID {user_id}")
            return True
            
        except sqlite3.Error as e:
            log_and_notify('error', f"Database error changing password: {e}")
            return False
        except Exception as e:
            log_and_notify('error', f"Unexpected error changing password: {e}")
            return False
    
    def delete_user(self, user_id: int, password: str) -> bool:
        """
        Удаляет пользователя из системы.
        
        Args:
            user_id: ID пользователя
            password: Пароль для подтверждения
            
        Returns:
            bool: True при успешном удалении, False при ошибке
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Проверяем пароль
            cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
            user_data = cursor.fetchone()
            
            if not user_data:
                logger.warning(f"User deletion failed: User not found with ID {user_id}")
                return False
            
            stored_hash = user_data[0]
            
            if self._hash_password(password) != stored_hash:
                logger.warning(f"User deletion failed: Incorrect password for user ID {user_id}")
                return False
            
            # Удаляем пользователя
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            
            if cursor.rowcount == 0:
                logger.warning(f"User deletion failed: No user deleted with ID {user_id}")
                return False
            
            conn.commit()
            logger.info(f"User deleted successfully with ID {user_id}")
            return True
            
        except sqlite3.Error as e:
            log_and_notify('error', f"Database error deleting user: {e}")
            return False
        except Exception as e:
            log_and_notify('error', f"Unexpected error deleting user: {e}")
            return False
    
    @staticmethod
    def close_connection():
        """Закрывает соединение с базой данных."""
        # Этот метод больше не нужен, так как соединения управляются централизованно
        logger.debug("Database connection management is centralized") 