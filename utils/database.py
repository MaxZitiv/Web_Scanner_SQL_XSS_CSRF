import sqlite3
import os
import json
import datetime
from typing import List, Dict, Optional, Any, Tuple, Union, Callable, cast
from urllib.parse import urlparse
from utils.logger import logger, log_and_notify
from utils.encryption import (
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    decrypt_sensitive_data_safe,
)
from utils.vulnerability_info import (
    location_for_database,
    vulnerability_dict_to_details,
)
# Добавляем аннотации типов для функций шифрования
encrypt_sensitive_data: Callable[[Union[str, Dict[str, Any], List[Any]]], str] = encrypt_sensitive_data
decrypt_sensitive_data: Callable[[str], Union[str, Dict[str, Any], List[Any]]] = decrypt_sensitive_data
decrypt_sensitive_data_safe: Callable[[Any, Any], Union[str, Dict[str, Any], List[Any], Any]] = decrypt_sensitive_data_safe
# from utils.validators import validator
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from utils.sys_utils import get_bundle_root

# Глобальная переменная для пути к базе данных
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', "scanner.db")

class Database:
    """Класс для управления базой данных SQLite с шифрованием и валидацией данных."""

    def __init__(self, db_file: str = "scanner.db"):
        self.db_file = db_file
        self.MAX_URL_LENGTH = 2048
        self.MAX_RESULT_SIZE = 10 * 1024 * 1024  # 10MB
        self._connection = None
        self._executor = ThreadPoolExecutor()
        self._setup_database()

    @staticmethod
    def update_user_credentials(user_id: int, username: str, email: str, password_hash: str) -> bool:
        """
        Обновляет учетные данные пользователя в базе данных.
        
        :param user_id: ID пользователя
        :param username: Новое имя пользователя
        :param email: Новый email
        :param password_hash: Хеш нового пароля
        :return: True если обновление успешно, False в противном случае
        """
        try:
            # Проверяем существование глобальной переменной db
            global db
            # Проверяем, что db инициализирован и доступен
            try:
                # Простая проверка работоспособности соединения
                conn = db.get_db_connection()
            except Exception:
                # Если возникла ошибка, пересоздаем экземпляр
                db = Database()
                
            with db.get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET username = ?, email = ?, password_hash = ? WHERE id = ?",
                    (username, email, password_hash, user_id)
                )
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Error updating user credentials: {e}")
            return False

    @staticmethod
    def get_resource_path(relative_path: str) -> str:
        """Получает полный путь к ресурсу, учитывая возможность запуска из .exe."""
        try:
            base_path = get_bundle_root()
            return os.path.join(base_path, relative_path)
        except Exception as e:
            log_and_notify('error', f"Error getting resource path: {e}")
            return os.path.join(os.path.abspath("."), relative_path)

    def get_db_connection(self) -> sqlite3.Connection:
        """Создает и возвращает соединение с базой данных."""
        # Некоторые внешние вызовы закрывают общее соединение (conn.close()).
        # Если это произошло, пересоздаем его, чтобы следующие запросы
        # (статистика, уязвимости, отчёты) не падали с
        # "Cannot operate on a closed database".
        if self._connection is not None:
            try:
                cur = self._connection.cursor()
                cur.execute('SELECT 1')
                cur.fetchone()
            except (sqlite3.ProgrammingError, sqlite3.OperationalError, sqlite3.DatabaseError):
                try:
                    self._connection.close()
                except Exception:
                    pass
                self._connection = None

        if self._connection is None:
            db_path = self.get_resource_path(os.path.join('data', self.db_file))
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            try:
                self._connection = sqlite3.connect(db_path, check_same_thread=False)
                self._connection.row_factory = sqlite3.Row
            except sqlite3.Error as e:
                log_and_notify('error', f"Error connecting to database: {e}")
                raise
        return self._connection
    
    @contextmanager
    def get_db_connection_cm(self):
        """Контекстный менеджер для безопасного соединения с БД."""
        conn = None
        try:
            conn = self.get_db_connection()
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            log_and_notify('error', f"Database error: {e}")
            raise
            
    def _setup_database(self) -> None:
        """Инициализирует базу данных, создает таблицы и индексы."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()

                cursor.execute(f'''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 50),
                        password_hash TEXT NOT NULL CHECK(length(password_hash) > 0),
                        email TEXT UNIQUE NOT NULL CHECK(length(email) > 0),
                        avatar_path TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        last_login TEXT,
                        failed_attempts INTEGER DEFAULT 0,
                        locked_until TEXT
                    )
                ''')

                cursor.execute(f'''
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        url TEXT NOT NULL CHECK(length(url) > 0 AND length(url) <= {self.MAX_URL_LENGTH}),
                        result TEXT NOT NULL CHECK(length(result) > 0),
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                        scan_type TEXT NOT NULL,
                        status TEXT DEFAULT 'completed',
                        scan_duration REAL DEFAULT 0.0,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        url TEXT NOT NULL,
                        type TEXT NOT NULL,
                        details TEXT,
                        status TEXT DEFAULT 'Новая',
                        severity TEXT DEFAULT 'Средний',
                        description TEXT DEFAULT '',
                        response TEXT DEFAULT '',
                        request_params TEXT DEFAULT '',
                        recommendations TEXT DEFAULT '[]',
                        resources TEXT DEFAULT '[]',
                        comments TEXT DEFAULT '[]',
                        created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                    )
                ''')

                # Миграция для уже существующих таблиц: добавляем новые колонки,
                # если схема была создана до включения расширенных полей.
                for column, ddl in (
                    ('status', "TEXT DEFAULT 'Новая'"),
                    ('severity', "TEXT DEFAULT 'Средний'"),
                    ('description', "TEXT DEFAULT ''"),
                    ('response', "TEXT DEFAULT ''"),
                    ('request_params', "TEXT DEFAULT ''"),
                    ('recommendations', "TEXT DEFAULT '[]'"),
                    ('resources', "TEXT DEFAULT '[]'"),
                    ('comments', "TEXT DEFAULT '[]'"),
                    ('created_date', "TEXT DEFAULT CURRENT_TIMESTAMP"),
                ):
                    try:
                        cursor.execute(f'ALTER TABLE vulnerabilities ADD COLUMN {column} {ddl}')
                    except sqlite3.OperationalError:
                        # Колонка уже существует — ошибка ожидаемая и не критичная.
                        pass

                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id)')
            logger.info("Database setup complete.")
        except Exception as e:
            log_and_notify('error', f"Error setting up database: {e}")
            raise

    def safe_execute(self, query: str, params: Optional[Tuple[Any, ...]] = None) -> List[Dict[str, Any]]:
        """
        Безопасное выполнение SQL-запроса с параметрами.
        
        Args:
            query: SQL-запрос с плейсхолдерами ?
            params: Параметры для подстановки в запрос
            
        Returns:
            List[Dict]: Результаты запроса в виде списка словарей
            
        Raises:
            ValueError: Если в запросе обнаружены потенциально опасные конструкции
            sqlite3.Error: При ошибке выполнения запроса
        """
        # Проверяем на потенциально опасные конструкции в SQL
        dangerous_keywords = ['drop', 'delete', 'truncate', 'alter', 'exec', 'execute', 
                            'insert', 'update', 'create', 'replace']
        
        # Проверяем только для SELECT запросов
        if query.strip().lower().startswith('select'):
            query_lower = query.lower()
            for keyword in dangerous_keywords:
                if keyword in query_lower:
                    raise ValueError(f"Potentially dangerous keyword '{keyword}' detected in SELECT query")
        
        # Выполняем запрос безопасно
        with self.get_db_connection_cm() as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            # Получаем результаты
            if query.strip().lower().startswith('select'):
                columns = [column[0] for column in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            # Для других запросов возвращаем пустой список
            return []

    def close_connection(self):
        """Закрывает соединение с базой данных."""
        if self._connection:
            self._connection.close()
            self._connection = None
        if self._executor:
            self._executor.shutdown(wait=True)

    # --- Методы для работы с пользователями (добавлены из user_model.py) ---
    def add_user(self, username: str, email: str, password_hash: str) -> Tuple[bool, str]:
        """Добавляет нового пользователя в базу данных."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)
                ''', (username, email, password_hash))
                return True, "Пользователь успешно добавлен."
        except sqlite3.IntegrityError as e:
            if 'UNIQUE constraint failed' in str(e):
                return False, f"Ошибка: пользователь с таким именем или email уже существует. Детали: {e}"
            return False, f"Ошибка целостности данных: {e}"
        except Exception as e:
            log_and_notify('error', f"Error adding user {username}: {e}")
            return False, f"Неизвестная ошибка: {e}"
    
    def get_user_by_username_or_email(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Получает пользователя по имени пользователя или email."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, password_hash, email, created_at, last_login, failed_attempts, locked_until
                    FROM users WHERE username = ? OR email = ?
                ''', (identifier, identifier))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            log_and_notify('error', f"Error getting user by identifier {identifier}: {e}")
            return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Получает пользователя по ID."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
                user_data = cursor.fetchone()

                if user_data:
                    # Преобразуем кортеж в словарь для удобства
                    columns = [column[0] for column in cursor.description]
                    user_dict = dict(zip(columns, user_data))
                    logger.debug(f"User data retrieved: {user_dict}")
                    return user_dict
                else:
                    logger.warning(f"No user found with ID {user_id}")
                    return None
        except Exception as e:
            log_and_notify('error', f"Error getting user by ID {user_id}: {e}")
            return None

    def update_user_password(self, user_id: int, new_password_hash: str) -> bool:
        """Обновляет пароль пользователя."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, user_id))
                return cursor.rowcount > 0
        except Exception as e:
            log_and_notify('error', f"Error updating password for user {user_id}: {e}")
            return False

    def update_user_email(self, user_id: int, new_email: str) -> bool:
        """Обновляет email пользователя."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user_id))
                return cursor.rowcount > 0
        except sqlite3.IntegrityError:
            return False  # Email уже занят
        except Exception as e:
            log_and_notify('error', f"Error updating email for user {user_id}: {e}")
            return False
    
    def update_failed_attempts(self, username: str, failed: bool = True) -> None:
        """Обновляет счётчик неудачных попыток входа пользователя и блокирует аккаунт при необходимости."""
        if not username.strip():
            return
        
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT failed_attempts FROM users WHERE username = ?', (username,))
                row = cursor.fetchone()
                if not row:
                    return

                failed_attempts = row['failed_attempts']
                if failed:
                    failed_attempts += 1
                else:
                    failed_attempts = 0  # Сброс счетчика при успешном входе

                locked_until = None
                if failed_attempts >= 5:
                    locked_until = (datetime.datetime.now() + datetime.timedelta(minutes=10)).isoformat()
                    logger.warning(f"Account locked for {username} due to too many failed attempts.")

                cursor.execute('''
                    UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?
                ''', (failed_attempts, locked_until, username))
        except Exception as e:
            log_and_notify('error', f"Error updating failed attempts for '{username}': {e}")
    
    def update_last_login(self, user_id: int) -> bool:
        """Обновляет время последнего входа пользователя."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET last_login = datetime("now") WHERE id = ?', (user_id,))
                return cursor.rowcount > 0
        except Exception as e:
            log_and_notify('error', f"Error updating last login for user {user_id}: {e}")
            return False

    def get_all_users(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Получает список всех пользователей."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, username, email, created_at, last_login FROM users ORDER BY created_at DESC LIMIT ?', (limit,))
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            log_and_notify('error', f"Error getting all users: {e}")
            return []

    def delete_user(self, user_id: int) -> bool:
        """Удаляет пользователя по ID."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
                return cursor.rowcount > 0
        except Exception as e:
            log_and_notify('error', f"Error deleting user {user_id}: {e}")
            return False
            
    # --- Методы для работы со сканами (существующие) ---
    def get_scans_by_user(self, user_id: int, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Получает сканирования пользователя с пагинацией."""
        if user_id <= 0:
            return []
        
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, url, timestamp, scan_type, status, scan_duration
                    FROM scans 
                    WHERE user_id = ? 
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                ''', (user_id, limit, offset))
                rows = cursor.fetchall()
                result: List[Dict[str, Any]] = []
                for row in rows:
                    item = dict(row)
                    item['url'] = decrypt_sensitive_data_safe(
                        item.get('url', ''),
                        '[URL недоступен: ключ шифрования]',
                    )
                    result.append(item)
                return result
        except Exception as e:
            log_and_notify('error', f"Error retrieving scans for user {user_id}: {e}")
            return []
    
    def get_scan_statistics(self, user_id: int) -> Dict[str, Any]:
        """Получает статистику сканирований пользователя."""
        stats: Dict[str, Any] = {
            'total_scans': 0,
            'vulnerabilities_found': 0,
            'scan_types': {},
            'average_duration': 0.0
        }
        if user_id <= 0:
            return stats
        
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                # ... (Остальной код этого метода остаётся без изменений)
                cursor.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (user_id,))
                stats['total_scans'] = cursor.fetchone()[0]

                cursor.execute('''
                    SELECT COUNT(*) FROM vulnerabilities 
                    WHERE scan_id IN (SELECT id FROM scans WHERE user_id = ?)
                ''', (user_id,))
                stats['vulnerabilities_found'] = cursor.fetchone()[0]

                cursor.execute('''
                    SELECT scan_type, COUNT(*) as count
                    FROM scans
                    WHERE user_id = ?
                    GROUP BY scan_type
                ''', (user_id,))
                for row in cursor.fetchall():
                    stats['scan_types'][row['scan_type']] = row['count']

                cursor.execute('''
                    SELECT AVG(scan_duration) as avg_duration
                    FROM scans
                    WHERE user_id = ?
                ''', (user_id,))
                avg_row = cursor.fetchone()
                if avg_row and avg_row['avg_duration'] is not None:
                    stats['average_duration'] = round(avg_row['avg_duration'], 2)
                return stats
        except Exception as e:
            log_and_notify('error', f"Error retrieving scan statistics for user {user_id}: {e}")
            return stats

    def delete_scan(self, scan_id: int, user_id: int) -> bool:
        """Удаляет конкретное сканирование с проверкой владельца."""
        if scan_id <= 0 or user_id <= 0:
            return False
        
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
                return cursor.rowcount > 0
        except Exception as e:
            log_and_notify('error', f"Error deleting scan {scan_id}: {e}")
            return False
    
    def delete_scans_by_user(self, user_id: int) -> bool:
        """Удаляет все сканирования пользователя."""
        if user_id <= 0:
            return False
        
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM scans WHERE user_id = ?', (user_id,))
                logger.info(f"All scans for user {user_id} deleted successfully")
            return True
        except Exception as e:
            log_and_notify('error', f"Error deleting scans for user {user_id}: {e}")
            return False
        
    def is_valid_url(self, url: str) -> bool:
        """
        Проверяет корректность URL.
        
        :param url: URL для проверки
        :return: True если URL корректен, False в противном случае
        """
        try:
            # Проверка типа строки
            if not url:
                return False
                
            # Декодируем URL в байты для urlparse
            url_bytes = url.encode('utf-8')
            result = urlparse(url_bytes)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def save_scan_async(self, user_id: int, url: str, results: Optional[List[Dict[str, Any]]], scan_type: str = "general", scan_duration: float = 0.0) -> bool:
        """Сохраняет результаты сканирования в базу данных."""
        if user_id <= 0:
            log_and_notify('error', "Invalid user_id provided")
            return False
        if not url.strip():
            log_and_notify('error', "Invalid URL provided")
            return False
        # results может быть пустым списком, если уязвимостей не найдено
        if results is None:
            log_and_notify('error', "Invalid results format")
            return False

        try:
            result_json = json.dumps(results, ensure_ascii=False, separators=(',', ':'), default=str)
            if len(result_json.encode('utf-8')) > self.MAX_RESULT_SIZE:
                result_json = result_json[:int(self.MAX_RESULT_SIZE / 2)] + "..."
                logger.warning("Scan result truncated due to size limit")

            encrypted_url: str = encrypt_sensitive_data(url)
            encrypted_result: str = encrypt_sensitive_data(result_json)
        except Exception as e:
            log_and_notify('error', f"Error processing scan data for saving: {e}")
            return False

        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO scans (user_id, url, result, scan_type, scan_duration)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, encrypted_url, encrypted_result, scan_type, scan_duration))
                scan_id = cursor.lastrowid
                
                for vuln in results:
                    if 'type' in vuln and ('details' in vuln or 'description' in vuln):
                        vuln_url = vuln.get('url', url)
                        encrypted_vuln_url: str = encrypt_sensitive_data(vuln_url)

                        # Сохраняем подробное описание и отдельно — компактное
                        # место в коде (параметр/поле/метод/форма).
                        raw_details: Any = vuln.get('details', vuln.get('description', ''))
                        full_details: str
                        if isinstance(raw_details, dict):
                            full_details = vulnerability_dict_to_details(
                                cast(Dict[str, Any], raw_details)
                            )
                        elif isinstance(raw_details, list):
                            detail_items = cast(List[Any], raw_details)
                            full_details = ' | '.join(str(item) for item in detail_items)
                        else:
                            full_details = str(raw_details)
                        request_params = location_for_database(full_details) or full_details

                        cursor.execute('''
                            INSERT INTO vulnerabilities (
                                scan_id, url, type, details, status, severity,
                                description, response, request_params
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            scan_id,
                            encrypted_vuln_url,
                            vuln['type'],
                            full_details,
                            str(vuln.get('status', 'Новая')),
                            str(vuln.get('severity', 'Средний')),
                            full_details,
                            str(vuln.get('test_url', vuln.get('response', ''))),
                            request_params,
                        ))
            return True
        except Exception as e:
            log_and_notify('error', f"Error saving scan: {e}")
            return False
    
    def get_scan_by_id(self, scan_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Получает сканирование по ID с проверкой владельца."""
        if scan_id <= 0 or user_id <= 0:
            return None
        
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, user_id, url, result, timestamp, scan_type, status, scan_duration
                    FROM scans 
                    WHERE id = ? AND user_id = ?
                ''', (scan_id, user_id))
                row = cursor.fetchone()
                if row:
                    data = dict(row)
                    data['url'] = decrypt_sensitive_data_safe(
                        data.get('url', ''),
                        '[URL недоступен: ключ шифрования]',
                    )

                    decrypted_result = decrypt_sensitive_data_safe(
                        data.get('result', '[]'),
                        None,
                    )
                    if isinstance(decrypted_result, str):
                        try:
                            data['results'] = json.loads(decrypted_result)
                        except json.JSONDecodeError:
                            data['results'] = []
                    elif isinstance(decrypted_result, (dict, list)):
                        data['results'] = decrypted_result
                    else:
                        data['results'] = []

                    if 'result' in data:
                        del data['result']
                    return data
                return None
        except Exception as e:
            log_and_notify('error', f"Error getting scan {scan_id}: {e}")
            return None

    def update_scan_status(self, scan_id: int, status: str) -> bool:
        """Обновляет статус сканирования."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE scans SET status = ? WHERE id = ?
                ''', (status, scan_id))
                return cursor.rowcount > 0
        except Exception as e:
            log_and_notify('error', f"Error updating status for scan {scan_id}: {e}")
            return False

    # --- Методы для работы с найденными уязвимостями ---

    @staticmethod
    def _parse_json_field(value: Any, default: Any) -> Any:
        """Безопасно разбирает JSON-поле из БД.

        Старые записи могут содержать обычный текст вместо JSON — в этом
        случае значение возвращается как есть, чтобы подробности и место
        найденной уязвимости не терялись.
        """
        if value is None:
            return default
        if isinstance(value, (dict, list)):
            return cast(Any, value)
        text = str(value).strip()
        if not text:
            return default
        if text.startswith(("{", "[")):
            try:
                return json.loads(text)
            except (json.JSONDecodeError, TypeError):
                return text
        return text

    def _vulnerability_from_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Преобразует строку таблицы vulnerabilities в словарь для UI."""
        data = dict(row)
        data['url'] = decrypt_sensitive_data_safe(
            str(data.get('url', '')),
            '[URL недоступен: ключ шифрования]',
        )

        data['details'] = self._parse_json_field(data.get('details'), {})
        data['request_params'] = self._parse_json_field(data.get('request_params'), {})
        data['recommendations'] = self._parse_json_field(data.get('recommendations'), [])
        data['resources'] = self._parse_json_field(data.get('resources'), [])
        data['comments'] = self._parse_json_field(data.get('comments'), [])

        # Общие поля, ожидаемые интерфейсом.
        data.setdefault('description', '')
        data.setdefault('status', 'Новая')
        data.setdefault('severity', 'Средний')
        data.setdefault('response', '')
        data.setdefault('created_date', '')
        return data

    def get_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Возвращает все найденные уязвимости."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, scan_id, url, type, details, status, severity,
                           description, response, request_params, recommendations,
                           resources, comments, created_date
                    FROM vulnerabilities
                    ORDER BY id DESC
                ''')
                rows: List[Dict[str, Any]] = [dict(row) for row in cursor.fetchall()]
            return [self._vulnerability_from_row(row) for row in rows]
        except Exception as e:
            log_and_notify('error', f"Error loading vulnerabilities: {e}")
            return []

    def get_vulnerability_by_id(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        """Возвращает одну уязвимость по её ID."""
        if vuln_id <= 0:
            return None
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, scan_id, url, type, details, status, severity,
                           description, response, request_params, recommendations,
                           resources, comments, created_date
                    FROM vulnerabilities
                    WHERE id = ?
                ''', (vuln_id,))
                row = cursor.fetchone()
            return self._vulnerability_from_row(dict(row)) if row else None
        except Exception as e:
            log_and_notify('error', f"Error loading vulnerability {vuln_id}: {e}")
            return None

    def update_vulnerability_status(self, vuln_id: int, status: str) -> bool:
        """Обновляет статус уязвимости."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE vulnerabilities SET status = ? WHERE id = ?
                ''', (status, vuln_id))
                return cursor.rowcount > 0
        except Exception as e:
            log_and_notify('error', f"Error updating vulnerability status {vuln_id}: {e}")
            return False

    def add_vulnerability_comment(self, vuln_id: int, comment: str) -> bool:
        """Добавляет комментарий к уязвимости."""
        try:
            with self.get_db_connection_cm() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT comments FROM vulnerabilities WHERE id = ?', (vuln_id,))
                row = cursor.fetchone()
                if not row:
                    return False
                comments_value = self._parse_json_field(row['comments'], [])
                comments: List[Dict[str, Any]] = (
                    cast(List[Dict[str, Any]], comments_value)
                    if isinstance(comments_value, list)
                    else []
                )
                comments.append({'text': comment, 'created_date': datetime.datetime.now().isoformat()})
                cursor.execute(
                    'UPDATE vulnerabilities SET comments = ? WHERE id = ?',
                    (json.dumps(comments, ensure_ascii=False), vuln_id)
                )
                return True
        except Exception as e:
            log_and_notify('error', f"Error adding vulnerability comment {vuln_id}: {e}")
            return False

# --- Создаем единственный экземпляр класса для использования во всем приложении ---
db = Database()