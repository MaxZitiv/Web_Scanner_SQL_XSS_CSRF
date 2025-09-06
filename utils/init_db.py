import sqlite3
import os
from utils.logger import logger, log_and_notify
from utils.database import db


def create_base_tables():
    """Создает базовые таблицы, если их не существует."""
    logger.info("Initializing database...")
    conn = None
    try:
        # DB_FILE уже содержит правильный путь от get_resource_path
        if not os.path.exists(db.db_file):
            # Создаем пустой файл, если его нет
            open(db.db_file, 'a').close()

        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        # Создаем таблицу users с базовыми полями
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Создаем таблицу scans с базовыми полями
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        
        # Создаем таблицу vulnerabilities для хранения найденных уязвимостей
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            url TEXT NOT NULL,
            type TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
        ''')
        
        # Добавляем базовые индексы
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON scans(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON scans(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_url ON vulnerabilities(url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerabilities(type)')
        
        conn.commit()
        logger.info("Database initialized successfully with basic structure")
        return True
    except (sqlite3.Error, ValueError, OSError) as e:
        log_and_notify('error', f"Error initializing database: {e}")
        return False
    finally:
        if conn is not None:
            conn.close()

def migrate_database():
    """Migrate existing database to add new security fields."""
    conn = None
    try:
        conn = sqlite3.connect('scanner.db')
        cursor = conn.cursor()
        
        # Проверяем существующие колонки в таблице users
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Добавляем недостающие колонки для безопасности в users
        new_columns = [
            ('last_login', 'TIMESTAMP'),
            ('failed_attempts', 'INTEGER DEFAULT 0'),
            ('locked_until', 'TIMESTAMP')
        ]
        
        for column_name, column_type in new_columns:
            if column_name not in columns:
                logger.info(f"[init_db] Добавляю колонку {column_name} в таблицу users...")
                try:
                    cursor.execute(f'ALTER TABLE users ADD COLUMN {column_name} {column_type}')
                    logger.info(f"[init_db] Колонка {column_name} успешно добавлена!")
                except Exception as e:
                    log_and_notify('error', f"[init_db] Ошибка при добавлении {column_name}: {e}")
        
        # Обновляем существующие записи, добавляя временные email если нужно
        if 'email' in columns:
            cursor.execute('SELECT id, username FROM users WHERE email IS NULL OR email = ""')
            users_without_email = cursor.fetchall()
            
            for user_id, username in users_without_email:
                temp_email = f"{username}@temp.local"
                try:
                    cursor.execute('UPDATE users SET email = ? WHERE id = ?', (temp_email, user_id))
                except Exception as e:
                    log_and_notify('error', f"Error updating email for user {username}: {e}")
        
        # Проверяем существующие колонки в таблице scans
        cursor.execute("PRAGMA table_info(scans)")
        scan_columns = [column[1] for column in cursor.fetchall()]
        
        # Добавляем недостающие колонки в таблицу scans
        new_scan_columns = [
            ('scan_type', 'TEXT NOT NULL DEFAULT "general"'),
            ('status', 'TEXT DEFAULT "completed"')
        ]
        
        for column_name, column_type in new_scan_columns:
            if column_name not in scan_columns:
                logger.info(f"Adding {column_name} column to scans table")
                try:
                    cursor.execute(f'ALTER TABLE scans ADD COLUMN {column_name} {column_type}')
                    logger.info(f"Successfully added {column_name} column to scans")
                except Exception as e:
                    log_and_notify('error', f"Error adding {column_name} column to scans: {e}")
        
        # Добавляем дополнительные индексы
        try:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_type ON scans(scan_type)')
            logger.info("Added scan_type index")
        except Exception as e:
            log_and_notify('error', f"Error adding scan_type index: {e}")
        
        # Проверяем существование таблицы vulnerabilities
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'")
        if not cursor.fetchone():
            logger.info("Создание таблицы vulnerabilities...")
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                type TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_url ON vulnerabilities(url)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerabilities(type)')
            logger.info("Таблица vulnerabilities успешно создана")
        
        conn.commit()
        logger.info("Database migration completed successfully")
        return True
    except (sqlite3.Error, ValueError, OSError) as e:
        log_and_notify('error', f"Error migrating database: {e}")
        return False
    finally:
        if conn is not None:
            conn.close()

def check_database_integrity():
    """Проверка целостности базы данных"""
    conn = None
    try:
        conn = sqlite3.connect('scanner.db')
        cursor = conn.cursor()
        
        # Проверяем структуру таблиц
        cursor.execute("PRAGMA table_info(users)")
        users_columns = [column[1] for column in cursor.fetchall()]
        
        cursor.execute("PRAGMA table_info(scans)")
        scans_columns = [column[1] for column in cursor.fetchall()]
        
        required_users_columns = [
            'id', 'username', 'email', 'password_hash', 'created_at'
        ]
        optional_users_columns = [
            'last_login', 'failed_attempts', 'locked_until'
        ]
        required_scans_columns = [
            'id', 'user_id', 'url', 'result', 'timestamp'
        ]
        optional_scans_columns = [
            'scan_type', 'status'
        ]
        
        users_required_ok = all(col in users_columns for col in required_users_columns)
        scans_required_ok = all(col in scans_columns for col in required_scans_columns)
        
        users_optional = [col for col in optional_users_columns if col in users_columns]
        scans_optional = [col for col in optional_scans_columns if col in scans_columns]
        
        if users_required_ok and scans_required_ok:
            logger.info("Database integrity check passed")
            logger.info(f"Optional users columns present: {users_optional}")
            logger.info(f"Optional scans columns present: {scans_optional}")
            return True
        else:
            missing_users = [col for col in required_users_columns if col not in users_columns]
            missing_scans = [col for col in required_scans_columns if col not in scans_columns]
            logger.warning(f"Database integrity check failed. Missing required users columns: {missing_users}, Missing required scans columns: {missing_scans}")
            return False
            
    except (sqlite3.Error, ValueError, OSError) as e:
        log_and_notify('error', f"Error checking database integrity: {e}")
        return False
    finally:
        if conn is not None:
            conn.close()

def reset_database():
    """Сброс базы данных (только для разработки)"""
    conn = None
    try:
        if os.path.exists('scanner.db'):
            os.remove('scanner.db')
            logger.info("Old database removed")
        
        if os.path.exists('scanner.db-wal'):
            os.remove('scanner.db-wal')
        
        if os.path.exists('scanner.db-shm'):
            os.remove('scanner.db-shm')
        
        # Создаем новую базу данных
        create_base_tables()
        logger.info("Database reset completed")
        return True
    except (sqlite3.Error, ValueError, OSError) as e:
        log_and_notify('error', f"Error resetting database: {e}")
        return False
    finally:
        if conn is not None:
            conn.close()

if __name__ == "__main__":
    logger.info("Initializing database...")
    create_base_tables()
    logger.info("Migrating database...")
    migrate_database()
    logger.info("Checking database integrity...")
    check_database_integrity()
    logger.info("Database setup completed!")
