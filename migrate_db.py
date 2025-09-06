#!/usr/bin/env python3
"""
Скрипт для миграции базы данных
Добавляет новые поля безопасности в существующую базу данных
"""

import sys
import os
import sqlite3
from pathlib import Path
from utils.logger import logger, log_and_notify
from utils.init_db import check_database_integrity, create_base_tables

# Добавляем текущую директорию в путь для импорта
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def migrate_scanner_db():
    """Миграция базы данных для добавления новых полей"""
    db_file = Path("scanner.db")
    
    if not db_file.exists():
        logger.info("База данных не найдена, создание новой базы данных...")
        return True
    
    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            
            # Проверяем существование поля scan_duration
            cursor.execute("PRAGMA table_info(scans)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'scan_duration' not in columns:
                logger.info("Добавление поля scan_duration в таблицу scans...")
                cursor.execute('ALTER TABLE scans ADD COLUMN scan_duration REAL DEFAULT 0.0')
                logger.info("Поле scan_duration успешно добавлено")
            else:
                logger.info("Поле scan_duration уже существует")

            # Добавляем проверку и добавление поля avatar_path
            cursor.execute("PRAGMA table_info(users)")
            user_columns = [column[1] for column in cursor.fetchall()]
            
            if 'avatar_path' not in user_columns:
                logger.info("Добавление поля avatar_path в таблицу users...")
                cursor.execute('ALTER TABLE users ADD COLUMN avatar_path TEXT')
                logger.info("Поле avatar_path успешно добавлено")
            else:
                logger.info("Поле avatar_path уже существует")
            
            # Проверяем и обновляем существующие записи
            cursor.execute("SELECT COUNT(*) FROM scans WHERE scan_duration IS NULL")
            null_count = cursor.fetchone()[0]
            
            if null_count > 0:
                logger.info(f"Обновление {null_count} записей с NULL значениями scan_duration...")
                cursor.execute("UPDATE scans SET scan_duration = 0.0 WHERE scan_duration IS NULL")
                logger.info("Записи успешно обновлены")
            
            conn.commit()
            logger.info("Миграция базы данных завершена успешно")
            return True
            
    except sqlite3.Error as e:
        logger.critical(f"Критическая ошибка работы с БД: {e}")
        return False
    except ValueError as e:
        log_and_notify('error', f"Ошибка преобразования данных: {e}")
        return False
    except KeyboardInterrupt:
        logger.warning("Миграция прервана пользователем")
        return False

def main() -> bool:
    try:
        logger.info("=== Миграция базы данных Web Scanner ===")
        logger.info("")
        
        # 1. Инициализация базы данных
        logger.info("1. Инициализация базы данных...")
        if create_base_tables():
            logger.info("   ✓ База данных инициализирована")
        else:
            log_and_notify('error', "   ✗ Ошибка инициализации базы данных")
            return False
        logger.info("")
        
        # 2. Выполнение миграции
        logger.info("2. Выполнение миграции...")
        if migrate_scanner_db():
            logger.info("   ✓ Миграция выполнена успешно")
        else:
            log_and_notify('error', "   ✗ Ошибка миграции")
            return False
        logger.info("")
        
        # 3. Проверка целостности
        logger.info("3. Проверка целостности базы данных...")
        if check_database_integrity():
            logger.info("   ✓ Целостность базы данных проверена")
        else:
            logger.warning("   ⚠ Предупреждение: некоторые поля могут отсутствовать")
        logger.info("")
        logger.info("=== Миграция завершена ===")
        logger.info("Теперь можно запускать приложение!")
        return True
        
    except KeyboardInterrupt:
        logger.warning("Миграция прервана пользователем")
        return False
    except Exception as e:
        logger.critical(f"Критическая ошибка: {e}")
        return False

if __name__ == "__main__":
    try:
        success = main()
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nМиграция прервана пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        sys.exit(1) 
