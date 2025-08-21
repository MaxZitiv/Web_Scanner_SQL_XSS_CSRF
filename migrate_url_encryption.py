#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Скрипт миграции для шифрования URL в существующих записях базы данных.
Этот скрипт шифрует URL в таблице scans, которые еще не зашифрованы.
"""

import sqlite3
import os
import sys
from utils.logger import setup_logger
from utils.encryption import get_encryption
from utils.database import get_db_connection

logger = setup_logger('migrate_url_encryption', filename='migrate_url_encryption.log')

def is_already_encrypted(data: str) -> bool:
    """
    Проверяет, зашифрованы ли данные.
    
    Args:
        data: Данные для проверки
        
    Returns:
        bool: True, если данные зашифрованы
    """
    if not data:
        return False
    
    try:
        # Используем функцию из utils.encryption
        encryption = get_encryption()
        return encryption.is_encrypted(data)
    except Exception:
        return False

def migrate_url_encryption() -> bool:
    """
    Мигрирует URL в таблице scans, шифруя те, которые еще не зашифрованы.
    
    Returns:
        bool: True если миграция прошла успешно
    """
    try:
        logger.info("Starting URL encryption migration...")
        
        # Получаем соединение с базой данных
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Получаем все записи из таблицы scans
        cursor.execute('SELECT id, url FROM scans')
        rows = cursor.fetchall()
        
        if not rows:
            logger.info("No scans found in database")
            return True
        
        logger.info(f"Found {len(rows)} scans to process")
        
        # Получаем экземпляр шифрования
        encryption = get_encryption()
        
        migration_count = 0
        error_count = 0
        
        for row in rows:
            scan_id, url = row
            
            try:
                # Проверяем, нужно ли шифровать URL
                if not is_already_encrypted(url):
                    encrypted_url = encryption.encrypt_url(url)
                    
                    # Обновляем запись
                    cursor.execute(
                        'UPDATE scans SET url = ? WHERE id = ?',
                        (encrypted_url, scan_id)
                    )
                    migration_count += 1
                    logger.debug(f"Encrypted URL for scan {scan_id}")
                else:
                    logger.debug(f"URL for scan {scan_id} is already encrypted")
                
                # Обновляем прогресс каждые 10 записей
                if migration_count % 10 == 0:
                    logger.info(f"Migrated {migration_count} records...")
                
            except Exception as e:
                logger.error(f"Error migrating scan {scan_id}: {e}", exc_info=True)
                error_count += 1
                continue
        
        # Сохраняем изменения
        conn.commit()
        conn.close()
        
        logger.info(f"URL encryption migration completed:")
        logger.info(f"  - Total records processed: {len(rows)}")
        logger.info(f"  - Records migrated: {migration_count}")
        logger.info(f"  - Errors: {error_count}")
        
        return error_count == 0
        
    except Exception as e:
        logger.error(f"Error in URL encryption migration: {e}", exc_info=True)
        return False

def migrate_vulnerabilities_url_encryption() -> bool:
    """
    Мигрирует URL в таблице vulnerabilities, шифруя те, которые еще не зашифрованы.
    
    Returns:
        bool: True если миграция прошла успешно
    """
    try:
        logger.info("Starting vulnerabilities URL encryption migration...")
        
        # Получаем соединение с базой данных
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Получаем все записи из таблицы vulnerabilities
        cursor.execute('SELECT id, url FROM vulnerabilities')
        rows = cursor.fetchall()
        
        if not rows:
            logger.info("No vulnerabilities found in database")
            return True
        
        logger.info(f"Found {len(rows)} vulnerabilities to process")
        
        # Получаем экземпляр шифрования
        encryption = get_encryption()
        
        migration_count = 0
        error_count = 0
        
        for row in rows:
            vuln_id, url = row
            
            try:
                # Проверяем, нужно ли шифровать URL
                if not is_already_encrypted(url):
                    encrypted_url = encryption.encrypt_url(url)
                    
                    # Обновляем запись
                    cursor.execute(
                        'UPDATE vulnerabilities SET url = ? WHERE id = ?',
                        (encrypted_url, vuln_id)
                    )
                    migration_count += 1
                    logger.debug(f"Encrypted URL for vulnerability {vuln_id}")
                else:
                    logger.debug(f"URL for vulnerability {vuln_id} is already encrypted")
                
                # Обновляем прогресс каждые 10 записей
                if migration_count % 10 == 0:
                    logger.info(f"Migrated {migration_count} vulnerability records...")
                
            except Exception as e:
                logger.error(f"Error migrating vulnerability {vuln_id}: {e}", exc_info=True)
                error_count += 1
                continue
        
        # Сохраняем изменения
        conn.commit()
        conn.close()
        
        logger.info(f"Vulnerabilities URL encryption migration completed:")
        logger.info(f"  - Total records processed: {len(rows)}")
        logger.info(f"  - Records migrated: {migration_count}")
        logger.info(f"  - Errors: {error_count}")
        
        return error_count == 0
        
    except Exception as e:
        logger.error(f"Error in vulnerabilities URL encryption migration: {e}", exc_info=True)
        return False

def main():
    """Основная функция для запуска миграции"""
    try:
        print("🔐 URL Encryption Migration Tool")
        print("=" * 50)
        
        # Проверяем существование базы данных
        if not os.path.exists('scanner.db'):
            print("❌ Database file 'scanner.db' not found!")
            return False
        
        print("📊 Starting URL encryption migration...")
        
        # Мигрируем URL в таблице scans
        scans_success = migrate_url_encryption()
        if not scans_success:
            print("❌ Failed to migrate scans URLs")
            return False
        
        # Мигрируем URL в таблице vulnerabilities
        vulns_success = migrate_vulnerabilities_url_encryption()
        if not vulns_success:
            print("❌ Failed to migrate vulnerabilities URLs")
            return False
        
        print("✅ URL encryption migration completed successfully!")
        print("🔒 All URLs are now encrypted in the database.")
        print("👤 Authorized users will see decrypted URLs in the interface.")
        print("🔐 Unauthorized users will see encrypted URLs.")
        
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        logger.error(f"Migration failed: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 