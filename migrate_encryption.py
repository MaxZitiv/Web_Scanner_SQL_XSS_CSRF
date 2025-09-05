#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Скрипт для миграции существующих данных в зашифрованном виде.
Этот скрипт шифрует все существующие результаты сканирования и URL в базе данных.
"""

import sqlite3
import json
import os
import sys
from typing import List, Dict, Optional
from utils.logger import logger, log_and_notify
from utils.encryption import get_encryption, encrypt_sensitive_data
from utils.database import db

def get_db_path() -> str:
    """Получает путь к базе данных"""
    return db.get_resource_path("scanner.db")

def is_already_encrypted(data: str) -> bool:
    """Проверяет, зашифрованы ли уже данные"""
    try:
        # Пытаемся распарсить как JSON (незашифрованные данные)
        json.loads(data)
        return False
    except (json.JSONDecodeError, TypeError):
        # Если не JSON, то вероятно уже зашифрованы
        return True

def migrate_scan_data() -> bool:
    """
    Мигрирует данные сканирования в зашифрованном виде.
    
    Returns:
        bool: True если миграция прошла успешно
    """
    try:
        db_path = get_db_path()
        if not os.path.exists(db_path):
            log_and_notify('error', f"Database file not found: {db_path}")
            return False
        
        logger.info("Starting encryption migration...")
        
        # Подключаемся к базе данных
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Получаем все записи сканирования
        cursor.execute('SELECT id, url, result FROM scans')
        rows = cursor.fetchall()
        
        if not rows:
            logger.info("No scan data found to migrate")
            return True
        
        logger.info(f"Found {len(rows)} scan records to migrate")
        
        migration_count = 0
        error_count = 0
        
        for row in rows:
            scan_id, url, result = row
            
            try:
                needs_migration = False
                new_url = url
                new_result = result
                
                # Проверяем, нужно ли шифровать URL
                if not is_already_encrypted(url):
                    new_url = encrypt_sensitive_data(url)
                    needs_migration = True
                    logger.debug(f"Encrypting URL for scan {scan_id}")
                
                # Проверяем, нужно ли шифровать результаты
                if not is_already_encrypted(result):
                    # Парсим JSON для проверки
                    try:
                        result_data = json.loads(result) if result else []
                        new_result = encrypt_sensitive_data(result_data)
                        needs_migration = True
                        logger.debug(f"Encrypting results for scan {scan_id}")
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON in scan {scan_id}, skipping")
                        continue
                
                # Обновляем запись, если нужно
                if needs_migration:
                    cursor.execute(
                        'UPDATE scans SET url = ?, result = ? WHERE id = ?',
                        (new_url, new_result, scan_id)
                    )
                    migration_count += 1
                    
                    if migration_count % 10 == 0:
                        logger.info(f"Migrated {migration_count} records...")
                
            except Exception as e:
                log_and_notify('error', f"Error migrating scan {scan_id}: {e}")
                error_count += 1
                continue
        
        # Сохраняем изменения
        conn.commit()
        conn.close()
        
        logger.info(f"Migration completed: {migration_count} records migrated, {error_count} errors")
        return error_count == 0
        
    except Exception as e:
        log_and_notify('error', f"Migration failed: {e}")
        return False

def verify_migration() -> bool:
    """
    Проверяет, что миграция прошла успешно.
    
    Returns:
        bool: True если все данные зашифрованы
    """
    try:
        db_path = get_db_path()
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, url, result FROM scans LIMIT 10')
        rows = cursor.fetchall()
        
        if not rows:
            logger.info("No data to verify")
            return True
        
        all_encrypted = True
        
        for row in rows:
            scan_id, url, result = row
            
            if not is_already_encrypted(url):
                logger.warning(f"URL for scan {scan_id} is not encrypted")
                all_encrypted = False
            
            if not is_already_encrypted(result):
                logger.warning(f"Results for scan {scan_id} are not encrypted")
                all_encrypted = False
        
        conn.close()
        
        if all_encrypted:
            logger.info("Verification passed: all data is encrypted")
        else:
            logger.warning("Verification failed: some data is not encrypted")
        
        return all_encrypted
        
    except Exception as e:
        log_and_notify('error', f"Verification failed: {e}")
        return False

def main():
    """Главная функция миграции"""
    print("=== Database Encryption Migration ===")
    print("This script will encrypt all existing scan data in the database.")
    print("Make sure to backup your database before proceeding!")
    
    response = input("Do you want to continue? (y/N): ").strip().lower()
    if response != 'y':
        print("Migration cancelled.")
        return
    
    print("\nStarting migration...")
    
    # Выполняем миграцию
    if migrate_scan_data():
        print("✓ Migration completed successfully!")
        
        # Проверяем результат
        print("\nVerifying migration...")
        if verify_migration():
            print("✓ Verification passed!")
            print("\nAll scan data has been successfully encrypted.")
        else:
            print("⚠ Verification failed. Some data may not be encrypted.")
    else:
        print("✗ Migration failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 