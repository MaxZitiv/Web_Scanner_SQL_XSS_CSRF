#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import base64
import hashlib
from cryptography.fernet import Fernet
from typing import Optional, Union, List, Dict, Any
import json
from utils.logger import logger, log_and_notify

class DatabaseEncryption:
    """
    Класс для шифрования чувствительных данных в базе данных.
    Использует Fernet (симметричное шифрование) с ключом, 
    производным от мастер-пароля приложения.
    """
    
    def __init__(self, master_key: Optional[str] = None):
        """
        Инициализация системы шифрования.
        
        Args:
            master_key: Мастер-ключ для шифрования. Если не указан, 
                       используется системный ключ или создается новый.
        """
        self.master_key = master_key or self._get_or_create_master_key()
        self.fernet = self._create_fernet()
        logger.info("Database encryption system initialized")
    
    def _get_or_create_master_key(self) -> str:
        """
        Получает существующий мастер-ключ или создает новый.
        
        Returns:
            str: Мастер-ключ
        """
        # Путь к файлу с ключом
        key_file = os.path.join(os.path.dirname(__file__), '..', '.db_key')
        
        try:
            # Пытаемся прочитать существующий ключ
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    key_data = f.read()
                    if len(key_data) >= 32:  # Минимальная длина ключа
                        logger.info("Using existing master key")
                        return base64.urlsafe_b64encode(key_data[:32]).decode()
            
            # Создаем новый ключ
            new_key = os.urandom(32)
            with open(key_file, 'wb') as f:
                f.write(new_key)
            
            # Устанавливаем права доступа только для владельца
            try:
                os.chmod(key_file, 0o600)
                # Проверяем, что права доступа установлены корректно
                file_stat = os.stat(key_file)
                if file_stat.st_mode & 0o777 != 0o600:
                    logger.warning(f"Key file permissions are not restrictive: {oct(file_stat.st_mode & 0o777)}")
                    # Повторная попытка установки прав
                    try:
                        os.chmod(key_file, 0o600)
                    except OSError:
                        logger.error("Failed to set restrictive permissions on key file")
            except OSError as e:
                logger.error(f"Could not set restrictive permissions on key file: {e}")
            
            logger.info("Created new master key")
            return base64.urlsafe_b64encode(new_key).decode()
            
        except Exception as e:
            log_and_notify('error', f"Error managing master key: {e}")
            # Fallback: используем системный ключ
            return self._generate_system_key()
    
    def _generate_system_key(self) -> str:
        """
        Генерирует ключ на основе системной информации.
        
        Returns:
            str: Системный ключ
        """
        # Используем комбинацию системной информации для создания ключа
        system_info = [
            os.getenv('USERNAME', ''),
            os.getenv('COMPUTERNAME', ''),
            os.path.expanduser('~'),
            os.getcwd()
        ]
        
        key_material = '|'.join(system_info).encode('utf-8')
        key_hash = hashlib.sha256(key_material).digest()
        
        logger.info("Generated system-based key")
        return base64.urlsafe_b64encode(key_hash).decode()
    
    def _create_fernet(self) -> Fernet:
        """
        Создает экземпляр Fernet для шифрования.
        
        Returns:
            Fernet: Экземпляр шифровальщика
        """
        try:
            # Декодируем мастер-ключ
            key_bytes = base64.urlsafe_b64decode(self.master_key.encode())
            
            # Создаем Fernet ключ
            fernet_key = base64.urlsafe_b64encode(key_bytes)
            return Fernet(fernet_key)
            
        except Exception as e:
            log_and_notify('error', f"Error creating Fernet instance: {e}")
            raise
    
    def encrypt_data(self, data: Union[str, Dict[str, Any], List[Any]]) -> str:
        """
        Шифрует данные.
        
        Args:
            data: Данные для шифрования (строка, словарь или список)
            
        Returns:
            str: Зашифрованные данные в base64
        """
        try:
            # Преобразуем данные в JSON строку
            if isinstance(data, (Dict, List)):
                json_data = json.dumps(data, ensure_ascii=False)
            else:
                json_data = str(data)  # type: ignore[arg-type]
            
            # Шифруем
            encrypted_bytes = self.fernet.encrypt(json_data.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted_bytes).decode()
            
        except Exception as e:
            log_and_notify('error', f"Error encrypting data: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str) -> Union[str, Dict[str, Any], List[Any]]:
        """
        Расшифровывает данные.
        
        Args:
            encrypted_data: Зашифрованные данные в base64
            
        Returns:
            Union[str, dict, list]: Расшифрованные данные
        """
        try:
            # Декодируем из base64
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            
            # Расшифровываем
            decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
            json_data = decrypted_bytes.decode('utf-8')
            
            # Пытаемся распарсить как JSON
            try:
                return json.loads(json_data)
            except json.JSONDecodeError:
                # Если не JSON, возвращаем как строку
                return json_data
                
        except Exception as e:
            log_and_notify('error', f"Error decrypting data: {e}")
            raise
    
    def encrypt_scan_results(self, results: List[Dict[str, Any]]) -> str:
        """
        Шифрует результаты сканирования.
        
        Args:
            results: Список результатов сканирования
            
        Returns:
            str: Зашифрованные результаты
        """
        return self.encrypt_data(results)
    
    def decrypt_scan_results(self, encrypted_results: str) -> List[Dict[str, Any]]:
        """
        Расшифровывает результаты сканирования.
        
        Args:
            encrypted_results: Зашифрованные результаты
            
        Returns:
            list: Расшифрованные результаты
        """
        decrypted: Union[str, Dict[str, Any], List[Any]] = self.decrypt_data(encrypted_results)
        if isinstance(decrypted, List):
            return decrypted  # type: ignore[return-value]
        else:
            logger.warning("Decrypted data is not a list, returning empty list")
            return []
    
    def encrypt_url(self, url: str) -> str:
        """
        Шифрует URL.
        
        Args:
            url: URL для шифрования
            
        Returns:
            str: Зашифрованный URL
        """
        return self.encrypt_data(url)
    
    def decrypt_url(self, encrypted_url: str) -> str:
        """
        Расшифровывает URL.
        
        Args:
            encrypted_url: Зашифрованный URL
            
        Returns:
            str: Расшифрованный URL
        """
        decrypted = self.decrypt_data(encrypted_url)
        return str(decrypted)
    
    def is_encrypted(self, data: str) -> bool:
        """
        Проверяет, зашифрованы ли данные.
        
        Args:
            data: Данные для проверки
            
        Returns:
            bool: True, если данные зашифрованы
        """
        try:
            # Пытаемся декодировать как base64
            base64.urlsafe_b64decode(data.encode())
            return True
        except Exception:
            return False

# Глобальный экземпляр шифрования
_encryption_instance: Optional[DatabaseEncryption] = None

def get_encryption() -> DatabaseEncryption:
    """
    Получает глобальный экземпляр шифрования.
    
    Returns:
        DatabaseEncryption: Экземпляр шифрования
    """
    global _encryption_instance
    if _encryption_instance is None:
        _encryption_instance = DatabaseEncryption()
    return _encryption_instance

def encrypt_sensitive_data(data: Union[str, Dict[str, Any], List[Any]]) -> str:
    """
    Шифрует чувствительные данные.
    
    Args:
        data: Данные для шифрования
        
    Returns:
        str: Зашифрованные данные
    """
    return get_encryption().encrypt_data(data)

def decrypt_sensitive_data(encrypted_data: str) -> Union[str, Dict[str, Any], List[Any]]:
    """
    Расшифровывает чувствительные данные.
    
    Args:
        encrypted_data: Зашифрованные данные
        
    Returns:
        Union[str, dict, list]: Расшифрованные данные
    """
    return get_encryption().decrypt_data(encrypted_data) 