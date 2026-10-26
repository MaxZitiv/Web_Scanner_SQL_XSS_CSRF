#!/usr/bin/env python3

import base64
import json
from pathlib import Path
from threading import Lock
from typing import Any

from cryptography.fernet import Fernet

from utils.key_storage import load_master_key
from utils.logger import log_and_notify, logger


class DatabaseEncryption:
    """
    Класс для шифрования чувствительных данных в базе данных.
    Использует Fernet и случайный 32-байтовый ключ.
    Аргумент master_key — готовый ключ в base64, а не пароль.
    """

    def __init__(
        self, master_key: str | None = None, *, key_path: str | Path | None = None, create_key: bool = True
    ) -> None:
        # Сохраняем путь/формат существующих ключей. Ошибки чтения не являются
        # разрешением на замену ключа или получение его из имени компьютера.
        self.master_key = master_key if master_key is not None else load_master_key(key_path, create=create_key)
        self.fernet = self._create_fernet()
        logger.info("Database encryption system initialized")

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
            log_and_notify("error", f"Error creating Fernet instance: {e}")
            raise

    def encrypt_data(self, data: str | dict[str, Any] | list[Any]) -> str:
        """
        Шифрует данные.

        Args:
            data: Данные для шифрования (строка, словарь или список)

        Returns:
            str: Зашифрованные данные в base64
        """
        try:
            # Преобразуем данные в JSON строку
            json_data = json.dumps(data, ensure_ascii=False) if isinstance(data, (dict, list)) else str(data)

            # Шифруем
            encrypted_bytes = self.fernet.encrypt(json_data.encode("utf-8"))
            return base64.urlsafe_b64encode(encrypted_bytes).decode()

        except Exception as e:
            log_and_notify("error", f"Error encrypting data: {e}")
            raise

    def decrypt_data(self, encrypted_data: str) -> str | dict[str, Any] | list[Any]:
        """
        Расшифровывает данные.

        Args:
            encrypted_data: Зашифрованные данные в base64

        Returns:
            Union[str, dict, list]: Расшифрованные данные
        """
        try:
            # Старые записи используют дополнительную обёртку base64.
            # Поддерживаем также стандартный токен Fernet без этой обёртки.
            token = encrypted_data.strip().encode("ascii")
            if not token.startswith(b"gAAAA"):
                token = base64.b64decode(token, altchars=b"-_", validate=True)
            decrypted_bytes = self.fernet.decrypt(token)
            json_data = decrypted_bytes.decode("utf-8")

            # Пытаемся распарсить как JSON
            try:
                return json.loads(json_data)
            except json.JSONDecodeError:
                # Если не JSON, возвращаем как строку
                return json_data

        except Exception as e:
            log_and_notify("error", f"Error decrypting data: {e}")
            raise

    def encrypt_scan_results(self, results: list[dict[str, Any]]) -> str:
        """
        Шифрует результаты сканирования.

        Args:
            results: Список результатов сканирования

        Returns:
            str: Зашифрованные результаты
        """
        return self.encrypt_data(results)

    def decrypt_scan_results(self, encrypted_results: str) -> list[dict[str, Any]]:
        """
        Расшифровывает результаты сканирования.

        Args:
            encrypted_results: Зашифрованные результаты

        Returns:
            list: Расшифрованные результаты
        """
        decrypted: str | dict[str, Any] | list[Any] = self.decrypt_data(encrypted_results)
        if isinstance(decrypted, list):
            return decrypted
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

    @staticmethod
    def is_encrypted(data: str) -> bool:
        """
        Проверяет, зашифрованы ли данные.

        Args:
            data: Данные для проверки

        Returns:
            bool: True, если данные зашифрованы
        """
        return looks_like_encrypted(data)


# Глобальный экземпляр шифрования
_encryption_instance: DatabaseEncryption | None = None
_encryption_lock = Lock()


def get_encryption(*, create_key: bool = True) -> DatabaseEncryption:
    """
    Получает глобальный экземпляр шифрования.

    Returns:
        DatabaseEncryption: Экземпляр шифрования
    """
    global _encryption_instance
    with _encryption_lock:
        if _encryption_instance is None:
            _encryption_instance = DatabaseEncryption(create_key=create_key)
        return _encryption_instance


def encrypt_sensitive_data(data: str | dict[str, Any] | list[Any]) -> str:
    """
    Шифрует чувствительные данные.

    Args:
        data: Данные для шифрования

    Returns:
        str: Зашифрованные данные
    """
    return get_encryption().encrypt_data(data)


def decrypt_sensitive_data(encrypted_data: str) -> str | dict[str, Any] | list[Any]:
    """
    Расшифровывает чувствительные данные.

    Args:
        encrypted_data: Зашифрованные данные

    Returns:
        Union[str, dict, list]: Расшифрованные данные
    """
    return get_encryption(create_key=False).decrypt_data(encrypted_data)


def looks_like_encrypted(data: Any) -> bool:
    """Распознаёт структуру Fernet, а не произвольную строку в base64."""
    if not isinstance(data, str) or not data:
        return False
    try:
        raw = base64.b64decode(data.strip().encode("ascii"), altchars=b"-_", validate=True)
        if raw.startswith(b"gAAAA"):
            raw = base64.b64decode(raw, altchars=b"-_", validate=True)
        # Версия, timestamp, IV, хотя бы один блок ciphertext и HMAC.
        return len(raw) >= 73 and raw[0] == 0x80 and (len(raw) - 57) % 16 == 0
    except ValueError:
        return False


def decrypt_sensitive_data_safe(
    data: Any,
    default: Any = None,
) -> str | dict[str, Any] | list[Any] | Any:
    """Безопасно расшифровывает значение.

    Если значение не выглядит зашифрованным, возвращает его как есть.
    Если расшифровка невозможна (сменился ключ/перенесена БД без .db_key),
    возвращает ``default`` (или исходное открытое значение), не перебрасывая
    исключение в место, которое открывает список уязвимостей. Это устраняет
    задержку и ошибки при просмотре старых сканирований.
    """
    if data is None:
        return default
    text = str(data)
    if not looks_like_encrypted(text):
        return text
    try:
        return get_encryption(create_key=False).decrypt_data(text)
    except Exception as e:
        logger.debug(f"Safe decrypt skipped for old/incompatible value: {e}")
        if default is not None:
            return default
        # Для URL-подобных значений возвращаем исходное значение.
        if text.startswith(("http://", "https://")):
            return text
        return "[значение недоступно — требуется .db_key]"
