from utils.database import db
from utils.logger import logger, log_and_notify
from typing import List, Dict, Optional, Any
import sqlite3
from utils.security import validate_input_length, is_safe_url
from models.scan_result_model import ScanResult, Vulnerability


class ScanModel:
    """
    Модель для работы с результатами сканирования.
    Предоставляет методы для сохранения, получения и удаления сканирований.
    """
    
    def __init__(self):
        self.conn = db.get_db_connection()
        logger.info('ScanModel initialized')

    @staticmethod
    def save_scan_result(user_id: int, url: str, results: List[Dict[str, Any]], scan_type: str = "general", scan_duration: float = 0.0) -> bool:
        """
        Сохраняет результат сканирования в базу данных.

        Args:
            user_id: ID пользователя
            url: URL сканируемого сайта
            results: Результаты сканирования
            scan_type: Тип сканирования (по умолчанию "general")
            scan_duration: Длительность сканирования в секундах

        Returns:
            bool: True если сохранение прошло успешно
        """
        try:
            # Валидация входных параметров
            if user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {user_id}")
                return False

            if not validate_input_length(url, 1, 2048):
                log_and_notify('error', f"Invalid URL length: {len(url) if url else 0}")
                return False

            if not is_safe_url(url):
                logger.warning(f"Potentially unsafe URL: {url}")

            # Сохраняем результат
            success = db.save_scan_async(user_id, url, results, scan_type, scan_duration)

            if success:
                logger.info(f'Scan result saved for user {user_id} and url {url}')
            else:
                log_and_notify('error', f'Failed to save scan result for user {user_id}')

            return success

        except (sqlite3.Error, ValueError, KeyError, AttributeError) as e:
            log_and_notify('error', f'Error saving scan result: {e}')
            return False
            
    @staticmethod
    def save_scan_result_object(scan_result: ScanResult) -> bool:
        """
        Сохраняет результат сканирования в базу данных, используя датакласс ScanResult.

        Args:
            scan_result: Объект ScanResult с данными о сканировании

        Returns:
            bool: True если сохранение прошло успешно
        """
        try:
            # Валидация входных параметров
            if scan_result.user_id is None or scan_result.user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {scan_result.user_id}")
                return False

            if not validate_input_length(scan_result.url, 1, 2048):
                log_and_notify('error', f"Invalid URL length: {len(scan_result.url)}")
                return False

            if not is_safe_url(scan_result.url):
                logger.warning(f"Potentially unsafe URL: {scan_result.url}")

            # Преобразуем уязвимости в формат словаря для сохранения в БД
            vulnerabilities_dict = [vuln.to_dict() for vuln in scan_result.vulnerabilities]

            # Сохраняем результат
            success = db.save_scan_async(
                scan_result.user_id, 
                scan_result.url, 
                vulnerabilities_dict, 
                scan_result.scan_type, 
                scan_result.scan_duration
            )

            if success:
                logger.info(f'Scan result saved for user {scan_result.user_id} and url {scan_result.url}')
            else:
                log_and_notify('error', f'Failed to save scan result for user {scan_result.user_id}')

            return success

        except (sqlite3.Error, ValueError, KeyError, AttributeError) as e:
            log_and_notify('error', f'Error saving scan result: {e}')
            return False
        """
        Args:
            user_id: ID пользователя
            url: URL сканируемого сайта
            results: Результаты сканирования
            scan_type: Тип сканирования (по умолчанию "general")
            scan_duration: Длительность сканирования в секундах
        
        Returns:
            bool: True если сохранение прошло успешно
        """
        try:
            # Валидация входных параметров
            if user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {user_id}")
                return False
            
            if not validate_input_length(url, 1, 2048):
                log_and_notify('error', f"Invalid URL length: {len(url) if url else 0}")
                return False
            
            if not is_safe_url(url):
                logger.warning(f"Potentially unsafe URL: {url}")
            

            
            # Сохраняем результат
            success = db.save_scan_async(user_id, url, results, scan_type, scan_duration)
            
            if success:
                logger.info(f'Scan result saved for user {user_id} and url {url}')
            else:
                log_and_notify('error', f'Failed to save scan result for user {user_id}')
            
            return success
            
        except (sqlite3.Error, ValueError, KeyError, AttributeError) as e:
            log_and_notify('error', f'Error saving scan result: {e}')
            return False

    @staticmethod
    def get_user_scans(user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Получает сканирования пользователя с ограничением.

        Args:
            user_id: ID пользователя
            limit: Максимальное количество сканирований (по умолчанию 50)

        Returns:
            List[Dict]: Список сканирований
        """
        try:
            # Валидация входных параметров
            if user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {user_id}")
                return []

            if limit <= 0 or limit > 100:
                limit = 50

            scans = db.get_scans_by_user(user_id)
            logger.info(f'Retrieved {len(scans)} scans for user {user_id}')
            return scans[:limit]

        except (sqlite3.Error, ValueError, KeyError, AttributeError) as e:
            log_and_notify('error', f'Error retrieving user scans: {e}')
            return []
            
    @staticmethod
    def get_user_scan_objects(user_id: int, limit: int = 50) -> List[ScanResult]:
        """
        Получает сканирования пользователя с ограничением в виде объектов ScanResult.

        Args:
            user_id: ID пользователя
            limit: Максимальное количество сканирований (по умолчанию 50)

        Returns:
            List[ScanResult]: Список сканирований
        """
        try:
            # Валидация входных параметров
            if user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {user_id}")
                return []

            if limit <= 0 or limit > 100:
                limit = 50

            scans = db.get_scans_by_user(user_id)
            logger.info(f'Retrieved {len(scans)} scans for user {user_id}')
            
            # Преобразуем словари в объекты ScanResult
            scan_objects = []
            for scan_data in scans[:limit]:
                scan_objects.append(ScanResult.from_dict(scan_data))
                
            return scan_objects

        except (sqlite3.Error, ValueError, KeyError, AttributeError) as e:
            log_and_notify('error', f'Error retrieving user scans: {e}')
            return []
        
    @staticmethod
    def delete_scan_result(scan_id: int, user_id: int) -> bool:
        """
        Удаляет конкретное сканирование с проверкой владельца.
        
        Args:
            scan_id: ID сканирования
            user_id: ID пользователя (для проверки владельца)
        
        Returns:
            bool: True если удаление прошло успешно
        """
        try:
            # Валидация входных параметров
            if scan_id <= 0:
                log_and_notify('error', f"Invalid scan_id: {scan_id}")
                return False
            
            if user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {user_id}")
                return False
            
            success = db.delete_scan(scan_id, user_id)
            
            if success:
                logger.info(f'Scan {scan_id} deleted successfully by user {user_id}')
            else:
                logger.warning(f'Failed to delete scan {scan_id} by user {user_id}')
            
            return success
            
        except (sqlite3.Error, ValueError, KeyError, AttributeError) as e:
            log_and_notify('error', f'Error deleting scan {scan_id}: {e}')
            return False

    @staticmethod
    def delete_user_scans(user_id: int) -> bool:
        """
        Удаляет все сканирования пользователя.
        
        Args:
            user_id: ID пользователя
        
        Returns:
            bool: True если удаление прошло успешно
        """
        try:
            # Валидация входных параметров
            if user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {user_id}")
                return False
            
            success = db.delete_scans_by_user(user_id)
            
            if success:
                logger.info(f'All scans for user {user_id} deleted successfully')
            else:
                log_and_notify('error', f'Failed to delete scans for user {user_id}')
            
            return success
            
        except (sqlite3.Error, ValueError, KeyError, AttributeError) as e:
            log_and_notify('error', f'Error deleting scans for user {user_id}: {e}')
            return False

    @staticmethod
    def get_scan_statistics(user_id: int) -> Dict[str, Any]:
        """
        Получает статистику сканирований пользователя.
        
        Args:
            user_id: ID пользователя
        
        Returns:
            Dict: Статистика сканирований
        """
        try:
            # Валидация входных параметров
            if user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {user_id}")
                return {}
            
            stats = db.get_scan_statistics(user_id)
            logger.info(f'Retrieved scan statistics for user {user_id}')
            return stats
            
        except (sqlite3.Error, ValueError, KeyError, AttributeError) as e:
            log_and_notify('error', f'Error getting scan statistics: {e}')
            return {}

    @staticmethod
    def get_scan_by_id(scan_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Получает конкретное сканирование по ID с проверкой владельца.
        
        Args:
            scan_id: ID сканирования
            user_id: ID пользователя (для проверки владельца)
        
        Returns:
            Optional[Dict]: Данные сканирования или None
        """
        try:
            from utils.database import db
            
            # Валидация входных параметров
            if scan_id <= 0:
                log_and_notify('error', f"Invalid scan_id: {scan_id}")
                return None
            
            if user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {user_id}")
                return None
            
            scan = db.get_scan_by_id(scan_id, user_id)
            
            if scan:
                logger.info(f'Retrieved scan {scan_id} for user {user_id}')
            else:
                logger.warning(f'Scan {scan_id} not found or not owned by user {user_id}')
            
            return scan
            
        except (sqlite3.Error, ValueError, KeyError, AttributeError) as e:
            log_and_notify('error', f'Error getting scan {scan_id}: {e}')
            return None

    def get_recent_scans(self, user_id: int, days: int = 7) -> List[Dict[str, Any]]:
        """
        Получает недавние сканирования пользователя.
        
        Args:
            user_id: ID пользователя
            days: Количество дней для фильтрации (по умолчанию 7)
        
        Returns:
            List[Dict]: Список недавних сканирований
        """
        try:
            # Валидация входных параметров
            if user_id <= 0:
                log_and_notify('error', f"Invalid user_id: {user_id}")
                return []
            
            if days <= 0 or days > 365:
                days = 7
            
            # Получаем все сканирования и фильтруем по дате
            all_scans = self.get_user_scans(user_id, limit=1000)
            
            import datetime
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days)
            
            recent_scans: List[Dict[str, Any]] = []
            for scan in all_scans:
                try:
                    scan_date = datetime.datetime.strptime(scan['timestamp'], '%Y-%m-%d %H:%M:%S')
                    if scan_date >= cutoff_date:
                        recent_scans.append(scan)
                except (ValueError, KeyError):
                    continue
            
            logger.info(f'Retrieved {len(recent_scans)} recent scans for user {user_id}')
            return recent_scans
            
        except Exception as e:
            log_and_notify('error', f'Error getting recent scans: {e}')
            return []

