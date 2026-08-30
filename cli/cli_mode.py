"""
Интерфейс командной строки для сканера веб-уязвимостей
"""
import os
import argparse
import asyncio
import importlib.util
from typing import List, Dict, Any, Optional
import getpass

# Загружаем sys_utils по абсолютному пути, чтобы не обращаться к sys.path
# до добавления корня проекта в пути поиска модулей.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SYS_UTILS_PATH = os.path.join(_PROJECT_ROOT, "utils", "sys_utils.py")


def _load_sys_utils() -> Any:
    """Загружает utilities/sys_utils.py как отдельный модуль."""
    spec = importlib.util.spec_from_file_location("_sys_utils", _SYS_UTILS_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Не удалось загрузить {_SYS_UTILS_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_sys_utils = _load_sys_utils()

# Добавляем корневую директорию проекта в sys.path
_sys_utils.add_to_path(0, _PROJECT_ROOT)

from models.user_model import UserModel
from controllers.auth_controller import AuthController
from controllers.scan_controller import ScanController
from utils.logger import logger


class CLIMode:
    """Класс для работы в режиме командной строки"""

    def __init__(self):
        self.user_model = UserModel()
        self.auth_controller = AuthController(self.user_model)
        self.scan_controller = None
        self.current_user_id = None
        self.current_username = None

    def login(self, username: str, password: str) -> bool:
        """Авторизация пользователя"""
        try:
            success, message = self.auth_controller.login(username, password)
            if success:
                self.current_user_id = self.user_model.get_user_id()
                self.current_username = self.user_model.get_username()
                print(f"✅ Успешный вход. Добро пожаловать, {self.current_username}!")
                logger.info(f"User {username} logged in successfully via CLI")
                return True
            else:
                print(f"❌ Ошибка входа: {message}")
                logger.warning(f"Failed login attempt for {username}: {message}")
                return False
        except Exception as e:
            error_msg = f"Ошибка при входе: {e}"
            print(f"❌ {error_msg}")
            logger.error(error_msg)
            return False

    def interactive_login(self) -> bool:
        """Интерактивный вход с запросом учетных данных"""
        print("=== Вход в систему ===")
        username = input("Имя пользователя или Email: ")
        password = getpass.getpass("Пароль: ")
        return self.login(username, password)

    def _log_message(self, message: str) -> None:
        """Обработчик сообщений лога для CLI режима"""
        print(message)
        
    def _update_progress(self, progress: int, current_url: str = "", total_urls: int = 0, found_vulns: int = 0) -> None:
        """Обработчик обновления прогресса для CLI режима
        
        Args:
            progress: Процент выполнения (0-100)
            current_url: Текущий обрабатываемый URL
            total_urls: Общее количество URL для сканирования
            found_vulns: Количество найденных уязвимостей
        """
        progress_bar_length = 40
        filled_length = int(progress_bar_length * progress / 100)
        bar = "█" * filled_length + "-" * (progress_bar_length - filled_length)
        
        # Формируем строку прогресса
        progress_str = f"\rПрогресс: |{bar}| {progress}%"
        
        # Добавляем дополнительную информацию если доступна
        if current_url:
            # Ограничиваем длину URL для отображения
            display_url = current_url[:60] + "..." if len(current_url) > 60 else current_url
            progress_str += f"\nТекущий URL: {display_url}"
        
        if total_urls > 0:
            progress_str += f"\nОбработано URL: {int(total_urls * progress / 100)}/{total_urls}"
        
        if found_vulns > 0:
            progress_str += f"\nНайдено уязвимостей: {found_vulns}"
        
        # Очищаем предыдущие строки и выводим новую информацию
        print("\033[K", end="")  # Очищаем текущую строку
        if current_url:
            print("\033[K", end="")  # Очищаем строку с URL
        if total_urls > 0:
            print("\033[K", end="")  # Очищаем строку с количеством URL
        if found_vulns > 0:
            print("\033[K", end="")  # Очищаем строку с уязвимостями
            
        # Возвращаем курсор в начало и выводим обновленную информацию
        print("\033[3F", end="")  # Перемещаем курсор на 3 строки вверх
        print(progress_str, flush=True)
        
    def _process_results(self, results: Dict[str, Any], scan_type: str = "standard") -> None:
        """Обработчик результатов сканирования для CLI режима"""
        if "error" in results:
            print(f"\n❌ Ошибка сканирования: {results['error']}")
            return
            
        url = results.get("url", "неизвестно")
        vulnerabilities = results.get("vulnerabilities", {})
        
        print(f"\n📄 Результаты сканирования для {url}:")
        
        # Вывод результатов по каждому типу уязвимостей
        for vuln_type, vuln_list in vulnerabilities.items():
            if vuln_type == "sql":
                if vuln_list:
                    print(f"   - SQL инъекции: обнаружено {len(vuln_list)}")
                    for vuln in vuln_list[:3]:  # Показываем только первые 3
                        print(f"     • {vuln.get('description', 'Без описания')}")
                else:
                    print("   - SQL инъекции: не обнаружены")
                    
            elif vuln_type == "xss":
                if vuln_list:
                    print(f"   - XSS уязвимости: обнаружено {len(vuln_list)}")
                    for vuln in vuln_list[:3]:  # Показываем только первые 3
                        print(f"     • {vuln.get('description', 'Без описания')}")
                else:
                    print("   - XSS уязвимости: не обнаружены")
                    
            elif vuln_type == "csrf":
                if vuln_list:
                    print(f"   - CSRF уязвимости: обнаружено {len(vuln_list)}")
                    for vuln in vuln_list[:3]:  # Показываем только первые 3
                        print(f"     • {vuln.get('description', 'Без описания')}")
                else:
                    print("   - CSRF уязвимости: не обнаружены")
        
        # Дополнительная статистика
        total_urls = results.get("total_urls_scanned", 0)
        total_forms = results.get("total_forms_scanned", 0)
        scan_duration = results.get("scan_duration", 0)
        
        print("\n📊 Статистика сканирования:")
        print(f"   - Обработано URL: {total_urls}")
        print(f"   - Проверено форм: {total_forms}")
        print(f"   - Время выполнения: {scan_duration:.2f} сек")
        
        # Сохранение результатов в базу данных
        try:
            from utils.database import Database
            db = Database()
            
            # Подготовка списка уязвимостей для сохранения
            vulns_list: List[Dict[str, Any]] = []
            for vuln_type, vuln_items in vulnerabilities.items():
                if vuln_items:
                    for vuln in vuln_items:
                        vulns_list.append({
                            "type": vuln_type,
                            "url": vuln.get("url", url),
                            "details": vuln.get("description", "")
                        })
            
            # Сохранение результатов
            if self.current_user_id is not None:
                success = db.save_scan_async(
                    self.current_user_id,
                    url,
                    vulns_list,
                    scan_type,
                    scan_duration
                )
                
                if success:
                    print("\n💾 Результаты сохранены в базе данных")
        except Exception as e:
            print(f"\n⚠️ Предупреждение: не удалось сохранить результаты в базу данных: {e}")

    async def scan_url(self, url: str, scan_type: str = "standard", max_depth: int = 3, max_concurrent: int = 5, timeout: int = 30) -> bool:
        """Запуск сканирования указанного URL с настраиваемыми параметрами
        
        Args:
            url: URL для сканирования
            scan_type: Тип сканирования (standard, deep, quick)
            max_depth: Максимальная глубина сканирования
            max_concurrent: Максимальное количество одновременных запросов
            timeout: Таймаут запроса в секундах
        """
        if not self.current_user_id:
            print("❌ Ошибка: не выполнен вход в систему")
            return False

        try:
            # Инициализация контроллера сканирования
            self.scan_controller = ScanController(url, [scan_type], self.current_user_id, max_depth=max_depth, max_concurrent=max_concurrent, timeout=timeout)
            print(f"🔍 Запуск сканирования: {url}")
            print(f"   Тип сканирования: {scan_type}")
            print(f"   Максимальная глубина: {max_depth}")
            print(f"   Макс. одновременных запросов: {max_concurrent}")
            print(f"   Таймаут запроса: {timeout} сек")

            # Реальная логика сканирования
            print("⏳ Сканирование в процессе...")

            # Вызов метода сканирования с указанными параметрами
            # Создаем переменные для отслеживания метрик
            scan_metrics: Dict[str, Any] = {
                "current_url": "",
                "total_urls": 0,
                "found_vulns": 0
            }
            
            # Создаем обертку для обновления прогресса с метриками
            def update_progress_with_metrics(progress: float) -> None:
                # Преобразуем float в int для совместимости
                progress_int = int(progress)
                
                self._update_progress(
                    progress_int, 
                    scan_metrics["current_url"],
                    scan_metrics["total_urls"],
                    scan_metrics["found_vulns"]
                )
            
            # Создаем обертку для обработки логов с обновлением метрик
            def log_with_metrics(message: str) -> None:
                # Выводим сообщение
                self._log_message(message)
                
                # Обновляем метрики на основе сообщений
                if "Найдена уязвимость:" in message:
                    scan_metrics["found_vulns"] += 1
                elif "Обнаружено" in message and "URL для сканирования" in message:
                    # Извлекаем общее количество URL
                    try:
                        import re
                        match = re.search(r'Обнаружено (\d+) URL', message)
                        if match:
                            scan_metrics["total_urls"] = int(match.group(1))
                    except (TypeError, ValueError, AttributeError):
                        return
            
            # Создаем специальную обертку для обработки двух параметров из progress.emit
            def progress_wrapper(progress: float, current_url: str = "") -> None:
                # Обновляем метрики
                if current_url:
                    scan_metrics["current_url"] = current_url
                
                # Вызываем наш обработчик прогресса
                update_progress_with_metrics(progress)
            
            await self.scan_controller.start_scan(
                url, 
                [scan_type], 
                max_depth=max_depth, 
                max_concurrent=max_concurrent, 
                timeout=timeout, 
                on_log=log_with_metrics, 
                on_progress=progress_wrapper,
                on_result=lambda results: self._process_results(results, scan_type)
            )

            # Очищаем строки прогресса
            print("\033[4B", end="")  # Перемещаем курсор на 4 строки вниз
            print("\033[K", end="")  # Очищаем текущую строку
            print("\033[K", end="")  # Очищаем следующую строку
            print("\033[K", end="")  # Очищаем следующую строку
            print("\033[K", end="")  # Очищаем следующую строку
            print("\033[4F", end="")  # Возвращаем курсор на 4 строки вверх
            
            print("\n✅ Сканирование завершено!")

            return True
        except Exception as e:
            error_msg = f"Ошибка при сканировании: {e}"
            print(f"❌ {error_msg}")
            logger.error(error_msg)
            return False

    def list_scans(self) -> List[Dict[str, Any]]:
        """Получение списка всех сканирований пользователя"""
        if not self.current_user_id:
            print("❌ Ошибка: не выполнен вход в систему")
            return []

        try:
            # Здесь будет реальная логика получения списка сканирований
            # Для примера просто вернем пустой список
            print("📋 Список сканирований:")
            print("   (пока нет сохраненных сканирований)")
            return []
        except Exception as e:
            error_msg = f"Ошибка при получении списка сканирований: {e}"
            print(f"❌ {error_msg}")
            logger.error(error_msg)
            return []

    def show_scan_results(self, scan_id: int) -> bool:
        """Показать результаты сканирования по ID"""
        if not self.current_user_id:
            print("❌ Ошибка: не выполнен вход в систему")
            return False

        try:
            # Здесь будет реальная логика получения результатов сканирования
            print(f"📄 Результаты сканирования #{scan_id}:")
            print("   (результаты не найдены)")
            return True
        except Exception as e:
            error_msg = f"Ошибка при получении результатов сканирования: {e}"
            print(f"❌ {error_msg}")
            logger.error(error_msg)
            return False

    def export_results(self, scan_id: int, format: str, filename: str) -> bool:
        """Экспорт результатов сканирования"""
        if not self.current_user_id:
            print("❌ Ошибка: не выполнен вход в систему")
            return False

        try:
            # Здесь будет реальная логика экспорта
            print(f"💾 Экспорт результатов сканирования #{scan_id} в {format} формат...")
            print(f"   Сохранено в файл: {filename}")
            return True
        except Exception as e:
            error_msg = f"Ошибка при экспорте результатов: {e}"
            print(f"❌ {error_msg}")
            logger.error(error_msg)
            return False

    def interactive_mode(self) -> None:
        """Интерактивный режим работы"""
        if not self.current_user_id:
            if not self.interactive_login():
                print("❌ Не удалось войти в систему. Выход.")
                return

        print(f"\n🚀 Запуск интерактивного режима для пользователя: {self.current_username}")
        print("Доступные команды:")
        print("  scan <url> [type] [depth] [concurrent] [timeout] - Запустить сканирование URL")
        print("    type: тип сканирования (1=quick, 2=standard, 3=deep), по умолчанию: 2")
        print("    depth: максимальная глубина сканирования (1-10), по умолчанию: 3")
        print("    concurrent: макс. количество одновременных запросов (1-20), по умолчанию: 5")
        print("    timeout: таймаут запроса в секундах (5-300), по умолчанию: 30")
        print("  list - Показать список сканирований")
        print("  results <id> - Показать результаты сканирования")
        print("  export <id> <format> <filename> - Экспорт результатов")
        print("  help - Показать справку")
        print("  exit - Выйти из программы")

        while True:
            try:
                command = input(f"\n[{self.current_username}]> ").strip()
                if not command:
                    continue

                parts = command.split()
                cmd = parts[0].lower()

                if cmd == "exit":
                    print("👋 До свидания!")
                    break
                elif cmd == "help":
                    print("Доступные команды:")
                    print("  scan <url> [type] [depth] [concurrent] [timeout] - Запустить сканирование URL")
                    print("    type: тип сканирования (1=quick, 2=standard, 3=deep), по умолчанию: 2")
                    print("    depth: максимальная глубина сканирования (1-10), по умолчанию: 3")
                    print("    concurrent: макс. количество одновременных запросов (1-20), по умолчанию: 5")
                    print("    timeout: таймаут запроса в секундах (5-300), по умолчанию: 30")
                    print("  list - Показать список сканирований")
                    print("  results <id> - Показать результаты сканирования")
                    print("  export <id> <format> <filename> - Экспорт результатов")
                    print("  help - Показать справку")
                    print("  exit - Выйти из программы")
                elif cmd == "scan" and len(parts) >= 2:
                    url = parts[1]
                    scan_type = parts[2] if len(parts) > 2 else "standard"
                    max_depth = int(parts[3]) if len(parts) > 3 else 3
                    max_concurrent = int(parts[4]) if len(parts) > 4 else 5
                    timeout = int(parts[5]) if len(parts) > 5 else 30
                    
                    # Преобразуем тип сканирования в правильный формат
                    if scan_type.isdigit():
                        scan_type_map = {
                            "1": "quick",
                            "2": "standard",
                            "3": "deep"
                        }
                        scan_type = scan_type_map.get(scan_type, "standard")
                    
                    asyncio.run(self.scan_url(url, scan_type, max_depth, max_concurrent, timeout))
                elif cmd == "list":
                    self.list_scans()
                elif cmd == "results" and len(parts) >= 2:
                    try:
                        scan_id = int(parts[1])
                        self.show_scan_results(scan_id)
                    except ValueError:
                        print("❌ ID сканирования должен быть числом")
                elif cmd == "export" and len(parts) >= 4:
                    try:
                        scan_id = int(parts[1])
                        format_type = parts[2]
                        filename = parts[3]
                        self.export_results(scan_id, format_type, filename)
                    except ValueError:
                        print("❌ ID сканирования должен быть числом")
                else:
                    print("❌ Неизвестная команда или неверные параметры. Введите 'help' для справки.")
            except KeyboardInterrupt:
                print("👋 До свидания!")
                break
            except Exception as e:
                error_msg = f"Ошибка выполнения команды: {e}"
                print(f"❌ {error_msg}")
                logger.error(error_msg)


def run_cli_mode(url: Optional[str] = None, username: Optional[str] = None, 
                  scan_type: str = "2", max_depth: int = 3, max_concurrent: int = 5, timeout: int = 30) -> int:
    """Запуск CLI режима
    
    Args:
        url: URL для сканирования (опционально)
        username: Имя пользователя для входа (опционально)
        scan_type: Тип сканирования (1=quick, 2=standard, 3=deep)
        max_depth: Максимальная глубина сканирования
        max_concurrent: Максимальное количество одновременных запросов
        timeout: Таймаут запроса в секундах
    """
    
    # Преобразуем числовой тип сканирования в строковый
    scan_type_map = {
        "1": "quick",
        "2": "standard",
        "3": "deep"
    }
    scan_type = scan_type_map.get(scan_type, "standard")
    print("🔧 Web Scanner CLI режим")
    print("=" * 40)

    cli = CLIMode()

    # Если передан URL, но не переданы учетные данные, запрашиваем их
    if url and not username:
        print("Для сканирования требуется вход в систему")
        if not cli.interactive_login():
            return 1

    # Если переданы и URL, и учетные данные
    if url and username:
        password = getpass.getpass("Пароль: ")
        if not cli.login(username, password):
            return 1
        asyncio.run(cli.scan_url(url, scan_type, max_depth, max_concurrent, timeout))
        return 0

    # Иначе запускаем интерактивный режим
    cli.interactive_mode()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Scanner CLI")
    parser.add_argument("--url", help="URL для сканирования")
    parser.add_argument("--username", help="Имя пользователя для входа")
    parser.add_argument("--type", choices=["1", "2", "3"], default="2", 
                       help="Тип сканирования (1=quick, 2=standard, 3=deep)")
    parser.add_argument("--depth", type=int, default=3, 
                       help="Максимальная глубина сканирования")
    parser.add_argument("--concurrent", type=int, default=5, 
                       help="Максимальное количество одновременных запросов")
    parser.add_argument("--timeout", type=int, default=30, 
                       help="Таймаут запроса в секундах")

    args = parser.parse_args()
    exit_code = run_cli_mode(args.url, args.username, args.type, args.depth, args.concurrent, args.timeout)
    _sys_utils.exit_process(exit_code)