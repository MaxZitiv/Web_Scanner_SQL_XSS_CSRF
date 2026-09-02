from datetime import datetime
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import aiohttp
from bs4.element import Tag

from utils.logger import logger
from utils.unified_error_handler import log_and_notify
from utils.vulnerability_info import format_vulnerability_details, vulnerability_dict_to_details

from ._scan_worker_protocol import _ScanWorkerProtocol
from ._scanner_config import SAFE_SQL_PAYLOADS, SAFE_XSS_PAYLOADS, SQL_ERROR_PATTERNS


class ScanWorkerChecksMixin(_ScanWorkerProtocol):
    def _process_scan_results(
        self: _ScanWorkerProtocol,
        url: str,
        results: list[Any],
        scan_types_used: list[str],
        results_by_type: dict[str, list[dict[str, Any]]],
    ):
        """Обрабатывает результаты сканирования и сохраняет место уязвимости."""
        try:
            for scan_type in scan_types_used:
                if scan_type not in results_by_type:
                    continue

                if scan_type not in self.vulnerabilities:
                    self.vulnerabilities[scan_type] = []

                for raw_result in results:
                    if isinstance(raw_result, dict):
                        result = cast(dict[str, Any], raw_result)
                    else:
                        result = {"details": str(raw_result)}

                    # Формируем единое, понятное описание места уязвимости.
                    details = vulnerability_dict_to_details(result)
                    if result.get("details") and not details:
                        details = str(result["details"])

                    location = {
                        "url": url,
                        "details": details,
                        "parameter": str(result.get("parameter", result.get("param", ""))),
                        "method": str(result.get("method", "")),
                        "action": str(result.get("action", "")),
                        "field": str(result.get("field", "")),
                        "payload": str(result.get("payload", "")),
                        "test_url": str(result.get("test_url", "")),
                        "location": str(result.get("location", "")),
                        "timestamp": datetime.now().isoformat(),
                    }
                    results_by_type[scan_type].append(location)
                    self.vulnerabilities[scan_type].append(location)
                    self.signals.vulnerability_found.emit(url, scan_type, details)

        except Exception as e:
            logger.error(f"Error processing scan results: {e}")

    def _vulnerability_result(
        self: _ScanWorkerProtocol,
        url: str,
        *,
        param: str = "",
        method: str = "GET",
        action: str = "",
        field: str = "",
        payload: str = "",
        test_url: str = "",
        note: str = "",
    ) -> dict[str, Any]:
        """Собирает словарь с точным местом обнаруженной уязвимости."""
        details = format_vulnerability_details(
            url=url,
            parameter=param,
            method=method,
            action=action,
            field=field,
            payload=payload,
            test_url=test_url,
            note=note,
        )
        return {
            "url": url,
            "details": details,
            "parameter": param,
            "method": method,
            "action": action,
            "field": field,
            "payload": payload,
            "test_url": test_url,
            "location": field or action,
        }

    async def check_sql_injection(
        self: _ScanWorkerProtocol, session: aiohttp.ClientSession, url: str, forms: list[Tag] | None = None
    ) -> dict[str, Any] | None:
        """Проверка на SQL-инъекции.

        Возвращает словарь с точным параметром/полем, где найдена уязвимость.
        """
        if forms is None:
            forms = []
        try:
            # --- Тестируем параметры URL по одному ---
            parameter_names = self._query_parameter_names(url)
            for payload in SAFE_SQL_PAYLOADS[:5]:
                if self.should_stop:
                    return None
                for param_name in parameter_names:
                    test_url = self._inject_payload_into_param(url, param_name, payload)
                    result = await self.smart_request(session, "GET", test_url)
                    if result:
                        _, content = result
                        if any(pattern.search(content) for pattern in SQL_ERROR_PATTERNS):
                            return self._vulnerability_result(
                                url,
                                param=param_name,
                                method="GET",
                                field=f"query-parameter '{param_name}'",
                                payload=payload,
                                test_url=test_url,
                                note="SQL injection vulnerability detected",
                            )

            # --- Тестируем поля формы по одному ---
            for form in forms:
                if self.should_stop:
                    return None
                action = urljoin(url, str(form.get("action", "")))
                method = str(form.get("method", "get")).upper()
                input_elements = form.find_all("input")[:3]
                for input_elem in input_elements:
                    input_name = str(input_elem.get("name", ""))
                    if input_name and input_elem.get("type") in ["text", "password", "email", "search", "url"]:
                        form_data = {input_name: SAFE_SQL_PAYLOADS[0]}
                        payload = SAFE_SQL_PAYLOADS[0]
                        if method == "POST":
                            result = await self.smart_request(session, "POST", action, data=form_data)
                            test_url = action
                        else:
                            test_url = f"{action}?{urlencode(form_data)}"
                            result = await self.smart_request(session, "GET", test_url)
                        if result:
                            _, content = result
                            if any(pattern.search(content) for pattern in SQL_ERROR_PATTERNS):
                                field = self._form_field_name(input_elem)
                                return self._vulnerability_result(
                                    url,
                                    param=input_name,
                                    method=method,
                                    action=action,
                                    field=field,
                                    payload=payload,
                                    test_url=test_url,
                                    note="SQL injection vulnerability detected in form",
                                )
            return None

        except Exception as e:
            logger.error(f"Error in SQL injection check: {e}")
            return None

    async def check_xss(
        self: _ScanWorkerProtocol, session: aiohttp.ClientSession, url: str, forms: list[Tag]
    ) -> dict[str, Any] | None:
        """Проверка на XSS-уязвимости.

        Возвращает словарь с точным параметром/полем, где найдена уязвимость.
        """
        try:
            # --- Тестируем параметры URL по одному ---
            parameter_names = self._query_parameter_names(url)
            for payload in SAFE_XSS_PAYLOADS[:3]:
                if self.should_stop:
                    return None
                for param_name in parameter_names:
                    test_url = self._inject_payload_into_param(url, param_name, payload)
                    result = await self.smart_request(session, "GET", test_url)
                    if result:
                        _, content = result
                        if payload in content:
                            # Проверяем, что пэйлоад не был экранирован
                            from bs4 import BeautifulSoup as BS

                            soup = BS(content, "html.parser")
                            scripts = soup.find_all("script")
                            reflected = any(script.string and payload in script.string for script in scripts)
                            if reflected:
                                return self._vulnerability_result(
                                    url,
                                    param=param_name,
                                    method="GET",
                                    field=f"query-parameter '{param_name}'",
                                    payload=payload,
                                    test_url=test_url,
                                    note="Reflected XSS vulnerability detected",
                                )

            # --- Тестируем поля формы по одному ---
            for form in forms:
                if self.should_stop:
                    return None
                action = urljoin(url, str(form.get("action", "")))
                method = str(form.get("method", "get")).upper()
                input_elements = form.find_all("input")[:3]
                for input_elem in input_elements:
                    input_name = str(input_elem.get("name", ""))
                    if input_name and input_elem.get("type") in ["text", "password", "email", "search", "url"]:
                        payload = SAFE_XSS_PAYLOADS[0]
                        form_data = {input_name: payload}
                        if method == "POST":
                            result = await self.smart_request(session, "POST", action, data=form_data)
                            test_url = action
                        else:
                            test_url = f"{action}?{urlencode(form_data)}"
                            result = await self.smart_request(session, "GET", test_url)
                        if result:
                            _, content = result
                            if payload in content:
                                field = self._form_field_name(input_elem)
                                return self._vulnerability_result(
                                    url,
                                    param=input_name,
                                    method=method,
                                    action=action,
                                    field=field,
                                    payload=payload,
                                    test_url=test_url,
                                    note="XSS vulnerability detected in form",
                                )
            return None

        except Exception as e:
            logger.error(f"Error in XSS check: {e}")
            return None

    async def check_csrf(self: _ScanWorkerProtocol, url: str, forms: list[Tag]) -> dict[str, Any] | None:
        """Проверка на CSRF-уязвимости.

        Возвращает словарь с URL формы и полем, где отсутствует CSRF-токен.
        """
        try:
            known_csrf_token_names = {
                "csrf_token",
                "csrfmiddlewaretoken",
                "authenticity_token",
                "_csrf",
                "_token",
                "__requestverificationtoken",
                "xsrf_token",
            }

            vulnerable_forms: list[dict[str, str]] = []

            for form in forms:
                try:
                    action = urljoin(url, str(form.get("action", "")))
                    form_method = str(form.get("method", "get")).upper()

                    # Проверяем только POST формы
                    if form_method == "POST":
                        hidden_fields = form.find_all("input", type="hidden")
                        form_has_csrf_token = False
                        hidden_names: list[str] = []
                        for field in hidden_fields:
                            field_name = str(field.get("name", "")).lower()
                            if field_name:
                                hidden_names.append(field_name)
                            if field_name in known_csrf_token_names:
                                form_has_csrf_token = True
                                break

                        if not form_has_csrf_token:
                            vulnerable_forms.append(
                                {
                                    "action": action,
                                    "method": "POST",
                                    "location": (
                                        f"форма {action} (скрытые поля: "
                                        + (", ".join(hidden_names) if hidden_names else "не найдены")
                                        + ")"
                                    ),
                                }
                            )

                except Exception as e:
                    logger.warning(f"Error processing form in CSRF check: {e}")
                    continue

            if vulnerable_forms:
                first = vulnerable_forms[0]
                all_actions = sorted({v["action"] for v in vulnerable_forms})
                return self._vulnerability_result(
                    url,
                    param="CSRF-токен",
                    method=first["method"],
                    action=first["action"],
                    field="скрытые поля формы",
                    payload="отсутствует CSRF-токен",
                    test_url=first["action"],
                    note="Potential CSRF in POST forms to: " + ", ".join(all_actions[:3]),
                )
            return None

        except Exception as e:
            log_and_notify("error", f"Error in check_csrf: {e}")
            return None

    def _inject_payload_into_url(self: _ScanWorkerProtocol, url: str, payload: str) -> str:
        """Внедряет пэйлоад во все параметры URL."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Добавляем пэйлоад к каждому параметру
        injected_params: dict[str, list[str]] = {}
        for key, values in query_params.items():
            injected_params[key] = [f"{value}{payload}" for value in values]

        new_query = urlencode(injected_params, doseq=True)
        return parsed._replace(query=new_query).geturl()

    @staticmethod
    def _query_parameter_names(url: str) -> list[str]:
        """Возвращает имена параметров в query-строке URL."""
        try:
            parsed = urlparse(url)
            return [name for name in parse_qs(parsed.query) if name]
        except Exception:
            return []

    def _inject_payload_into_param(self: _ScanWorkerProtocol, url: str, param_name: str, payload: str) -> str:
        """Внедряет пэйлоад в конкретный параметр URL.

        Это позволяет точно указать, какой именно параметр уязвим.
        """
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        injected_params: dict[str, list[str]] = {}
        for key, values in query_params.items():
            if key == param_name:
                injected_params[key] = [f"{value}{payload}" for value in values]
            else:
                injected_params[key] = values
        new_query = urlencode(injected_params, doseq=True)
        return parsed._replace(query=new_query).geturl()

    @staticmethod
    def _form_field_name(field: Tag) -> str:
        """Человекочитаемое имя поля формы, например input[name='q']."""
        try:
            name = str(field.get("name", ""))
            field_type = str(field.get("type", "text"))
            return f"{field.name}[name='{name}', type='{field_type}']"
        except Exception:
            return str(field)
