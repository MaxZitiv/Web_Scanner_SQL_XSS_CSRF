"""Связь сканеров с каталогами. HTTP полностью подменён, пейлоады не отправляются."""

from dataclasses import dataclass
from typing import cast
from unittest.mock import AsyncMock, Mock, call
from urllib.parse import parse_qs, urlparse

import aiohttp
import pytest
import requests
from bs4 import BeautifulSoup
from bs4.element import Tag

from payloads.csrf import SAFE_CSRF_PAYLOADS
from payloads.rce import RCE_PAYLOADS
from payloads.sql import ADVANCED_SQL_PAYLOADS, SAFE_SQL_PAYLOADS
from payloads.ssrf import SSRF_PAYLOADS
from payloads.xss import ADVANCED_XSS_PAYLOADS, SAFE_XSS_PAYLOADS
from payloads.xxe import XXE_PAYLOADS
from scanner import _scan_worker_checks, _scanner_config, _scanner_core, advanced_scanner, scanner_fixed
from scanner.advanced_scanner import AdvancedScanner
from scanner.scanner_fixed import Scanner, ScanWorker


@pytest.fixture(autouse=True)
def block_real_http(monkeypatch: pytest.MonkeyPatch) -> None:
    # Даже ошибочная потеря подмены в тесте не должна запускать реальный запрос.
    monkeypatch.setattr(
        aiohttp.ClientSession, "_request", AsyncMock(side_effect=AssertionError("Real HTTP is forbidden in tests"))
    )
    monkeypatch.setattr(
        requests.Session, "request", Mock(side_effect=AssertionError("Real HTTP is forbidden in tests"))
    )


@dataclass
class HTTPDouble:
    session: aiohttp.ClientSession
    get: AsyncMock
    post: AsyncMock


@pytest.fixture
def http() -> HTTPDouble:
    response = Mock(status=200)
    response.text = AsyncMock(return_value="ordinary page")
    session = Mock(spec=aiohttp.ClientSession)
    get = AsyncMock(return_value=response)
    post = AsyncMock(return_value=response)
    session.get = get
    session.post = post
    return HTTPDouble(cast(aiohttp.ClientSession, session), get, post)


def test_scanner_imports_and_compatibility_exports_share_the_same_catalogs() -> None:
    for name, payloads in (
        ("SAFE_SQL_PAYLOADS", SAFE_SQL_PAYLOADS),
        ("SAFE_XSS_PAYLOADS", SAFE_XSS_PAYLOADS),
        ("SAFE_CSRF_PAYLOADS", SAFE_CSRF_PAYLOADS),
    ):
        assert getattr(_scanner_config, name) is payloads
        assert getattr(_scanner_core, name) is payloads
        assert getattr(scanner_fixed, name) is payloads
        assert name in scanner_fixed.__all__
    assert _scan_worker_checks.SAFE_SQL_PAYLOADS is SAFE_SQL_PAYLOADS
    assert _scan_worker_checks.SAFE_XSS_PAYLOADS is SAFE_XSS_PAYLOADS


@pytest.mark.parametrize(
    ("attribute", "template"),
    [
        ("advanced_sql_payloads", ADVANCED_SQL_PAYLOADS),
        ("advanced_xss_payloads", ADVANCED_XSS_PAYLOADS),
        ("ssrf_payloads", SSRF_PAYLOADS),
        ("xxe_payloads", XXE_PAYLOADS),
        ("rce_payloads", RCE_PAYLOADS),
    ],
)
def test_advanced_scanner_preserves_independent_mutable_lists(attribute: str, template: list[str]) -> None:
    first, second = AdvancedScanner(), AdvancedScanner()
    first_payloads = cast(list[str], getattr(first, attribute))
    second_payloads = cast(list[str], getattr(second, attribute))
    snapshot = template.copy()
    assert first_payloads == second_payloads == template
    assert first_payloads is not second_payloads and first_payloads is not template
    first_payloads.append("local-test-marker")
    assert template == second_payloads == snapshot


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "payloads", "vulnerability_type"),
    [
        ("_check_sql_injections", SAFE_SQL_PAYLOADS, "SQL Injection"),
        ("_check_xss_reflected", SAFE_XSS_PAYLOADS, "Reflected XSS"),
        ("_check_csrf_vulnerabilities", SAFE_CSRF_PAYLOADS, "CSRF"),
    ],
)
async def test_core_scanner_keeps_catalog_order_and_limit(
    monkeypatch: pytest.MonkeyPatch, method: str, payloads: list[str], vulnerability_type: str
) -> None:
    scanner = Scanner()
    test_payload = AsyncMock()
    monkeypatch.setattr(scanner, "_test_payload", test_payload)
    await getattr(scanner, method)()
    assert test_payload.await_args_list == [
        call(payload, vulnerability_type) for payload in payloads[: _scanner_config.MAX_PAYLOADS_PER_URL]
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "payloads", "limit"),
    [("check_sql_injection", SAFE_SQL_PAYLOADS, 5), ("check_xss", SAFE_XSS_PAYLOADS, 3)],
)
async def test_worker_keeps_query_payload_order_and_limit(
    monkeypatch: pytest.MonkeyPatch, http: HTTPDouble, method: str, payloads: list[str], limit: int
) -> None:
    worker = ScanWorker("https://scanner.example", ["sql", "xss"], 1)
    request = AsyncMock(return_value=(Mock(), "ordinary page"))
    monkeypatch.setattr(worker, "smart_request", request)
    result = await getattr(worker, method)(http.session, "https://scanner.example?input=seed", [])
    assert result is None
    sent = [parse_qs(urlparse(cast(str, args.args[2])).query)["input"][0] for args in request.await_args_list]
    assert sent == ["seed" + payload for payload in payloads[:limit]]
    http.get.assert_not_called()
    http.post.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "payloads"), [("check_sql_injection", SAFE_SQL_PAYLOADS), ("check_xss", SAFE_XSS_PAYLOADS)]
)
async def test_worker_forms_keep_the_first_payload(
    monkeypatch: pytest.MonkeyPatch, http: HTTPDouble, method: str, payloads: list[str]
) -> None:
    worker = ScanWorker("https://scanner.example", ["sql", "xss"], 1)
    request = AsyncMock(return_value=(Mock(), "ordinary page"))
    monkeypatch.setattr(worker, "smart_request", request)
    form = BeautifulSoup(
        '<form action="/submit" method="post"><input type="text" name="q"></form>', "html.parser"
    ).find("form")
    assert isinstance(form, Tag)
    assert await getattr(worker, method)(http.session, "https://scanner.example", [form]) is None
    request.assert_awaited_once_with(http.session, "POST", "https://scanner.example/submit", data={"q": payloads[0]})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "payloads", "limit"),
    [
        ("advanced_sql_injection_check", ADVANCED_SQL_PAYLOADS, 3),
        ("advanced_xss_check", ADVANCED_XSS_PAYLOADS, 3),
        ("ssrf_check", SSRF_PAYLOADS, 5),
        ("rce_check", RCE_PAYLOADS, 3),
    ],
)
async def test_advanced_checks_keep_query_payload_order_and_limits(
    monkeypatch: pytest.MonkeyPatch, http: HTTPDouble, method: str, payloads: list[str], limit: int
) -> None:
    monkeypatch.setattr(advanced_scanner, "time", Mock(time=Mock(return_value=1000.0)))
    scanner = AdvancedScanner()
    assert await getattr(scanner, method)(http.session, "https://scanner.example?input=seed", []) is None
    sent = [parse_qs(urlparse(cast(str, args.args[0])).query)["input"][0] for args in http.get.await_args_list]
    assert sent == payloads[:limit]
    http.post.assert_not_called()


@pytest.mark.asyncio
async def test_xxe_keeps_exact_first_xml_body(http: HTTPDouble) -> None:
    scanner = AdvancedScanner()
    form = BeautifulSoup(
        '<form action="/submit" method="post"><textarea name="xml"></textarea></form>', "html.parser"
    ).find("form")
    assert isinstance(form, Tag)
    assert await scanner.xxe_check(http.session, "https://scanner.example", [form]) is None
    http.post.assert_awaited_once_with(
        "https://scanner.example/submit", data=XXE_PAYLOADS[0], headers={"Content-Type": "application/xml"}
    )
    http.get.assert_not_called()
