"""Интеграция сетевой политики с основным сканером (Python 3.14)."""

from typing import cast
from unittest.mock import AsyncMock, Mock

import aiohttp
import pytest
from test_http_safety import response, session_for

from scanner import _scan_worker_core
from scanner.network_manager import NetworkManager
from scanner.scanner_fixed import ScanWorker


@pytest.mark.asyncio
async def test_worker_does_not_cache_responses_or_duplicate_headers() -> None:
    session, request = session_for(response(b"first"), response(b"second"))
    worker = ScanWorker("https://scanner.example", ["sql"], 1)
    one = await worker.smart_request(session, "GET", worker.base_url, headers={"X-Test": "ok"})
    two = await worker.smart_request(session, "GET", worker.base_url, headers={"X-Test": "ok"})
    assert one is not None and one[1] == "first"
    assert two is not None and two[1] == "second"
    assert request.call_count == 2
    assert request.call_args.kwargs["headers"]["X-Test"] == "ok"
    assert request.call_args.kwargs["headers"]["Accept-Encoding"] == "identity"


@pytest.mark.asyncio
async def test_worker_post_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = AsyncMock(side_effect=TimeoutError())
    monkeypatch.setattr(_scan_worker_core, "request_text", operation)
    worker = ScanWorker("https://scanner.example", ["sql"], 1)
    assert await worker.smart_request(cast(aiohttp.ClientSession, Mock()), "POST", worker.base_url) is None
    operation.assert_awaited_once()
    assert worker.base_url in worker.unscanned_urls


@pytest.mark.asyncio
async def test_network_manager_uses_fresh_responses_and_blocks_other_origins(monkeypatch: pytest.MonkeyPatch) -> None:
    session, request = session_for(response(b"first"), response(b"second"))
    manager = NetworkManager()
    monkeypatch.setattr(manager, "_session", session)
    one = await manager.request("GET", "https://scanner.example")
    two = await manager.request("GET", "https://scanner.example")
    assert one is not None and one[1] == "first"
    assert two is not None and two[1] == "second"
    assert await manager.request("GET", "https://other.example") is None
    assert request.call_count == 2


@pytest.mark.asyncio
async def test_controller_reports_persistence_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from controllers.scan_controller import ScanController

    controller = ScanController("https://scanner.example", ["sql"], 1)
    monkeypatch.setattr(controller, "_perform_scan", AsyncMock(return_value={"results": {}}))
    monkeypatch.setattr(controller, "save_scan_result", AsyncMock(return_value=False))
    on_result = Mock()
    await controller.start_scan("https://scanner.example", ["sql"], on_result=on_result)
    on_result.assert_called_once()
    assert on_result.call_args.args[0]["saved"] is False
