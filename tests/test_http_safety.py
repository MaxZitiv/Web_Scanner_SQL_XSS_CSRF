"""HTTP-политика и её интеграция; сокеты и DNS в тестах не используются."""

import gzip
import socket
from collections.abc import AsyncIterator
from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock

import aiohttp
import pytest
from aiohttp.abc import ResolveResult
from multidict import CIMultiDict

from utils.http_safety import (
    HTTPPolicyError,
    PublicResolver,
    create_session,
    origin,
    public_address,
    read_limited_text,
    request_text,
    require_scope,
)


class Chunks:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.reads = 0

    async def iter_chunked(self, size: int) -> AsyncIterator[bytes]:
        for position in range(0, len(self.content), size):
            self.reads += 1
            yield self.content[position : position + size]


def response(content: bytes = b"ordinary page", *, status: int = 200, headers: dict[str, str] | None = None) -> Mock:
    result = Mock(status=status, content_length=None, charset="utf-8")
    result.headers = CIMultiDict({"Content-Type": "text/html", **(headers or {})})
    result.content = Chunks(content)
    return result


def session_for(*responses: Mock) -> tuple[aiohttp.ClientSession, Mock]:
    contexts: list[MagicMock] = []
    for result in responses:
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=result)
        context.__aexit__ = AsyncMock(return_value=False)
        contexts.append(context)
    session = Mock(spec=aiohttp.ClientSession)
    request = Mock(side_effect=contexts)
    session.request = request
    return cast(aiohttp.ClientSession, session), request


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fec0::1",
        "::ffff:127.0.0.1",
        "64:ff9b::a00:1",
        "224.0.0.1",
    ],
)
def test_non_public_addresses_are_rejected(address: str) -> None:
    assert not public_address(address)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:pass@scanner.example",
        "http://127.0.0.1:8080",
        "http://[::1]",
        "http://localhost.",
        "https://host.local",
        "https://scanner.example:0",
        "https://scanner.example:bad",
        "https://scanner.example\n",
        "https://scanner.example\\@evil.example",
    ],
)
def test_unsafe_origins_are_rejected(url: str) -> None:
    with pytest.raises(HTTPPolicyError):
        origin(url)


def test_scope_accepts_only_same_origin_and_standard_https_upgrade() -> None:
    require_scope("https://SCANNER.EXAMPLE.:443/path?a=1", "http://scanner.example")
    require_scope("https://scanner.example/path", "https://scanner.example")
    for target in (
        "https://evil.example",
        "https://sub.scanner.example",
        "https://scanner.example:8443",
        "http://scanner.example",
    ):
        with pytest.raises(HTTPPolicyError):
            require_scope(target, "https://scanner.example")


@pytest.mark.asyncio
@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["8.8.8.8", "10.0.0.1"], []])
async def test_dns_is_checked_in_connector_resolver(monkeypatch: pytest.MonkeyPatch, addresses: list[str]) -> None:
    records: list[ResolveResult] = [
        {"hostname": "scanner.example", "host": address, "port": 443, "family": socket.AF_INET, "proto": 0, "flags": 0}
        for address in addresses
    ]
    monkeypatch.setattr(aiohttp.ThreadedResolver, "resolve", AsyncMock(return_value=records))
    resolver = PublicResolver()
    with pytest.raises(HTTPPolicyError):
        await resolver.resolve("scanner.example", 443)
    await resolver.close()


@pytest.mark.asyncio
async def test_public_dns_addresses_are_returned_without_second_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    records: list[ResolveResult] = [
        {
            "hostname": "scanner.example",
            "host": "8.8.8.8",
            "port": 443,
            "family": socket.AF_INET,
            "proto": 0,
            "flags": 0,
        }
    ]
    lookup = AsyncMock(return_value=records)
    monkeypatch.setattr(aiohttp.ThreadedResolver, "resolve", lookup)
    resolver = PublicResolver()
    assert await resolver.resolve("scanner.example", 443) is records
    lookup.assert_awaited_once()
    await resolver.close()


@pytest.mark.asyncio
async def test_owned_session_disables_environment_proxies_and_automatic_decompression() -> None:
    async with create_session(aiohttp.ClientTimeout(total=5)) as session:
        assert not session.trust_env
        assert not session.auto_decompress


@pytest.mark.asyncio
async def test_redirect_outside_scope_is_not_requested() -> None:
    first = response(status=302, headers={"Location": "http://127.0.0.1/internal"})
    session, request = session_for(first)
    with pytest.raises(HTTPPolicyError):
        await request_text(session, "GET", "https://scanner.example", scope_url="https://scanner.example")
    request.assert_called_once()
    assert request.call_args.kwargs["allow_redirects"] is False


@pytest.mark.asyncio
async def test_https_upgrade_and_relative_redirect_are_followed_explicitly() -> None:
    session, request = session_for(
        response(status=301, headers={"Location": "https://scanner.example/path"}),
        response(status=302, headers={"Location": "/final"}),
        response(b"done"),
    )
    _, text = await request_text(session, "GET", "http://scanner.example", scope_url="http://scanner.example")
    assert text == "done"
    assert [call.args[1] for call in request.call_args_list] == [
        "http://scanner.example",
        "https://scanner.example/path",
        "https://scanner.example/final",
    ]


@pytest.mark.asyncio
async def test_post_redirect_and_tls_bypass_are_rejected() -> None:
    session, request = session_for(response(status=307, headers={"Location": "/again"}))
    with pytest.raises(HTTPPolicyError):
        await request_text(
            session, "POST", "https://scanner.example", scope_url="https://scanner.example", data={"q": "test"}
        )
    request.assert_called_once()
    with pytest.raises(HTTPPolicyError):
        await request_text(session, "GET", "https://scanner.example", scope_url="https://scanner.example", ssl=False)
    request.assert_called_once()


@pytest.mark.asyncio
async def test_redirect_loop_is_bounded() -> None:
    session, request = session_for(*(response(status=302, headers={"Location": "/again"}) for _ in range(6)))
    with pytest.raises(HTTPPolicyError):
        await request_text(session, "GET", "https://scanner.example", scope_url="https://scanner.example")
    assert request.call_count == 6


@pytest.mark.asyncio
@pytest.mark.parametrize("compressed", [False, True])
async def test_stream_and_decompressed_size_are_bounded(compressed: bool) -> None:
    payload = b"x" * 2000
    result = response(
        gzip.compress(payload) if compressed else payload, headers=({"Content-Encoding": "gzip"} if compressed else {})
    )
    with pytest.raises(HTTPPolicyError):
        await read_limited_text(cast(aiohttp.ClientResponse, result), 100)


@pytest.mark.asyncio
async def test_valid_gzip_and_invalid_charset_are_supported() -> None:
    result = response(gzip.compress("текст".encode()), headers={"Content-Encoding": "gzip"})
    result.charset = "does-not-exist"
    assert await read_limited_text(cast(aiohttp.ClientResponse, result), 100) == "текст"


@pytest.mark.asyncio
async def test_declared_size_and_binary_responses_are_not_downloaded() -> None:
    oversized = response()
    oversized.content_length = 1000
    with pytest.raises(HTTPPolicyError):
        await read_limited_text(cast(aiohttp.ClientResponse, oversized), 100)
    assert oversized.content.reads == 0
    binary = response(b"x" * 2000, headers={"Content-Type": "image/png"})
    assert await read_limited_text(cast(aiohttp.ClientResponse, binary), 100) == ""
    binary.close.assert_called_once()
    assert binary.content.reads == 0


@pytest.mark.asyncio
async def test_custom_host_cannot_change_target_and_legacy_tls_switch_is_blocked() -> None:
    session, request = session_for(response())
    await request_text(
        session,
        "GET",
        "https://scanner.example",
        scope_url="https://scanner.example",
        headers={"Host": "other.example"},
    )
    assert request.call_args.kwargs["headers"]["Host"] == "scanner.example"
    with pytest.raises(HTTPPolicyError):
        await request_text(
            session, "GET", "https://scanner.example", scope_url="https://scanner.example", verify_ssl=False
        )
    request.assert_called_once()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://scanner.example:8443", True),
        ("https://scanner.example:0", False),
        ("http://127.0.0.1:8080", False),
        ("http://localhost.:80", False),
        ("http://100.64.0.1", False),
        ("https://u:p@scanner.example", False),
    ],
)
def test_frontend_url_validation_handles_host_and_port_separately(url: str, expected: bool) -> None:
    from utils.security import is_safe_url

    assert is_safe_url(url) is expected


@pytest.mark.asyncio
async def test_whole_operation_has_a_timeout_even_with_redirects() -> None:
    import asyncio

    session, request = session_for(response(status=302, headers={"Location": "/next"}), response())
    context = MagicMock()

    async def enter() -> Mock:
        await asyncio.sleep(0.05)
        return response()

    context.__aenter__ = AsyncMock(side_effect=enter)
    context.__aexit__ = AsyncMock(return_value=False)
    request.side_effect = None
    request.return_value = context
    with pytest.raises(TimeoutError):
        await request_text(
            session,
            "GET",
            "https://scanner.example",
            scope_url="https://scanner.example",
            timeout=aiohttp.ClientTimeout(total=0.001),
        )
