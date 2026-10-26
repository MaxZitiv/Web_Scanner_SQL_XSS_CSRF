"""Ограниченный HTTP-клиент для основного воркера и NetworkManager.

Проверяем адрес на каждом переходе, а DNS — в resolver самого коннектора,
чтобы проверенный адрес не разрешался повторно перед подключением.
"""

import asyncio
import ipaddress
import math
import socket
import ssl
import zlib
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit

import aiohttp
from aiohttp.abc import ResolveResult
from multidict import CIMultiDict
from yarl import URL

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class HTTPPolicyError(ValueError):
    """Небезопасный адрес, перенаправление или слишком большой ответ."""


def public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if not ip.is_global or ip.is_multicast or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        # Переходные механизмы могут скрывать IPv4-адрес назначения.
        if ip.is_site_local or ip.sixtofour or ip.teredo or ip in ipaddress.ip_network("64:ff9b::/96"):
            return False
        if ip.ipv4_mapped is not None:
            return public_address(str(ip.ipv4_mapped))
    return True


def origin(url: str) -> tuple[str, str, int]:
    try:
        if not url or any(ord(char) < 32 or ord(char) == 127 for char in url):
            raise ValueError("control characters")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("HTTP(S) required")
        if parsed.username is not None or parsed.password is not None or "\\" in parsed.netloc or "%" in parsed.netloc:
            raise ValueError("credentials or ambiguous host")
        host = (URL(url).raw_host or "").rstrip(".").lower()
        if not host or host == "localhost" or host.endswith((".localhost", ".local")):
            raise ValueError("local host")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass  # Все DNS-ответы проверяет PublicResolver при подключении.
        else:
            if not public_address(host):
                raise ValueError("non-public address")
        return parsed.scheme, host, port
    except ValueError as error:
        raise HTTPPolicyError("Недопустимый HTTP(S)-адрес назначения") from error


def require_scope(url: str, scope_url: str) -> None:
    target, scope = origin(url), origin(scope_url)
    if target == scope:
        return
    # Единственное автоматическое расширение: обычный HTTP -> HTTPS
    # того же хоста. Поддомены и произвольные порты не разрешаются неявно.
    if scope[0] == "http" and scope[2] == 80 and target == ("https", scope[1], 443):
        return
    raise HTTPPolicyError("Адрес выходит за пределы выбранного сайта")


class PublicResolver(aiohttp.ThreadedResolver):
    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> list[ResolveResult]:
        addresses = await super().resolve(host, port, socket.AddressFamily(family))
        if not addresses or any(not public_address(item["host"]) for item in addresses):
            raise HTTPPolicyError("DNS вернул непубличный или недопустимый адрес")
        return addresses


def create_session(timeout: aiohttp.ClientTimeout, headers: Mapping[str, str] | None = None) -> aiohttp.ClientSession:
    return aiohttp.ClientSession(
        timeout=timeout,
        headers=headers,
        connector=aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False),
        trust_env=False,
        auto_decompress=False,
    )


async def read_limited_text(response: aiohttp.ClientResponse, limit: int = MAX_RESPONSE_BYTES) -> str:
    if limit <= 0:
        raise ValueError("Response limit must be positive")
    content_type = response.headers.get("Content-Type", "").lower()
    if content_type and not any(kind in content_type for kind in ("text", "html", "json", "xml", "javascript")):
        response.close()  # Бинарные файлы не загружаем ради освобождения соединения.
        return ""
    if response.content_length is not None and response.content_length > limit:
        raise HTTPPolicyError("Ответ превышает допустимый размер")
    encoding = response.headers.get("Content-Encoding", "identity").lower().strip()
    if encoding not in {"identity", "", "gzip", "deflate"}:
        raise HTTPPolicyError("Неподдерживаемая кодировка сжатого ответа")
    decoder = zlib.decompressobj(31 if encoding == "gzip" else 15) if encoding in {"gzip", "deflate"} else None
    data = bytearray()
    wire_size = 0
    async for chunk in response.content.iter_chunked(64 * 1024):
        wire_size += len(chunk)
        if wire_size > limit:
            raise HTTPPolicyError("Сжатый ответ превышает допустимый размер")
        try:
            decoded = decoder.decompress(chunk, limit - len(data) + 1) if decoder is not None else chunk
        except zlib.error as error:
            raise HTTPPolicyError("Повреждён сжатый ответ") from error
        data.extend(decoded)
        if len(data) > limit:
            raise HTTPPolicyError("Распакованный ответ превышает допустимый размер")
    if decoder is not None and (not decoder.eof or decoder.unused_data):
        raise HTTPPolicyError("Неполный или составной сжатый ответ")
    try:
        return data.decode(response.charset or "utf-8", errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


async def request_text(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    scope_url: str,
    max_bytes: int = MAX_RESPONSE_BYTES,
    **kwargs: Any,
) -> tuple[aiohttp.ClientResponse, str]:
    method = method.upper()
    require_scope(url, scope_url)
    if kwargs.get("proxy") is not None:
        raise HTTPPolicyError("Прокси не поддерживается безопасным DNS-клиентом")
    if kwargs.get("verify_ssl") not in (None, True) or any(
        tls is False
        or (isinstance(tls, ssl.SSLContext) and (tls.verify_mode == ssl.CERT_NONE or not tls.check_hostname))
        for tls in (kwargs.get("ssl"), kwargs.get("ssl_context"))
    ):
        raise HTTPPolicyError("Отключение проверки TLS запрещено")
    if kwargs.get("server_hostname") is not None:
        raise HTTPPolicyError("Переопределение TLS hostname запрещено")
    headers = CIMultiDict[str](kwargs.pop("headers", {}))
    headers["Accept-Encoding"] = "identity"
    # Эти параметры безопасности не могут переопределяться вызывающей стороной.
    kwargs.pop("allow_redirects", None)
    kwargs.pop("auto_decompress", None)
    kwargs.pop("max_redirects", None)
    configured_timeout = kwargs.get("timeout", session.timeout)
    total = configured_timeout.total if isinstance(configured_timeout, aiohttp.ClientTimeout) else configured_timeout
    budget = float(total) if isinstance(total, (int, float)) else 30.0
    if not math.isfinite(budget) or budget <= 0:
        budget = 30.0
    # Один бюджет на всю цепочку, а не новый полный timeout на каждом redirect.
    async with asyncio.timeout(budget):
        current = url
        for redirect in range(MAX_REDIRECTS + 1):
            # Не позволяем Host из пользовательских заголовков обойти границы цели.
            headers["Host"] = URL(current).raw_authority
            async with session.request(
                method, current, headers=headers, allow_redirects=False, auto_decompress=False, **kwargs
            ) as response:
                if response.status not in REDIRECT_STATUSES:
                    return response, await read_limited_text(response, max_bytes)
                if method not in {"GET", "HEAD"}:
                    raise HTTPPolicyError("Автоматическая повторная отправка формы при redirect запрещена")
                location = response.headers.get("Location")
                if not location or redirect == MAX_REDIRECTS:
                    raise HTTPPolicyError("Недопустимая или слишком длинная цепочка перенаправлений")
                target = urljoin(current, location)
                require_scope(target, scope_url)
                require_scope(target, current)  # В частности, запрещаем HTTPS -> HTTP.
                current = target
        raise HTTPPolicyError("Превышен предел перенаправлений")
