"""Каталоги и простой сканер: проверки без Qt и реальных HTTP-запросов."""

import ast
import hashlib
import json
import subprocess
import sys
import tomllib
from fnmatch import fnmatchcase
from pathlib import Path
from unittest.mock import Mock, call

import pytest

from payloads.csrf import SAFE_CSRF_PAYLOADS
from payloads.rce import RCE_PAYLOADS
from payloads.sql import ADVANCED_SQL_PAYLOADS, SAFE_SQL_PAYLOADS, SQLI_PAYLOADS
from payloads.ssrf import SSRF_PAYLOADS
from payloads.xss import ADVANCED_XSS_PAYLOADS, SAFE_XSS_PAYLOADS, XSS_PAYLOADS
from payloads.xxe import XXE_PAYLOADS
from utils import vulnerability_scanner

ROOT = Path(__file__).resolve().parents[1]
CATALOGS: dict[str, list[str]] = {
    "SAFE_SQL_PAYLOADS": SAFE_SQL_PAYLOADS,
    "SQLI_PAYLOADS": SQLI_PAYLOADS,
    "ADVANCED_SQL_PAYLOADS": ADVANCED_SQL_PAYLOADS,
    "SAFE_XSS_PAYLOADS": SAFE_XSS_PAYLOADS,
    "XSS_PAYLOADS": XSS_PAYLOADS,
    "ADVANCED_XSS_PAYLOADS": ADVANCED_XSS_PAYLOADS,
    "SAFE_CSRF_PAYLOADS": SAFE_CSRF_PAYLOADS,
    "SSRF_PAYLOADS": SSRF_PAYLOADS,
    "XXE_PAYLOADS": XXE_PAYLOADS,
    "RCE_PAYLOADS": RCE_PAYLOADS,
}

# Снимок строк до переноса (коммит bda4fd9). Хеш JSON учитывает порядок,
# конечные пробелы SQL и отступы/переносы XML, не дублируя сами пейлоады.
FINGERPRINTS: dict[str, tuple[int, str]] = {
    "SAFE_SQL_PAYLOADS": (14, "f63a953eaf31d6796b7902518670d68ad41efc646c0e4c42664c42fe7ce1b812"),
    "SQLI_PAYLOADS": (6, "e091459231b263f9d20b882804b39b411aa29a312b7a70b47a8388fc4f39b5bf"),
    "ADVANCED_SQL_PAYLOADS": (6, "a178b818ef41172f40ee6f019345a1d8ba8cb9f09c8c295c2bd888ecdd1d8b3a"),
    "SAFE_XSS_PAYLOADS": (10, "cc66d4dfdd29eec979b35fa390dd9eac3202e4d3219b32e55eb176c7f1ee6fa0"),
    "XSS_PAYLOADS": (3, "96a7aefa424bf9be631802b3de00e2d3ca9d05b146f8c2cf766f2daf12477bcc"),
    "ADVANCED_XSS_PAYLOADS": (7, "7515cffc1eb9502f83288232ea68a4ec39deed8613f77db5f2d015ba0943c2f3"),
    "SAFE_CSRF_PAYLOADS": (4, "76442de08a29db5773901bad20f777df99635fbc3644ede492b1870faf30233f"),
    "SSRF_PAYLOADS": (10, "c14af23332cf95b17d00b1ea25374442a3d22ab435ce574840c1834d7a9a9c5d"),
    "XXE_PAYLOADS": (2, "87f1fbde855d48e8dd2c0fb9610eb54a3f01193b0c229d972fe6ba9e734fd9d4"),
    "RCE_PAYLOADS": (8, "3208d1e0649013d80d1d74cf13c07e7bd121f8b165812d9f1ed3b694b5bd9b29"),
}


@pytest.mark.parametrize("name", CATALOGS)
def test_catalog_contents_and_order_match_pre_refactor_snapshot(name: str) -> None:
    payloads = CATALOGS[name]
    count, digest = FINGERPRINTS[name]
    assert type(payloads) is list  # Сохраняем тип прежних публичных наборов.
    assert len(payloads) == count
    serialized = json.dumps(payloads, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(serialized).hexdigest() == digest


def test_payload_imports_are_independent_of_application_and_dependencies(tmp_path: Path) -> None:
    script = f"""
import importlib
import sys
sys.path.insert(0, {str(ROOT)!r})
for name in ('sql', 'xss', 'csrf', 'ssrf', 'xxe', 'rce'):
    importlib.import_module('payloads.' + name)
assert not {{'scanner', 'utils', 'PyQt6', 'aiohttp', 'requests'}}.intersection(sys.modules)
"""
    # Без site-packages, PYTHONPATH и текущей директории проекта.
    # -B также исключает запись __pycache__ при проверке чистого импорта.
    subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script], cwd=tmp_path, check=True, timeout=10)
    assert not list(tmp_path.iterdir())


def test_payload_package_is_included_in_distribution() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    discovery = config["tool"]["setuptools"]["packages"]["find"]
    assert (ROOT / "payloads" / "__init__.py").is_file()
    assert any(fnmatchcase("payloads", pattern) for pattern in discovery["include"])
    assert not any(fnmatchcase("payloads", pattern) for pattern in discovery["exclude"])


def test_scanners_do_not_define_inline_payload_lists() -> None:
    for directory in ("scanner", "utils"):
        for path in (ROOT / directory).rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, ast.AnnAssign):
                    targets, value = [node.target], node.value
                else:
                    continue
                for target in targets:
                    name = (
                        target.id
                        if isinstance(target, ast.Name)
                        else target.attr
                        if isinstance(target, ast.Attribute)
                        else ""
                    )
                    if name.lower().endswith("_payloads"):
                        assert not isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)), (path, name)


def test_utility_compatibility_names_reference_catalogs() -> None:
    assert vulnerability_scanner.SQLI_PAYLOADS is SQLI_PAYLOADS
    assert vulnerability_scanner.XSS_PAYLOADS is XSS_PAYLOADS


@pytest.mark.parametrize(
    ("method", "payloads", "parameter"),
    [("scan_sql_injection", SQLI_PAYLOADS, "id"), ("scan_xss", XSS_PAYLOADS, "q")],
)
def test_utility_checks_use_full_original_order(
    monkeypatch: pytest.MonkeyPatch, method: str, payloads: list[str], parameter: str
) -> None:
    request = Mock(return_value=Mock(status_code=200, text="ordinary page"))
    monkeypatch.setattr(vulnerability_scanner.requests, "get", request)
    check = getattr(vulnerability_scanner, method)
    assert check("https://scanner.example") is False
    assert request.call_args_list == [
        call(f"https://scanner.example?{parameter}={payload}", timeout=5, allow_redirects=False) for payload in payloads
    ]


def test_utility_xss_still_stops_after_first_reflection(monkeypatch: pytest.MonkeyPatch) -> None:
    request = Mock(return_value=Mock(status_code=200, text=XSS_PAYLOADS[0]))
    monkeypatch.setattr(vulnerability_scanner.requests, "get", request)
    assert vulnerability_scanner.scan_xss("https://scanner.example")
    request.assert_called_once_with(f"https://scanner.example?q={XSS_PAYLOADS[0]}", timeout=5, allow_redirects=False)
