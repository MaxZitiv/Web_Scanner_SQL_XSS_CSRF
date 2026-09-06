"""Проверки структуры, не требующие запуска Qt."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEGACY_MODULES = {
    "views.dashboard_window_fixed",
    "views.dashboard_window_optimized",
    "views.dashboard_window_updated",
    "views.dashboard_window_wrapper",
}


def test_only_one_dashboard_window_module_and_class_remain() -> None:
    assert sorted(path.name for path in (ROOT / "views").glob("dashboard_window*.py")) == ["dashboard_window.py"]
    definitions: list[Path] = []
    for path in (ROOT / "views").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        definitions.extend(
            path for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name == "DashboardWindow"
        )
    assert definitions == [ROOT / "views" / "dashboard_window.py"]


def test_no_application_module_imports_deleted_dashboard_variants() -> None:
    for directory in ("cli", "controllers", "models", "scanner", "ui", "utils", "views", "tests"):
        for path in (ROOT / directory).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    assert node.module not in LEGACY_MODULES, path
                elif isinstance(node, ast.Import):
                    assert not LEGACY_MODULES.intersection(alias.name for alias in node.names), path


def test_legacy_navigation_entry_delegates_to_canonical_route() -> None:
    tree = ast.parse((ROOT / "ui" / "main_window.py").read_text(encoding="utf-8"))
    main_window = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MainWindow")
    method = next(
        node for node in main_window.body if isinstance(node, ast.FunctionDef) and node.name == "show_dashboard"
    )
    calls = [node for node in ast.walk(method) if isinstance(node, ast.Call)]
    assert len(calls) == 1
    assert ast.unparse(calls[0]) == "self.go_to_dashboard(user_id, username)"
