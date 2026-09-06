"""Изолированные БД: тесты не открывают историю из рабочей копии приложения."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import chdir
from logging import FileHandler
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

# Уже импорт utils.__init__ создаёт глобальную БД. Временно меняем рабочую
# директорию ДО импорта любого utils-модуля, а не только Database.
_bootstrap_directory = TemporaryDirectory(prefix="scanner-test-bootstrap-")
with chdir(_bootstrap_directory.name):
    from utils import database as database_module

    database_module.db.get_db_connection().close()


def pytest_unconfigure() -> None:
    # Логи bootstrap тоже находятся во временной директории. На Windows
    # открытые файловые обработчики нужно закрыть до её удаления.
    for handler in database_module.logger.handlers[:]:
        if isinstance(handler, FileHandler) and Path(handler.baseFilename).is_relative_to(_bootstrap_directory.name):
            database_module.logger.removeHandler(handler)
            handler.close()
    _bootstrap_directory.cleanup()


@pytest.fixture
def database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[database_module.Database]:
    # Ошибки транзакций в тестах не должны отправлять SMTP-уведомления.
    monkeypatch.setattr(database_module, "log_and_notify", Mock())
    monkeypatch.setattr(database_module, "get_bundle_root", lambda: str(tmp_path))
    isolated_db = database_module.Database(str(tmp_path / "history.db"))
    monkeypatch.setattr(database_module, "db", isolated_db)
    yield isolated_db
    isolated_db.get_db_connection().close()


@pytest.fixture
def history_database(database: database_module.Database) -> database_module.Database:
    """Два сканирования Alice и одно Bob, каждое со своей уязвимостью."""
    with database.get_db_connection_cm() as conn:
        conn.executemany(
            "INSERT INTO users (id, username, password_hash, email) VALUES (?, ?, ?, ?)",
            [(1, "alice", "hash", "alice@example.com"), (2, "bob", "hash", "bob@example.com")],
        )
        conn.executemany(
            "INSERT INTO scans (id, user_id, url, result, scan_type) VALUES (?, ?, ?, ?, ?)",
            [
                (1, 1, "https://alice.example/first", "[]", "sql"),
                (2, 1, "https://alice.example/second", "[]", "xss"),
                (3, 2, "https://bob.example/", "[]", "csrf"),
            ],
        )
        conn.executemany(
            "INSERT INTO vulnerabilities (id, scan_id, url, type, description) VALUES (?, ?, ?, ?, ?)",
            [
                (1, 1, "https://alice.example/first", "sql", "First finding"),
                (2, 2, "https://alice.example/second", "xss", "Second finding"),
                (3, 3, "https://bob.example/", "csrf", "Bob's finding"),
            ],
        )
    return database


@pytest.fixture(scope="session")
def application() -> Iterator[QApplication]:
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError as error:
        pytest.skip(f"Native Qt libraries are unavailable: {error}")

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
        instance = QApplication.instance()
        app = instance if isinstance(instance, QApplication) else QApplication([])
        app.setQuitOnLastWindowClosed(False)
        yield app
        app.closeAllWindows()


@pytest.fixture
def dialogs(monkeypatch: pytest.MonkeyPatch) -> dict[str, Mock]:
    from PyQt6.QtWidgets import QMessageBox

    from utils.error_handler import error_handler

    mocks = {
        "warning": Mock(return_value=QMessageBox.StandardButton.No),
        "information": Mock(return_value=QMessageBox.StandardButton.Ok),
        "critical": Mock(return_value=QMessageBox.StandardButton.Ok),
        "question": Mock(return_value=QMessageBox.StandardButton.No),
    }
    for name, mock in mocks.items():
        monkeypatch.setattr(QMessageBox, name, mock)
    for name in ("error_message", "info_message", "warning_message"):
        mocks[name] = Mock()
        monkeypatch.setattr(error_handler, f"show_{name}", mocks[name])
    return mocks
