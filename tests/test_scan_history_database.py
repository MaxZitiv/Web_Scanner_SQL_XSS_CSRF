from typing import Any

import pytest

from utils.database import Database


def database_rows(database: Database) -> dict[str, list[tuple[Any, ...]]]:
    """Снимок всех пользовательских данных для проверки изоляции и отката."""
    conn = database.get_db_connection()
    return {
        "users": [tuple(row) for row in conn.execute("SELECT * FROM users ORDER BY id")],
        "scans": [tuple(row) for row in conn.execute("SELECT * FROM scans ORDER BY id")],
        "vulnerabilities": [tuple(row) for row in conn.execute("SELECT * FROM vulnerabilities ORDER BY id")],
    }


@pytest.mark.parametrize("foreign_keys", [0, 1])
def test_clear_history_removes_only_owners_scans_and_vulnerabilities(
    history_database: Database, foreign_keys: int
) -> None:
    conn = history_database.get_db_connection()
    conn.execute(f"PRAGMA foreign_keys = {foreign_keys}")
    before = database_rows(history_database)

    assert history_database.delete_scans_by_user(1)

    # Проверяем сохранение результата на диске, а не только текущее соединение.
    history_database.get_db_connection().close()
    after = database_rows(history_database)
    assert after["users"] == before["users"]
    assert after["scans"] == [before["scans"][2]]
    assert after["vulnerabilities"] == [before["vulnerabilities"][2]]
    assert history_database.get_scan_statistics(1)["total_scans"] == 0
    assert history_database.get_scan_statistics(1)["vulnerabilities_found"] == 0
    assert history_database.get_scan_statistics(2)["total_scans"] == 1
    assert history_database.get_scan_statistics(2)["vulnerabilities_found"] == 1


@pytest.mark.parametrize("user_id", [0, -1])
def test_invalid_user_id_cannot_clear_any_history(history_database: Database, user_id: int) -> None:
    before = database_rows(history_database)
    assert not history_database.delete_scans_by_user(user_id)
    assert database_rows(history_database) == before


def test_unknown_user_cannot_clear_another_users_history(history_database: Database) -> None:
    before = database_rows(history_database)
    assert history_database.delete_scans_by_user(999)
    assert database_rows(history_database) == before


def test_clearing_history_is_idempotent(history_database: Database) -> None:
    assert history_database.delete_scans_by_user(1)
    after_first_clear = database_rows(history_database)
    assert history_database.delete_scans_by_user(1)
    assert database_rows(history_database) == after_first_clear


def test_empty_database_can_be_cleared(database: Database) -> None:
    assert database.delete_scans_by_user(1)
    assert database_rows(database) == {"users": [], "scans": [], "vulnerabilities": []}


@pytest.mark.parametrize("table", ["scans", "vulnerabilities"])
def test_failed_deletion_rolls_back_both_tables(history_database: Database, table: str) -> None:
    before = database_rows(history_database)
    with history_database.get_db_connection_cm() as conn:
        conn.execute(f"""
            CREATE TRIGGER reject_history_cleanup BEFORE DELETE ON {table}
            BEGIN
                SELECT RAISE(ABORT, 'Simulated deletion failure');
            END
        """)

    assert not history_database.delete_scans_by_user(1)
    assert database_rows(history_database) == before


def test_clear_history_is_not_limited_to_visible_page(history_database: Database) -> None:
    with history_database.get_db_connection_cm() as conn:
        conn.executemany(
            "INSERT INTO scans (user_id, url, result, scan_type) VALUES (?, ?, ?, ?)",
            [(1, f"https://alice.example/{index}", "[]", "general") for index in range(150)],
        )

    assert history_database.get_scan_statistics(1)["total_scans"] == 152
    assert history_database.delete_scans_by_user(1)
    assert history_database.get_scans_by_user(1) == []
    assert history_database.get_all_vulnerabilities(1) == []
    assert len(history_database.get_scans_by_user(2)) == 1
    assert len(history_database.get_all_vulnerabilities(2)) == 1
