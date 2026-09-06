from collections.abc import Callable, Iterator
from typing import cast
from unittest.mock import Mock

import pytest

from utils.database import Database

try:
    from PyQt6.QtTest import QSignalSpy
    from PyQt6.QtWidgets import QApplication, QLabel, QMessageBox
except ImportError as error:
    pytest.skip(f"Native Qt libraries are unavailable: {error}", allow_module_level=True)
else:
    from ui import vulnerability_viewer as viewer_module
    from ui.vulnerability_viewer import ZapStyleVulnerabilityViewer
    from views import statistics_window as statistics_module
    from views.statistics_window import StatisticsWindow


@pytest.fixture(scope="module")
def application() -> Iterator[QApplication]:
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
        instance = QApplication.instance()
        app = instance if isinstance(instance, QApplication) else QApplication([])
        yield app
        app.closeAllWindows()


@pytest.fixture
def dialogs(monkeypatch: pytest.MonkeyPatch) -> dict[str, Mock]:
    mocks = {
        "warning": Mock(return_value=QMessageBox.StandardButton.No),
        "information": Mock(return_value=QMessageBox.StandardButton.Ok),
        "critical": Mock(return_value=QMessageBox.StandardButton.Ok),
        "question": Mock(return_value=QMessageBox.StandardButton.No),
    }
    for name, mock in mocks.items():
        monkeypatch.setattr(QMessageBox, name, mock)
    return mocks


@pytest.fixture
def make_window(
    application: QApplication,
    history_database: Database,
    monkeypatch: pytest.MonkeyPatch,
    dialogs: dict[str, Mock],
) -> Iterator[Callable[[Callable[[], bool] | None], StatisticsWindow]]:
    monkeypatch.setattr(statistics_module, "db", history_database)
    windows: list[StatisticsWindow] = []

    def create(is_scan_in_progress: Callable[[], bool] | None) -> StatisticsWindow:
        window = StatisticsWindow(1, is_scan_in_progress=is_scan_in_progress)
        windows.append(window)
        return window

    yield create
    for window in windows:
        window.close()
        window.deleteLater()
    application.processEvents()


@pytest.mark.parametrize("answer", [QMessageBox.StandardButton.No, QMessageBox.StandardButton.Close])
def test_cancel_does_not_delete_history(
    make_window: Callable[[Callable[[], bool] | None], StatisticsWindow],
    history_database: Database,
    dialogs: dict[str, Mock],
    answer: QMessageBox.StandardButton,
) -> None:
    window = make_window(None)
    dialogs["warning"].return_value = answer
    spy = QSignalSpy(window.history_cleared)

    window.clear_history_btn.click()

    assert window.scans_table.rowCount() == 2
    assert history_database.get_scan_statistics(1)["total_scans"] == 2
    assert history_database.get_scan_statistics(1)["vulnerabilities_found"] == 2
    assert len(spy) == 0
    dialogs["information"].assert_not_called()
    dialogs["critical"].assert_not_called()
    args = dialogs["warning"].call_args.args
    assert args[-1] == QMessageBox.StandardButton.No
    assert "вашего аккаунта" in args[2]
    assert "нельзя отменить" in args[2]


def test_clear_refreshes_history_charts_and_totals(
    make_window: Callable[[Callable[[], bool] | None], StatisticsWindow],
    history_database: Database,
    dialogs: dict[str, Mock],
) -> None:
    window = make_window(None)
    dialogs["warning"].return_value = QMessageBox.StandardButton.Yes
    spy = QSignalSpy(window.history_cleared)

    window.clear_history_btn.click()

    assert window.scans_table.rowCount() == 0
    assert not window.clear_history_btn.isEnabled()
    assert len(spy) == 1
    texts = [label.text() for label in window.stats_widget.findChildren(QLabel)]
    assert "Всего сканирований: 0" in texts
    assert "Всего уязвимостей: 0" in texts
    assert window.charts_layout.count() == 1
    item = window.charts_layout.itemAt(0)
    assert item is not None
    chart_placeholder = item.widget()
    assert isinstance(chart_placeholder, QLabel)
    assert chart_placeholder.text() == "Нет данных для отображения"
    assert history_database.get_all_vulnerabilities(1) == []
    assert len(history_database.get_all_vulnerabilities(2)) == 1
    dialogs["critical"].assert_not_called()
    dialogs["information"].assert_called_once()


def test_clear_deletes_all_records_not_only_displayed_hundred(
    make_window: Callable[[Callable[[], bool] | None], StatisticsWindow],
    history_database: Database,
    dialogs: dict[str, Mock],
) -> None:
    with history_database.get_db_connection_cm() as conn:
        conn.executemany(
            "INSERT INTO scans (user_id, url, result, scan_type) VALUES (?, ?, ?, ?)",
            [(1, f"https://alice.example/{index}", "[]", "general") for index in range(150)],
        )
    window = make_window(None)
    assert window.scans_table.rowCount() == 100
    dialogs["warning"].return_value = QMessageBox.StandardButton.Yes

    window.clear_history_btn.click()

    assert history_database.get_scan_statistics(1)["total_scans"] == 0
    assert history_database.get_scan_statistics(2)["total_scans"] == 1


def test_failed_clear_keeps_displayed_history_and_does_not_emit_signal(
    make_window: Callable[[Callable[[], bool] | None], StatisticsWindow],
    history_database: Database,
    monkeypatch: pytest.MonkeyPatch,
    dialogs: dict[str, Mock],
) -> None:
    window = make_window(None)
    monkeypatch.setattr(history_database, "delete_scans_by_user", Mock(return_value=False))
    dialogs["warning"].return_value = QMessageBox.StandardButton.Yes
    spy = QSignalSpy(window.history_cleared)

    window.clear_history_btn.click()

    assert window.scans_table.rowCount() == 2
    assert window.clear_history_btn.isEnabled()
    assert history_database.get_scan_statistics(1)["total_scans"] == 2
    assert len(spy) == 0
    dialogs["critical"].assert_called_once()
    dialogs["information"].assert_not_called()


def test_empty_history_does_not_request_confirmation(
    make_window: Callable[[Callable[[], bool] | None], StatisticsWindow],
    history_database: Database,
    dialogs: dict[str, Mock],
) -> None:
    assert history_database.delete_scans_by_user(1)
    window = make_window(None)
    assert not window.clear_history_btn.isEnabled()

    window.clear_scan_history()

    dialogs["warning"].assert_not_called()
    dialogs["information"].assert_called_once()
    assert history_database.get_scan_statistics(2)["total_scans"] == 1


def test_active_scan_blocks_clear_before_confirmation(
    make_window: Callable[[Callable[[], bool] | None], StatisticsWindow],
    history_database: Database,
    dialogs: dict[str, Mock],
) -> None:
    window = make_window(lambda: True)
    window.clear_history_btn.click()

    dialogs["warning"].assert_not_called()
    dialogs["information"].assert_called_once()
    assert history_database.get_scan_statistics(1)["total_scans"] == 2


def test_scan_state_is_rechecked_after_confirmation(
    make_window: Callable[[Callable[[], bool] | None], StatisticsWindow],
    history_database: Database,
    dialogs: dict[str, Mock],
) -> None:
    is_scanning = Mock(side_effect=[False, True])
    window = make_window(is_scanning)
    dialogs["warning"].return_value = QMessageBox.StandardButton.Yes
    window.clear_history_btn.click()

    dialogs["warning"].assert_called_once()
    dialogs["information"].assert_called_once()
    assert history_database.get_scan_statistics(1)["total_scans"] == 2
    assert window.scans_table.rowCount() == 2


def test_refresh_button_reloads_history(
    make_window: Callable[[Callable[[], bool] | None], StatisticsWindow], history_database: Database
) -> None:
    window = make_window(None)
    assert window.scans_table.rowCount() == 2
    assert history_database.delete_scans_by_user(1)

    window.refresh_btn.click()

    assert window.scans_table.rowCount() == 0
    assert not window.clear_history_btn.isEnabled()


@pytest.mark.parametrize("user_id", [1, 2])
def test_viewer_discards_deleted_selection_but_preserves_other_users_data(
    application: QApplication, history_database: Database, monkeypatch: pytest.MonkeyPatch, user_id: int
) -> None:
    monkeypatch.setattr(viewer_module, "db", history_database)
    viewer = ZapStyleVulnerabilityViewer(user_id)
    try:
        viewer.on_alert_clicked(0, 2)
        assert viewer.current_vulnerability is not None
        selected = viewer.current_vulnerability
        assert viewer.detail_url.text()
        assert viewer.change_status_btn.isEnabled()

        assert history_database.delete_scans_by_user(1)
        viewer.load_vulnerabilities()

        if user_id == 1:
            assert viewer.alerts_table.rowCount() == 0
            assert viewer.current_vulnerability is None
            assert viewer.detail_url.text() == ""
            assert viewer.detail_description.toPlainText() == ""
            assert viewer.request_text.toPlainText() == ""
            assert viewer.response_text.toPlainText() == ""
            assert not viewer.change_status_btn.isEnabled()
            assert not viewer.add_comment_btn.isEnabled()
            assert not viewer.export_btn.isEnabled()
            assert not viewer.report_btn.isEnabled()
        else:
            assert viewer.alerts_table.rowCount() == 1
            assert viewer.current_vulnerability == selected
            assert viewer.detail_url.text() == "https://bob.example/"
            assert viewer.change_status_btn.isEnabled()
    finally:
        viewer.close()
        viewer.deleteLater()
        application.processEvents()


def test_dashboard_refreshes_open_views_after_history_clear(
    application: QApplication,
    history_database: Database,
    monkeypatch: pytest.MonkeyPatch,
    dialogs: dict[str, Mock],
) -> None:
    from models.user_model import UserModel
    from views.dashboard_window_updated import DashboardWindow

    monkeypatch.setattr(statistics_module, "db", history_database)
    monkeypatch.setattr(viewer_module, "db", history_database)
    dashboard = DashboardWindow(1, "alice", UserModel())
    try:
        dashboard.results_table.setRowCount(1)
        assert dashboard.statistics_widget is not None
        dashboard.statistics_widget.update_stat("vulnerabilities", 2)
        dashboard.on_vulnerabilities()
        viewer = dashboard.vulnerability_viewer
        assert viewer is not None
        viewer.on_alert_clicked(0, 2)
        assert viewer.current_vulnerability is not None
        dashboard.on_statistics()
        window = dashboard.statistics_window
        assert window is not None
        dialogs["warning"].return_value = QMessageBox.StandardButton.Yes

        window.clear_history_btn.click()

        assert dashboard.results_table.rowCount() == 0
        assert dashboard.statistics_widget.get_stats()["vulnerabilities"] == 0
        assert window.scans_table.rowCount() == 0
        assert viewer.alerts_table.rowCount() == 0
        assert viewer.current_vulnerability is None
        assert "История сканирований очищена" in dashboard.log_text.toPlainText()

        # Повторное открытие использует ту же форму, но загружает новые данные.
        with history_database.get_db_connection_cm() as conn:
            conn.execute(
                "INSERT INTO scans (user_id, url, result, scan_type) VALUES (?, ?, ?, ?)",
                (1, "https://alice.example/new", "[]", "general"),
            )
        dashboard.on_statistics()
        assert dashboard.statistics_window is window
        assert window.scans_table.rowCount() == 1
    finally:
        dashboard.close()
        dashboard.deleteLater()
        application.processEvents()


def test_dashboard_considers_stopping_task_active_until_save_finishes(
    application: QApplication, history_database: Database, dialogs: dict[str, Mock]
) -> None:
    import asyncio

    from models.user_model import UserModel
    from views.dashboard_window_updated import DashboardWindow

    dashboard = DashboardWindow(1, "alice", UserModel())
    try:
        assert not dashboard.has_active_scan()
        task = Mock()
        task.done.return_value = False
        dashboard.current_scan_task = cast(asyncio.Task[None], task)
        assert dashboard.has_active_scan()

        task.done.return_value = True
        assert not dashboard.has_active_scan()

        dashboard.is_scanning = True
        assert dashboard.has_active_scan()
    finally:
        dashboard.is_scanning = False
        dashboard.current_scan_task = None
        dashboard.close()
        dashboard.deleteLater()
        application.processEvents()
