import asyncio
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio

from utils.database import Database

try:
    from PyQt6.QtCore import QCoreApplication, QEvent
    from PyQt6.QtGui import QCloseEvent
    from PyQt6.QtWidgets import QApplication, QMessageBox, QPushButton, QTableWidget, QWidget
except ImportError as error:
    pytest.skip(f"Native Qt libraries are unavailable: {error}", allow_module_level=True)
else:
    from controllers.scan_controller import ScanController
    from models.user_model import UserModel
    from ui import main_window as main_module
    from ui.main_window import MainWindow
    from utils.export_utils import ExportUtils
    from views import dashboard_window as dashboard_module
    from views.dashboard import reports
    from views.dashboard_window import DashboardWindow
    from views.statistics_widget import StatisticsWidget


@pytest.fixture
def dashboard_database(history_database: Database, monkeypatch: pytest.MonkeyPatch) -> Database:
    from ui import vulnerability_viewer
    from views import statistics_window

    monkeypatch.setattr(statistics_window, "db", history_database)
    monkeypatch.setattr(vulnerability_viewer, "db", history_database)
    return history_database


@pytest.fixture
def dashboard(
    application: QApplication, dashboard_database: Database, dialogs: dict[str, Mock]
) -> Iterator[DashboardWindow]:
    user_model = UserModel()
    user_model.set_current_user(1, "alice", "alice@example.com")
    window = DashboardWindow(1, "alice", user_model)
    yield window
    window.close()
    window.deleteLater()
    application.processEvents()


@pytest_asyncio.fixture
async def scanning_dashboard(dashboard: DashboardWindow) -> AsyncIterator[DashboardWindow]:
    yield dashboard
    task = dashboard.current_scan_task
    if task is not None and not task.done():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    # Доставляем также callback отменённой до первого шага задачи.
    await asyncio.sleep(0)


@dataclass
class ControlledScan:
    controller: ScanController
    factory: Mock
    start: AsyncMock
    started: asyncio.Event
    release: asyncio.Event
    result_ready: asyncio.Event
    settle: asyncio.Event
    pause: Mock
    resume: Mock
    stop: Mock


@pytest.fixture
def scan(monkeypatch: pytest.MonkeyPatch) -> ControlledScan:
    """Настоящие Qt-сигналы, но вместо сетевого сканирования — управляемые события."""
    controller = ScanController("https://example.com", ["sql", "xss", "csrf"], 1)
    started, release, result_ready, settle = (asyncio.Event() for _ in range(4))
    settle.set()

    async def run(**kwargs: Any) -> None:
        started.set()
        await release.wait()
        callback = cast(Callable[[dict[str, Any]], None], kwargs["on_result"])
        callback({"total_urls_scanned": 4, "total_vulnerabilities": 2, "scan_duration": 1.25})
        result_ready.set()
        await settle.wait()

    start = AsyncMock(side_effect=run)
    pause, resume, stop = Mock(), Mock(), Mock()
    monkeypatch.setattr(controller, "start_scan", start)
    monkeypatch.setattr(controller, "pause_scan", pause)
    monkeypatch.setattr(controller, "resume_scan", resume)
    monkeypatch.setattr(controller, "stop_scan", stop)
    factory = Mock(return_value=controller)
    monkeypatch.setattr(dashboard_module, "ScanController", factory)
    return ControlledScan(controller, factory, start, started, release, result_ready, settle, pause, resume, stop)


def assert_idle(window: DashboardWindow) -> None:
    assert not window.has_active_scan()
    assert window.start_scan_btn.isEnabled()
    assert not window.pause_scan_btn.isEnabled()
    assert not window.resume_scan_btn.isEnabled()
    assert not window.stop_scan_btn.isEnabled()
    for widget in (window.url_input, window.sql_checkbox, window.xss_checkbox, window.csrf_checkbox):
        assert widget.isEnabled()


async def start(window: DashboardWindow, scan: ControlledScan) -> asyncio.Task[None]:
    window.url_input.setText("example.com")
    window.start_scan_btn.click()
    task = window.current_scan_task
    assert task is not None
    await asyncio.wait_for(scan.started.wait(), timeout=2)
    return task


def test_dashboard_has_one_widget_tree_and_accepts_regular_widget_parent(
    application: QApplication, history_database: Database
) -> None:
    parent = QWidget()
    window = DashboardWindow(1, "alice", UserModel(), parent)
    try:
        assert window.parent() is parent
        assert window.centralWidget() is window.ui.central
        assert window.results_table is window.ui.results_table
        assert window.log_text is window.ui.log_text
        assert len(window.findChildren(QTableWidget)) == 1
        assert len(window.findChildren(StatisticsWidget)) == 1
        assert_idle(window)
    finally:
        parent.close()
        parent.deleteLater()
        application.processEvents()


def test_missing_running_loop_is_reported_without_creating_task(
    dashboard: DashboardWindow, scan: ControlledScan, dialogs: dict[str, Mock]
) -> None:
    dashboard.start_scan_btn.click()
    assert dashboard.current_scan_task is None
    scan.factory.assert_not_called()
    dialogs["error_message"].assert_called_once()
    assert_idle(dashboard)


@pytest.mark.asyncio
async def test_one_task_and_controller_per_scan(scanning_dashboard: DashboardWindow, scan: ControlledScan) -> None:
    task = await start(scanning_dashboard, scan)
    scanning_dashboard.start_scan_btn.click()
    await scanning_dashboard.on_start_scan()  # Повторный программный вызов также не запускает второй скан.
    assert scanning_dashboard.current_scan_task is task
    scan.factory.assert_called_once_with(
        url="https://example.com", scan_types=["sql", "xss", "csrf"], user_id=1, username="alice", timeout=30
    )
    assert scan.start.await_count == 1
    assert not scanning_dashboard.url_input.isEnabled()
    assert not scanning_dashboard.start_scan_btn.isEnabled()

    scan.release.set()
    await task
    assert_idle(scanning_dashboard)
    assert "Сканирование завершено" in scanning_dashboard.log_text.toPlainText()


@pytest.mark.asyncio
async def test_pause_resume_and_stop_wait_for_task_completion(
    scanning_dashboard: DashboardWindow, scan: ControlledScan, dialogs: dict[str, Mock]
) -> None:
    task = await start(scanning_dashboard, scan)
    scanning_dashboard.pause_scan_btn.click()
    scan.pause.assert_called_once()
    assert not scanning_dashboard.pause_scan_btn.isEnabled()
    assert scanning_dashboard.resume_scan_btn.isEnabled()
    assert scanning_dashboard.has_active_scan()

    scanning_dashboard.resume_scan_btn.click()
    scan.resume.assert_called_once()
    assert scanning_dashboard.pause_scan_btn.isEnabled()
    assert not scanning_dashboard.resume_scan_btn.isEnabled()

    # Отмена остановки сохраняет состояние.
    scanning_dashboard.stop_scan_btn.click()
    scan.stop.assert_not_called()
    assert scanning_dashboard.has_active_scan()
    dialogs["question"].return_value = QMessageBox.StandardButton.Yes
    scanning_dashboard.stop_scan_btn.click()
    scan.stop.assert_called_once()
    assert scanning_dashboard.has_active_scan()
    for button in (
        scanning_dashboard.start_scan_btn,
        scanning_dashboard.pause_scan_btn,
        scanning_dashboard.resume_scan_btn,
        scanning_dashboard.stop_scan_btn,
    ):
        assert not button.isEnabled()
    assert not scanning_dashboard.url_input.isEnabled()
    await scanning_dashboard.on_start_scan()
    scan.factory.assert_called_once()

    scan.release.set()
    await task
    assert_idle(scanning_dashboard)
    assert "Сканирование остановлено" in scanning_dashboard.log_text.toPlainText()


@pytest.mark.asyncio
async def test_result_callback_does_not_unlock_running_task(
    scanning_dashboard: DashboardWindow, scan: ControlledScan
) -> None:
    scan.settle.clear()
    task = await start(scanning_dashboard, scan)
    scan.release.set()
    await asyncio.wait_for(scan.result_ready.wait(), timeout=2)
    assert scanning_dashboard.has_active_scan()
    assert not scanning_dashboard.start_scan_btn.isEnabled()
    scan.settle.set()
    await task
    assert_idle(scanning_dashboard)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_point", ["constructor", "scan"])
async def test_failure_restores_all_controls(
    scanning_dashboard: DashboardWindow, scan: ControlledScan, dialogs: dict[str, Mock], failure_point: str
) -> None:
    if failure_point == "constructor":
        scan.factory.side_effect = RuntimeError("constructor failed")
    else:
        scan.start.side_effect = RuntimeError("scan failed")
    scanning_dashboard.url_input.setText("https://example.com")
    scanning_dashboard.start_scan_btn.click()
    task = scanning_dashboard.current_scan_task
    assert task is not None
    await task
    assert_idle(scanning_dashboard)
    dialogs["error_message"].assert_called_once()


@pytest.mark.asyncio
async def test_cancelled_task_restores_all_controls(scanning_dashboard: DashboardWindow, scan: ControlledScan) -> None:
    task = await start(scanning_dashboard, scan)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    scan.stop.assert_called_once()
    assert_idle(scanning_dashboard)


@pytest.mark.asyncio
async def test_cancel_before_first_step_is_also_cleaned_up(
    scanning_dashboard: DashboardWindow, scan: ControlledScan
) -> None:
    scanning_dashboard.start_scan_btn.click()
    task = scanning_dashboard.current_scan_task
    assert task is not None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)
    scan.factory.assert_not_called()
    assert_idle(scanning_dashboard)


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["", "ftp://example.com"])
async def test_rejected_parameters_keep_previous_results(
    scanning_dashboard: DashboardWindow, scan: ControlledScan, dialogs: dict[str, Mock], url: str
) -> None:
    scanning_dashboard.on_vulnerability_found("https://example.com", "sql", "parameter=id")
    scanning_dashboard.url_input.setText(url)
    await scanning_dashboard.on_start_scan()
    scan.factory.assert_not_called()
    assert scanning_dashboard.results_table.rowCount() == 1
    assert_idle(scanning_dashboard)
    dialogs["error_message"].assert_called_once()


@pytest.mark.asyncio
async def test_security_warning_defaults_to_no_and_cancel_does_not_start_scan(
    scanning_dashboard: DashboardWindow,
    scan: ControlledScan,
    dialogs: dict[str, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dashboard_module, "is_safe_url", Mock(return_value=False))
    scanning_dashboard.url_input.setText("https://example.com")
    await scanning_dashboard.on_start_scan()
    assert dialogs["question"].call_args.args[-1] == QMessageBox.StandardButton.No
    scan.factory.assert_not_called()
    assert_idle(scanning_dashboard)


@pytest.mark.asyncio
async def test_controller_signals_update_statistics_progress_and_findings(
    scanning_dashboard: DashboardWindow, scan: ControlledScan
) -> None:
    task = await start(scanning_dashboard, scan)
    scan.controller.signals.stats_updated.emit("urls_scanned", "7")
    scan.controller.signals.stats_updated.emit("scan_time", "00:00:03")
    scan.controller.signals.progress_updated.emit(150)
    scan.controller.signals.vulnerability_found.emit("https://example.com", "sql", "parameter=id")
    message = "<script>not markup</script>\n  SELECT  'a  b'"
    scan.controller.signals.log_event.emit(message)
    stats = scanning_dashboard.statistics_widget.get_stats()
    assert stats["urls_scanned"] == 7
    assert stats["scan_time"] == "00:00:03"
    assert stats["progress"] == 100
    assert scanning_dashboard.results_table.rowCount() == 1
    assert message in scanning_dashboard.log_text.toPlainText()
    scan.release.set()
    await task


def test_profile_button_and_updated_username(dashboard: DashboardWindow, monkeypatch: pytest.MonkeyPatch) -> None:
    from views import edit_profile_window

    dialog = Mock()
    factory = Mock(return_value=dialog)
    monkeypatch.setattr(edit_profile_window, "EditProfileWindow", factory)
    dashboard.ui.profile_btn.click()
    factory.assert_called_once_with(1, "alice", dashboard)
    dialog.exec.assert_called_once()
    dashboard.username = "new_name"
    dashboard.update_profile_info()
    assert "new_name" in dashboard.windowTitle()
    assert "new_name" in dashboard.ui.profile_label.text()


@pytest.mark.parametrize("format_name", [*reports.REPORT_FORMATS, "Отмена", None])
def test_report_format_selection_and_cancellation(
    dashboard: DashboardWindow, monkeypatch: pytest.MonkeyPatch, format_name: str | None
) -> None:
    def execute(dialog: QMessageBox) -> int:
        escape_button = dialog.escapeButton()
        assert escape_button is not None and escape_button.text() == "Отмена"
        return 0

    button = QPushButton(format_name) if format_name is not None else None
    monkeypatch.setattr(QMessageBox, "exec", execute)
    monkeypatch.setattr(QMessageBox, "clickedButton", Mock(return_value=button))
    selected = reports.select_report_format(dashboard)
    if format_name in reports.REPORT_FORMATS:
        assert selected == (format_name, reports.REPORT_FORMATS[format_name])
    else:
        assert selected is None


def test_export_preserves_columns_and_user_and_does_not_report_cancel_as_failure(
    dashboard: DashboardWindow, dialogs: dict[str, Mock], monkeypatch: pytest.MonkeyPatch
) -> None:
    choose = Mock(return_value=("CSV", "csv"))
    export = Mock(return_value=False)  # Например, отмена выбора пути в ExportUtils.
    monkeypatch.setattr(reports, "select_report_format", choose)
    monkeypatch.setattr(ExportUtils, "export_data", export)
    dashboard.ui.reports_btn.click()
    choose.assert_not_called()
    dialogs["info_message"].assert_called_once()

    dashboard.on_vulnerability_found("https://example.com", "sql", "parameter=id")
    dashboard.results_table.insertRow(1)  # Незавершённая строка не экспортируется.
    rows = reports.collect_report_rows(dashboard.results_table)
    assert len(rows) == 1
    assert tuple(rows[0]) == reports.REPORT_COLUMNS
    assert rows[0]["URL"] == "https://example.com"
    dashboard.ui.reports_btn.click()
    export.assert_called_once_with(dashboard, rows, "CSV", "csv", 1)
    dialogs["error_message"].assert_not_called()


@pytest.mark.asyncio
async def test_logout_confirms_once_and_waits_for_scan(
    scanning_dashboard: DashboardWindow, scan: ControlledScan, dialogs: dict[str, Mock]
) -> None:
    logout = Mock()
    cast(Any, scanning_dashboard.logout_requested).connect(logout)
    task = await start(scanning_dashboard, scan)
    scanning_dashboard.on_logout()
    scan.stop.assert_not_called()
    logout.assert_not_called()
    assert scanning_dashboard.user_model.get_user_id() == 1

    dialogs["question"].reset_mock()
    dialogs["question"].return_value = QMessageBox.StandardButton.Yes
    scanning_dashboard.on_logout()
    dialogs["question"].assert_called_once()
    scan.stop.assert_called_once()
    logout.assert_not_called()
    assert scanning_dashboard.has_active_scan()
    scan.release.set()
    await task
    logout.assert_called_once_with()
    assert scanning_dashboard.user_model.get_user_id() is None
    assert_idle(scanning_dashboard)


@pytest.mark.asyncio
async def test_close_confirms_once_and_waits_for_scan(
    scanning_dashboard: DashboardWindow, scan: ControlledScan, dialogs: dict[str, Mock]
) -> None:
    task = await start(scanning_dashboard, scan)
    on_ready = Mock()
    assert not scanning_dashboard.prepare_close(on_ready)
    scan.stop.assert_not_called()
    dialogs["question"].reset_mock()
    dialogs["question"].return_value = QMessageBox.StandardButton.Yes
    assert not scanning_dashboard.prepare_close(on_ready)
    assert not scanning_dashboard.prepare_close(on_ready)  # Повторное событие закрытия, без второго диалога.
    dialogs["question"].assert_called_once()
    scan.stop.assert_called_once()
    on_ready.assert_not_called()
    scan.release.set()
    await task
    on_ready.assert_called_once_with()
    assert scanning_dashboard.prepare_close(on_ready)


@pytest.fixture
def main_window(
    application: QApplication,
    dashboard_database: Database,
    dialogs: dict[str, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[MainWindow]:
    # Не запускаем загрузчик main.py и очистку кэшей при тестировании навигации.
    monkeypatch.setattr(main_module.LoginWindow, "load_styles", Mock())
    monkeypatch.setattr(main_module, "cleanup_on_exit", Mock(return_value={"all_successful": True}))
    model = UserModel()
    model.set_current_user(1, "alice", "alice@example.com")
    window = MainWindow(model)
    yield window
    window.close()
    window.deleteLater()
    application.processEvents()


def test_both_main_window_routes_use_same_class_and_logout_works_through_stack(
    main_window: MainWindow, dialogs: dict[str, Mock], application: QApplication
) -> None:
    main_window.on_mode_selected("gui", 1, "alice")
    first = main_window.dashboard_window
    assert type(first) is DashboardWindow
    assert first.parent() is main_window.stack
    assert first.user_model is main_window.user_model
    first.on_statistics()
    first.on_vulnerabilities()
    assert first.statistics_window is not None
    assert first.vulnerability_viewer is not None
    timer = first.vulnerability_viewer.refresh_timer

    main_window.show_dashboard(1, "alice")
    second = main_window.dashboard_window
    assert type(second) is DashboardWindow
    assert second is not first
    assert main_window.stack.indexOf(first) == -1
    assert not timer.isActive()
    assert main_window.stack.currentWidget() is second
    assert second.receivers(second.logout_requested) == 1
    dialogs["question"].return_value = QMessageBox.StandardButton.Yes
    second.on_logout()
    assert main_window.dashboard_window is None
    assert main_window.stack.currentWidget() is main_window.login_window
    assert main_window.user_model.get_user_id() is None
    application.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


@pytest.mark.parametrize("route", ["go_to_dashboard", "show_dashboard"])
def test_main_window_routes_reject_invalid_identity(main_window: MainWindow, route: str) -> None:
    navigate = getattr(main_window, route)
    navigate(0, "alice")
    assert main_window.dashboard_window is None
    navigate(1, " ")
    assert main_window.dashboard_window is None


def test_constructor_failure_keeps_previous_dashboard(
    main_window: MainWindow, monkeypatch: pytest.MonkeyPatch, dialogs: dict[str, Mock]
) -> None:
    main_window.go_to_dashboard(1, "alice")
    previous = main_window.dashboard_window
    assert previous is not None
    monkeypatch.setattr(main_module, "DashboardWindow", Mock(side_effect=RuntimeError("constructor failed")))
    main_window.show_dashboard(1, "alice")
    assert main_window.dashboard_window is previous
    assert main_window.stack.currentWidget() is previous
    dialogs["error_message"].assert_called_once()


@pytest.mark.asyncio
async def test_main_window_close_waits_before_cache_cleanup(
    main_window: MainWindow, scan: ControlledScan, dialogs: dict[str, Mock], monkeypatch: pytest.MonkeyPatch
) -> None:
    main_window.go_to_dashboard(1, "alice")
    panel = main_window.dashboard_window
    assert panel is not None
    cleanup = Mock(return_value={"all_successful": True})
    monkeypatch.setattr(main_module, "cleanup_on_exit", cleanup)
    task = await start(panel, scan)
    try:
        event = QCloseEvent()
        main_window.closeEvent(event)
        assert not event.isAccepted()
        cleanup.assert_not_called()

        dialogs["question"].return_value = QMessageBox.StandardButton.Yes
        main_window.closeEvent(QCloseEvent())
        scan.stop.assert_called_once()
        cleanup.assert_not_called()
        scan.release.set()
        await task
        cleanup.assert_called_once_with(safe_mode=True)
        assert not panel.has_active_scan()
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_two_clicks_before_first_task_step_share_one_task(
    scanning_dashboard: DashboardWindow, scan: ControlledScan
) -> None:
    scanning_dashboard.url_input.setText("https://example.com")
    scanning_dashboard.start_scan_btn.click()
    task = scanning_dashboard.current_scan_task
    assert task is not None
    scanning_dashboard.start_scan_btn.click()
    assert scanning_dashboard.current_scan_task is task
    await asyncio.wait_for(scan.started.wait(), timeout=2)
    scan.factory.assert_called_once()
    scan.release.set()
    await task
    assert_idle(scanning_dashboard)


@pytest.mark.asyncio
async def test_direct_await_does_not_retain_caller_and_preserves_scan_settings(
    scanning_dashboard: DashboardWindow, scan: ControlledScan
) -> None:
    scanning_dashboard.url_input.setText("https://example.com")
    scanning_dashboard.sql_checkbox.setChecked(False)
    scanning_dashboard.csrf_checkbox.setChecked(False)
    scan.release.set()
    await scanning_dashboard.on_start_scan()
    scan.factory.assert_called_once_with(
        url="https://example.com", scan_types=["xss"], user_id=1, username="alice", timeout=30
    )
    assert scan.controller.max_depth == 10
    assert scan.controller.max_concurrent == 5
    assert scanning_dashboard.current_scan_task is None
    assert_idle(scanning_dashboard)


@pytest.mark.asyncio
async def test_close_before_task_starts_cancels_only_queued_scan(
    scanning_dashboard: DashboardWindow, scan: ControlledScan, dialogs: dict[str, Mock]
) -> None:
    scanning_dashboard.start_scan_btn.click()
    task = scanning_dashboard.current_scan_task
    assert task is not None
    on_ready = Mock()
    dialogs["question"].return_value = QMessageBox.StandardButton.Yes
    assert not scanning_dashboard.prepare_close(on_ready)
    on_ready.assert_not_called()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)
    scan.factory.assert_not_called()
    scan.stop.assert_not_called()
    on_ready.assert_called_once()
    assert_idle(scanning_dashboard)


@pytest.mark.asyncio
async def test_failed_stop_does_not_log_out_or_leave_pending_exit(
    scanning_dashboard: DashboardWindow, scan: ControlledScan, dialogs: dict[str, Mock]
) -> None:
    logout = Mock()
    cast(Any, scanning_dashboard.logout_requested).connect(logout)
    task = await start(scanning_dashboard, scan)
    scan.stop.side_effect = RuntimeError("stop failed")
    dialogs["question"].return_value = QMessageBox.StandardButton.Yes
    scanning_dashboard.on_logout()
    dialogs["error_message"].assert_called_once()
    assert scanning_dashboard.has_active_scan()
    assert scanning_dashboard.stop_scan_btn.isEnabled()
    assert scanning_dashboard.user_model.get_user_id() == 1
    scan.release.set()
    await task
    logout.assert_not_called()
    assert_idle(scanning_dashboard)


@pytest.mark.asyncio
async def test_history_is_blocked_during_paused_stop_and_unlocked_after_settlement(
    scanning_dashboard: DashboardWindow,
    scan: ControlledScan,
    dialogs: dict[str, Mock],
    dashboard_database: Database,
) -> None:
    task = await start(scanning_dashboard, scan)
    scanning_dashboard.on_pause_scan()
    scanning_dashboard.on_statistics()
    history = scanning_dashboard.statistics_window
    assert history is not None
    assert history.scans_table.rowCount() == 2
    dialogs["question"].return_value = QMessageBox.StandardButton.Yes
    scanning_dashboard.on_stop_scan()
    scan.stop.assert_called_once()
    scan.resume.assert_not_called()
    history.clear_history_btn.click()
    dialogs["warning"].assert_not_called()
    dialogs["information"].assert_called_once()
    assert dashboard_database.get_scan_statistics(1)["total_scans"] == 2
    scan.release.set()
    await task
    dialogs["warning"].return_value = QMessageBox.StandardButton.Yes
    history.clear_history_btn.click()
    assert dashboard_database.get_scan_statistics(1)["total_scans"] == 0
    assert dashboard_database.get_scan_statistics(2)["total_scans"] == 1
    assert_idle(scanning_dashboard)


def test_results_preserve_location_tooltip_and_log_has_a_memory_bound(dashboard: DashboardWindow) -> None:
    details = "SQL Injection | Параметр: id | Метод: GET | URL: https://example.com"
    dashboard.on_vulnerability_found("https://example.com", "sql", details)
    location = dashboard.results_table.item(0, 2)
    assert location is not None
    assert location.text() == "Параметр: id | Метод: GET"
    assert location.toolTip() == details
    assert location.background().color().name() == "#ffcccc"
    assert dashboard.results_table.editTriggers() == QTableWidget.EditTrigger.NoEditTriggers
    document = dashboard.log_text.document()
    assert document is not None and document.maximumBlockCount() == 2000
    assert dashboard.log_text.isReadOnly()


@pytest.mark.parametrize("route", ["login", "dashboard"])
@pytest.mark.asyncio
async def test_navigation_does_not_delete_dashboard_while_scan_is_pending(
    main_window: MainWindow, scan: ControlledScan, dialogs: dict[str, Mock], route: str
) -> None:
    main_window.go_to_dashboard(1, "alice")
    previous = main_window.dashboard_window
    assert previous is not None
    task = await start(previous, scan)
    try:
        dialogs["question"].return_value = QMessageBox.StandardButton.Yes
        if route == "login":
            main_window.go_to_login()
        else:
            main_window.show_dashboard(1, "alice")
        assert main_window.dashboard_window is previous
        assert main_window.stack.currentWidget() is previous
        scan.stop.assert_called_once()
        scan.release.set()
        await task
        assert main_window.dashboard_window is not previous
        if route == "login":
            assert main_window.dashboard_window is None
            assert main_window.stack.currentWidget() is main_window.login_window
        else:
            assert type(main_window.dashboard_window) is DashboardWindow
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
