"""Единственная панель управления: связывает виджеты, сканер и навигацию."""

import asyncio
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import QMainWindow, QMessageBox, QWidget

from controllers.scan_controller import ScanController
from models.user_model import UserModel
from utils.error_handler import error_handler
from utils.logger import logger
from utils.security import is_safe_url
from views.dashboard.presentation import add_vulnerability_row, append_log, normalize_stat_value, scan_summary
from views.dashboard.reports import export_dashboard_report
from views.dashboard.scan_state import ScanState, apply_scan_controls, prepare_scan_options
from views.dashboard.widgets import DASHBOARD_STYLE, build_dashboard_ui

if TYPE_CHECKING:
    from ui.vulnerability_viewer import ZapStyleVulnerabilityViewer
    from views.statistics_window import StatisticsWindow


class DashboardWindow(QMainWindow):
    """Панель пользователя с одним владельцем асинхронной задачи сканирования."""

    logout_requested = pyqtSignal()

    def __init__(self, user_id: int, username: str, user_model: UserModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.user_id = user_id
        self.username = username
        self.user_model = user_model
        self.scan_controller: ScanController | None = None
        self.current_scan_task: asyncio.Task[None] | None = None
        self.is_scanning = False
        self._scan_state = ScanState.IDLE
        self._pending_exit: Callable[[], object] | None = None
        self.statistics_window: StatisticsWindow | None = None
        self.vulnerability_viewer: ZapStyleVulnerabilityViewer | None = None

        self.ui = build_dashboard_ui(self, username)
        self.setCentralWidget(self.ui.central)
        self.setGeometry(100, 100, 1400, 950)
        self.setStyleSheet(DASHBOARD_STYLE)
        self.update_profile_info()

        # Сохраняем используемые другими компонентами имена виджетов.
        # Это ссылки на единственный набор объектов, а не второй интерфейс.
        self.url_input = self.ui.url_input
        self.sql_checkbox = self.ui.sql_checkbox
        self.xss_checkbox = self.ui.xss_checkbox
        self.csrf_checkbox = self.ui.csrf_checkbox
        self.start_scan_btn = self.ui.start_scan_btn
        self.pause_scan_btn = self.ui.pause_scan_btn
        self.resume_scan_btn = self.ui.resume_scan_btn
        self.stop_scan_btn = self.ui.stop_scan_btn
        self.statistics_widget = self.ui.statistics_widget
        self.results_table = self.ui.results_table
        self.log_text = self.ui.log_text
        self._restore_scan_controls()

        for button, handler in (
            (self.ui.profile_btn, self.on_profile),
            (self.ui.statistics_btn, self.on_statistics),
            (self.ui.reports_btn, self.on_reports),
            (self.ui.vulnerabilities_btn, self.on_vulnerabilities),
            (self.ui.logout_btn, self.on_logout),
            (self.start_scan_btn, self._start_scan_wrapper),
            (self.pause_scan_btn, self.on_pause_scan),
            (self.resume_scan_btn, self.on_resume_scan),
            (self.stop_scan_btn, self.on_stop_scan),
        ):
            cast(Any, button.clicked).connect(handler)
        logger.info(f"DashboardWindow инициализирован для пользователя {username} (ID: {user_id})")

    def update_profile_info(self) -> None:
        """Вызывается также окном редактирования профиля после смены имени."""
        self.setWindowTitle(f"Web Scanner - {self.username}")
        self.ui.profile_label.setText(f"👤 Пользователь: {self.username}")

    def _show_error(self, context: str, error: Exception) -> None:
        logger.error(f"{context}: {error}", exc_info=True)
        error_handler.show_error_message("Ошибка", f"{context}: {error}")

    # --- Дочерние окна и отчёты ---
    def on_profile(self) -> None:
        try:
            from views.edit_profile_window import EditProfileWindow

            EditProfileWindow(self.user_id, self.username, self).exec()
        except Exception as error:
            self._show_error("Не удалось открыть профиль", error)

    def on_statistics(self) -> None:
        try:
            from views.statistics_window import StatisticsWindow

            if self.statistics_window is None:
                self.statistics_window = StatisticsWindow(self.user_id, self, is_scan_in_progress=self.has_active_scan)
                cast(Any, self.statistics_window.history_cleared).connect(self.on_scan_history_cleared)
            else:
                self.statistics_window.load_statistics()
            self.statistics_window.show()
            self.statistics_window.raise_()
            self.statistics_window.activateWindow()
        except Exception as error:
            self._show_error("Не удалось открыть статистику", error)

    def on_vulnerabilities(self) -> None:
        try:
            from ui.vulnerability_viewer import ZapStyleVulnerabilityViewer

            if self.vulnerability_viewer is None:
                self.vulnerability_viewer = ZapStyleVulnerabilityViewer(self.user_id, self)
            else:
                self.vulnerability_viewer.load_vulnerabilities()
                self.vulnerability_viewer.refresh_timer.start(30000)
            self.vulnerability_viewer.show()
            self.vulnerability_viewer.raise_()
            self.vulnerability_viewer.activateWindow()
        except Exception as error:
            self._show_error("Не удалось открыть просмотр уязвимостей", error)

    def on_reports(self) -> None:
        try:
            export_dashboard_report(self, self.results_table, self.user_id)
        except Exception as error:
            self._show_error("Не удалось создать отчёт", error)

    def on_scan_history_cleared(self) -> None:
        self.results_table.setRowCount(0)
        self.reset_scan_stats()
        if self.vulnerability_viewer is not None:
            self.vulnerability_viewer.load_vulnerabilities()
        self.on_log_event("🗑 История сканирований очищена")

    # --- Состояние и жизненный цикл сканирования ---
    def has_active_scan(self) -> bool:
        return self.is_scanning or (self.current_scan_task is not None and not self.current_scan_task.done())

    def _set_scan_state(self, state: ScanState) -> None:
        self._scan_state = state
        self.is_scanning = state is not ScanState.IDLE
        apply_scan_controls(self.ui, state)

    def _restore_scan_controls(self) -> None:
        self._set_scan_state(ScanState.IDLE)

    def _start_scan_wrapper(self) -> None:
        if self.has_active_scan():
            return
        try:
            # Приложение создаёт qasync loop в main.py. Нельзя создавать здесь
            # второй, не запущенный цикл, в котором задача никогда не выполнится.
            loop = asyncio.get_running_loop()
        except RuntimeError as error:
            self._show_error("Цикл событий сканирования не запущен", error)
            return
        task = loop.create_task(self.on_start_scan())
        self.current_scan_task = task
        task.add_done_callback(self._scan_task_finished)

    async def on_start_scan(self) -> None:
        task = asyncio.current_task()
        if self.has_active_scan() and (self.current_scan_task is not task or self.is_scanning):
            return
        self.current_scan_task = task
        controller: ScanController | None = None
        try:
            scan_types = [
                scan_type
                for checkbox, scan_type in (
                    (self.sql_checkbox, "sql"),
                    (self.xss_checkbox, "xss"),
                    (self.csrf_checkbox, "csrf"),
                )
                if checkbox.isChecked()
            ]
            options = prepare_scan_options(self.url_input.text(), scan_types)
            self.url_input.setText(options.url)
            if not is_safe_url(options.url):
                reply = QMessageBox.question(
                    self,
                    "⚠️ Предупреждение безопасности",
                    "URL может быть небезопасным. Продолжить?\n\n"
                    "Сканируйте только свои сайты или сайты, на которые у вас есть разрешение.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
            if self._scan_state is ScanState.STOPPING or (task is not None and task.cancelling()):
                return

            # Глубина и параллельность определены только в ScanController:
            # оба пути запуска GUI используют его настройки полного сканирования.
            controller = ScanController(
                url=options.url,
                scan_types=list(options.scan_types),
                user_id=self.user_id,
                username=self.username,
                timeout=options.timeout,
            )
            self.scan_controller = controller
            self._connect_scan_signals(controller)
            self.results_table.setRowCount(0)
            self.log_text.clear()
            self.reset_scan_stats()
            self._set_scan_state(ScanState.RUNNING)
            for message in (
                "🚀 НАЧИНАЕМ СКАНИРОВАНИЕ",
                f"📍 URL: {options.url}",
                f"🔍 Типы сканирования: {', '.join(options.scan_types)}",
                f"👤 Пользователь: {self.username}",
                f"🕐 Время начала: {datetime.now():%H:%M:%S}",
            ):
                self.on_log_event(message)
            await controller.start_scan(
                url=options.url,
                scan_types=list(options.scan_types),
                timeout=options.timeout,
                on_log=self.on_log_event,
                on_result=self.on_scan_complete,
            )
        except asyncio.CancelledError:
            if controller is not None:
                controller.stop_scan()
            self.on_log_event("⏹ Задача сканирования отменена")
            raise
        except Exception as error:
            self._show_error("Не удалось выполнить сканирование", error)
        finally:
            # Один путь восстановления для завершения, ошибки, отмены и
            # отклонённых параметров; вложенная фоновая задача больше не нужна.
            if self.current_scan_task is task:
                self.current_scan_task = None
                self._restore_scan_controls()
                self._finish_pending_exit()

    def _scan_task_finished(self, task: asyncio.Task[None]) -> None:
        # Если задача отменена ещё до первого шага, её finally не выполнится.
        if self.current_scan_task is task:
            self.current_scan_task = None
            self._restore_scan_controls()
            self._finish_pending_exit()
        if not task.cancelled() and (error := task.exception()) is not None:
            logger.error(f"Необработанная ошибка задачи сканирования: {error}")

    def _connect_scan_signals(self, controller: ScanController) -> None:
        signals = controller.signals
        cast(Any, signals.stats_updated).connect(self.on_stats_updated)
        cast(Any, signals.progress_updated).connect(self.update_progress_in_main_thread)
        cast(Any, signals.log_event).connect(self.on_log_event)
        cast(Any, signals.vulnerability_found).connect(self.on_vulnerability_found)
        cast(Any, signals.scan_error).connect(self.on_scan_error)

    def on_pause_scan(self) -> None:
        if self.scan_controller is None or self._scan_state is not ScanState.RUNNING:
            return
        try:
            self.scan_controller.pause_scan()
            self._set_scan_state(ScanState.PAUSED)
            self.on_log_event("⏸ Сканирование приостановлено")
        except Exception as error:
            self._show_error("Не удалось приостановить сканирование", error)

    def on_resume_scan(self) -> None:
        if self.scan_controller is None or self._scan_state is not ScanState.PAUSED:
            return
        try:
            self.scan_controller.resume_scan()
            self._set_scan_state(ScanState.RUNNING)
            self.on_log_event("▶ Сканирование возобновлено")
        except Exception as error:
            self._show_error("Не удалось возобновить сканирование", error)

    def _request_stop(self) -> None:
        if self._scan_state is ScanState.STOPPING:
            return
        if self.is_scanning and self.scan_controller is not None:
            self.scan_controller.stop_scan()
        elif self.current_scan_task is not None:
            self.current_scan_task.cancel()
        self._set_scan_state(ScanState.STOPPING)
        self.on_log_event("⏹ Останавливаем сканирование и сохраняем результаты…")

    def on_stop_scan(self) -> None:
        if not self.has_active_scan() or self._scan_state is ScanState.STOPPING:
            return
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "Вы уверены, что хотите остановить сканирование?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes and self.has_active_scan():
            try:
                self._request_stop()
            except Exception as error:
                self._show_error("Не удалось остановить сканирование", error)

    # --- Представление событий сканера ---
    def update_progress_in_main_thread(self, progress: int) -> None:
        self.statistics_widget.update_progress(progress)

    def on_stats_updated(self, stat_name: str, value: object) -> None:
        normalized = normalize_stat_value(stat_name, value)
        if isinstance(normalized, str):
            self.statistics_widget.update_stat_string(stat_name, normalized)
        else:
            self.statistics_widget.update_stat(stat_name, normalized)

    def on_log_event(self, message: str) -> None:
        append_log(self.log_text, message)
        logger.debug(message)

    def on_vulnerability_found(self, url: str, vulnerability_type: str, details: str) -> None:
        add_vulnerability_row(self.results_table, url, vulnerability_type, details)
        logger.info(f"Найдена уязвимость: {vulnerability_type} на {url}")

    def on_scan_error(self, message: str) -> None:
        self.on_log_event(f"❌ Ошибка сканирования: {message}")
        logger.error(message)

    def on_scan_complete(self, result: dict[str, Any]) -> None:
        if "error" in result:
            self.on_scan_error(str(result["error"]))
            return
        for message in scan_summary(result, stopped=self._scan_state is ScanState.STOPPING):
            self.on_log_event(message)
        # Кнопки разблокируются только в finally, после завершения задачи.
        if self.statistics_window is not None:
            self.statistics_window.load_statistics()
        if self.vulnerability_viewer is not None:
            self.vulnerability_viewer.load_vulnerabilities()

    def reset_scan_stats(self) -> None:
        self.statistics_widget.reset_stats()

    # --- Завершение работы и навигация ---
    def close_auxiliary_windows(self) -> None:
        if self.statistics_window is not None:
            self.statistics_window.close()
        if self.vulnerability_viewer is not None:
            self.vulnerability_viewer.refresh_timer.stop()
            self.vulnerability_viewer.close()

    def _defer_exit(self, action: Callable[[], object]) -> None:
        self._pending_exit = action
        try:
            self._request_stop()
        except Exception as error:
            self._pending_exit = None
            self._show_error("Не удалось завершить сканирование перед выходом", error)

    def _finish_pending_exit(self) -> None:
        action = self._pending_exit
        self._pending_exit = None
        if action is not None:
            action()

    def _finish_logout(self) -> None:
        self.close_auxiliary_windows()
        self.user_model.logout_user()
        if self.receivers(self.logout_requested):
            self.logout_requested.emit()
        else:
            self.close()
        logger.info(f"Пользователь {self.username} вышел из системы")

    def on_logout(self) -> None:
        if self._pending_exit is not None:
            return
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "Вы уверены, что хотите выйти? Активное сканирование будет остановлено.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        if self.has_active_scan():
            self._defer_exit(self._finish_logout)
        else:
            self._finish_logout()

    def prepare_close(self, when_ready: Callable[[], object]) -> bool:
        """Закрытие панели или MainWindow: одно подтверждение, ожидание сохранения."""
        if self.has_active_scan():
            if self._pending_exit is not None:
                return False
            reply = QMessageBox.question(
                self,
                "Подтверждение",
                "Сканирование ещё выполняется. Остановить его и закрыть окно после сохранения результатов?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return False
            if self.has_active_scan():
                self._defer_exit(when_ready)
                return False
        self.close_auxiliary_windows()
        return True

    def closeEvent(self, a0: QCloseEvent | None) -> None:
        if not self.prepare_close(self.close):
            if a0 is not None:
                a0.ignore()
            return
        if a0 is not None:
            a0.accept()
