"""Параметры и единые правила состояния элементов управления сканированием."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .widgets import DashboardWidgets


class ScanState(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"


@dataclass(frozen=True)
class ScanOptions:
    url: str
    scan_types: tuple[str, ...]
    timeout: int = 30


@dataclass(frozen=True)
class ScanControls:
    inputs_enabled: bool
    start_enabled: bool
    pause_enabled: bool
    resume_enabled: bool
    stop_enabled: bool


def prepare_scan_options(url: str, scan_types: Sequence[str]) -> ScanOptions:
    url = url.strip()
    if not url:
        raise ValueError("Пожалуйста, введите URL для сканирования")
    if "://" not in url:
        url = "https://" + url
    if len(url) > 2048:
        raise ValueError(f"URL слишком длинный (максимум 2048 символов). Текущая длина: {len(url)}")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Укажите HTTP- или HTTPS-адрес сайта")
    if not scan_types:
        raise ValueError("Выберите хотя бы один тип сканирования:\n• SQL Injection\n• XSS\n• CSRF")
    if any(scan_type not in {"sql", "xss", "csrf"} for scan_type in scan_types):
        raise ValueError("Неизвестный тип сканирования")
    return ScanOptions(url, tuple(dict.fromkeys(scan_types)))


def controls_for(state: ScanState) -> ScanControls:
    return ScanControls(
        inputs_enabled=state is ScanState.IDLE,
        start_enabled=state is ScanState.IDLE,
        pause_enabled=state is ScanState.RUNNING,
        resume_enabled=state is ScanState.PAUSED,
        stop_enabled=state in {ScanState.RUNNING, ScanState.PAUSED},
    )


def apply_scan_controls(widgets: DashboardWidgets, state: ScanState) -> None:
    controls = controls_for(state)
    for widget in (widgets.url_input, widgets.sql_checkbox, widgets.xss_checkbox, widgets.csrf_checkbox):
        widget.setEnabled(controls.inputs_enabled)
    widgets.start_scan_btn.setEnabled(controls.start_enabled)
    widgets.pause_scan_btn.setEnabled(controls.pause_enabled)
    widgets.resume_scan_btn.setEnabled(controls.resume_enabled)
    widgets.stop_scan_btn.setEnabled(controls.stop_enabled)
