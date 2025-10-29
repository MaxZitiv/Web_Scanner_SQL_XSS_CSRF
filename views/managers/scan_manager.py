from typing import Dict, Any, List, cast
from PyQt5.QtCore import QObject
from utils.logger import logger

class ScanManagerStatsMixin:
    """Миксин класс для оптимизации работы со статистикой в ScanManager"""
    def init_stats_manager(self):
        """Инициализация StatsManager и подключение сигналов"""
        if not hasattr(self, 'stats_manager'):
            from views.managers.stats_manager import StatsManager
            # Проверяем, что self наследуется от QObject
            parent = self if isinstance(self, QObject) else None
            self.stats_manager = StatsManager(parent)
            # Подключаем сигнал обновления статистики
            self.stats_manager.stats_updated.connect(self._on_stats_updated)

    def _on_stats_updated(self, key: str, value: int):
        """Обработчик сигнала обновления статистики от StatsManager"""
        try:
            # Обновляем локальную копию статистики
            if not hasattr(self, '_stats'):
                self._stats = self.stats_manager.get_stats()
            else:
                self._stats[key] = value

            # Обновляем UI если есть соответствующие метки
            try:
                dashboard = getattr(self, 'dashboard', None)
                if (dashboard is not None and
                    hasattr(dashboard, 'stats_labels') and
                    (stats_labels := getattr(dashboard, 'stats_labels', None)) is not None and
                    hasattr(stats_labels, '__getitem__') and
                    key in stats_labels):
                    label = stats_labels[key]
                    if hasattr(label, 'setText'):
                        label.setText(str(value))
            except AttributeError:
                # Игнорируем ошибки, если атрибут dashboard или его дочерние элементы недоступны
                pass
        except Exception as e:
            logger.error(f"Error in _on_stats_updated: {e}")

    def update_stats(self, key: str, value: int):
        """Обновляет статистику через StatsManager"""
        try:
            # Используем StatsManager для обновления статистики
            if hasattr(self, 'stats_manager'):
                self.stats_manager.update_stats(key, value)
        except Exception as e:
            logger.error(f"Error in update_stats: {e}")

    def increment_stats(self, key: str):
        """Увеличивает значение статистики на 1 через StatsManager"""
        try:
            # Используем StatsManager для увеличения статистики
            if hasattr(self, 'stats_manager'):
                self.stats_manager.increment_stats(key)
        except Exception as e:
            logger.error(f"Error in increment_stats: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Возвращает текущую статистику"""
        if hasattr(self, 'stats_manager'):
            return self.stats_manager.get_stats()
        return {}

    def reset_stats(self):
        """Сбрасывает статистику"""
        if hasattr(self, 'stats_manager'):
            self.stats_manager.reset_stats()

    def start_scan(self, url: str):
        """Запускает сканирование указанного URL"""
        logger.info(f"Starting scan for URL: {url}")

        # Получаем доступ к dashboard через атрибуты
        dashboard = getattr(self, 'dashboard', None)
        if dashboard is None:
            logger.error("Dashboard is not accessible, cannot start scan")
            return

        # Получаем типы сканирования из UI
        scan_types: List[str] = []
        if hasattr(dashboard, 'sql_checkbox') and dashboard.sql_checkbox.isChecked():
            scan_types.append('sql')
        if hasattr(dashboard, 'xss_checkbox') and dashboard.xss_checkbox.isChecked():
            scan_types.append('xss')
        if hasattr(dashboard, 'csrf_checkbox') and dashboard.csrf_checkbox.isChecked():
            scan_types.append('csrf')

        # Получаем параметры сканирования из UI
        max_depth = 3
        max_concurrent = 5
        timeout = 30

        if hasattr(dashboard, 'depth_spinbox'):
            max_depth = dashboard.depth_spinbox.value()
        if hasattr(dashboard, 'concurrent_spinbox'):
            max_concurrent = dashboard.concurrent_spinbox.value()
        if hasattr(dashboard, 'timeout_spinbox'):
            timeout = dashboard.timeout_spinbox.value()

        # Запускаем сканирование через контроллер
        if hasattr(dashboard, 'scan_controller') and dashboard.scan_controller is not None:
            # Создаем асинхронную задачу для сканирования
            import asyncio

            # Определяем колбэки для обновления UI
            def on_progress(percent: int):
                if hasattr(dashboard, 'scan_progress') and dashboard.scan_progress is not None:
                    dashboard.scan_progress.setValue(percent)
                if hasattr(dashboard, 'progress_label') and dashboard.progress_label is not None:
                    dashboard.progress_label.setText(f"{percent}%")

            def on_log(message: str):
                if hasattr(dashboard, 'detailed_log') and dashboard.detailed_log is not None:
                    dashboard.detailed_log.append(message)

            def on_vulnerability(vuln: str):
                # Обработка найденной уязвимости
                logger.info(f"Vulnerability found: {vuln}")

            # Запускаем сканирование в асинхронном режиме
            async def run_scan():
                try:
                    await dashboard.scan_controller.start_scan(
                        url=url,
                        scan_types=scan_types,
                        max_depth=max_depth,
                        max_concurrent=max_concurrent,
                        timeout=timeout,
                        on_progress=on_progress,
                        on_log=on_log,
                        on_vulnerability=on_vulnerability
                    )
                except Exception as e:
                    logger.error(f"Error during scan: {e}")
                    if hasattr(dashboard, 'scan_status') and dashboard.scan_status is not None:
                        dashboard.scan_status.setText(f"Ошибка: {str(e)}")
                    if hasattr(dashboard, 'scan_button') and dashboard.scan_button is not None:
                        dashboard.scan_button.setEnabled(True)
                    if hasattr(dashboard, 'pause_button') and dashboard.pause_button is not None:
                        dashboard.pause_button.setEnabled(False)

            # Запускаем асинхронную задачу
            asyncio.create_task(run_scan())
        else:
            logger.error("Scan controller is not available")

    def clear_scan_log(self):
        """Очищает лог сканирования"""
        logger.info("Clearing scan log")

        # Получаем доступ к dashboard через атрибуты
        dashboard = getattr(self, 'dashboard', None)
        if dashboard is None:
            logger.warning("Dashboard is not accessible, cannot clear scan log")
            return

        # Очищаем текст лога
        if hasattr(dashboard, 'detailed_log') and dashboard.detailed_log is not None:
            dashboard.detailed_log.clear()

        # Очищаем дерево сайта
        if hasattr(dashboard, 'site_tree') and dashboard.site_tree is not None:
            dashboard.site_tree.clear()

        # Сбрасываем статистику
        if hasattr(dashboard, 'stats_labels'):
            for key, label in dashboard.stats_labels.items():
                if key != 'scan_time':  # Не сбрасываем время сканирования
                    label.setText("0")

        # Сбрасываем прогресс
        if hasattr(dashboard, 'scan_progress') and dashboard.scan_progress is not None:
            dashboard.scan_progress.setValue(0)
        if hasattr(dashboard, 'progress_label') and dashboard.progress_label is not None:
            dashboard.progress_label.setText("0%")

    def _update_scan_time(self):
        """Обновляет время сканирования"""
        logger.debug("Updating scan time")

        # Получаем доступ к dashboard через атрибуты
        dashboard = getattr(self, 'dashboard', None)
        if dashboard is None:
            logger.warning("Dashboard is not accessible, cannot update scan time")
            return

        # Проверяем, что сканирование активно и таймер существует
        if not hasattr(dashboard, '_scan_timer') or dashboard._scan_timer is None or not dashboard._scan_timer.isActive():
            return

        # Проверяем, что статистика существует и имеет нужную структуру
        if not hasattr(dashboard, '_stats') or dashboard._stats is None:
            dashboard._stats = cast(Dict[str, Any], {
                'urls_found': 0,
                'urls_scanned': 0,
                'forms_found': 0,
                'forms_scanned': 0,
                'vulnerabilities': 0,
                'requests_sent': 0,
                'errors': 0,
                'scan_start_time': None
            })

        # Если время начала сканирования установлено
        if dashboard._stats.get('scan_start_time'):
            import time

            # Вычисляем прошедшее время
            start_time = dashboard._stats['scan_start_time']
            current_time = time.time()
            elapsed_seconds = int(current_time - start_time)

            # Форматируем время в ЧЧ:ММ:СС
            hours = elapsed_seconds // 3600
            minutes = (elapsed_seconds % 3600) // 60
            seconds = elapsed_seconds % 60
            formatted_time = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

            # Обновляем метку времени в статистике
            if hasattr(dashboard, 'stats_labels') and 'scan_time' in dashboard.stats_labels:
                dashboard.stats_labels['scan_time'].setText(formatted_time)