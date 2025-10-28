
    def on_statistics(self):
        """Открытие окна статистики"""
        try:
            from views.statistics_window import StatisticsWindow
            statistics_window = StatisticsWindow(self.user_id, self)
            statistics_window.show()
        except Exception as e:
            logger.error(f"Ошибка при открытии статистики: {e}")
            error_handler.show_error_message("Ошибка", f"Не удалось открыть статистику: {str(e)}")

    def on_reports(self):
        """Открытие окна отчетов"""
        try:
            from views.reports_window import ReportsWindow
            reports_window = ReportsWindow(self.user_id, self)
            reports_window.show()
        except Exception as e:
            logger.error(f"Ошибка при открытии отчетов: {e}")
            error_handler.show_error_message("Ошибка", f"Не удалось открыть отчеты: {str(e)}")
