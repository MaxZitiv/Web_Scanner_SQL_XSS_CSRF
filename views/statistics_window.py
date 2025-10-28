"""
Окно для просмотра подробной статистики сканирования
views/statistics_window.py
"""

from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QTableWidget, QTableWidgetItem, QPushButton, 
                            QTabWidget)
from PyQt5.QtCore import Qt, QRect
from PyQt5.QtCharts import QPieSeries, QBarSeries, QBarSet, QValueAxis
from PyQt5.QtGui import QFont, QPainter
from typing import Optional
from utils.database import db
from utils.logger import logger

class StatisticsWindow(QMainWindow):
    """Окно для просмотра подробной статистики"""

    def __init__(self, user_id: int, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.user_id: int = user_id
        self.setWindowTitle("📊 Статистика сканирования")
        self.setGeometry(QRect(100, 100, 1200, 800))

        self.setup_ui()
        self.load_statistics()

    def setup_ui(self):
        """Настройка интерфейса"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()

        # Заголовок
        title_label = QLabel("📊 Статистика сканирования")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)

        # Вкладки
        self.tabs = QTabWidget()

        # Вкладка с таблицей сканирований
        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(6)
        self.scans_table.setHorizontalHeaderLabels([
            "ID сканирования", "URL", "Дата", "Найдено уязвимостей", "Время сканирования", "Статус"
        ])
        self.tabs.addTab(self.scans_table, "История сканирований")

        # Вкладка с диаграммами
        self.charts_widget = QWidget()
        self.charts_layout = QVBoxLayout()
        self.charts_widget.setLayout(self.charts_layout)
        self.tabs.addTab(self.charts_widget, "Диаграммы")

        # Вкладка с общей статистикой
        self.stats_widget = QWidget()
        self.stats_layout = QVBoxLayout()
        self.stats_widget.setLayout(self.stats_layout)
        self.tabs.addTab(self.stats_widget, "Общая статистика")

        main_layout.addWidget(self.tabs)

        # Кнопка закрытия
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.close)
        main_layout.addWidget(close_btn)

        central_widget.setLayout(main_layout)

    def load_statistics(self):
        """Загрузка статистики из базы данных"""
        try:
            # Загружаем историю сканирований
            self.load_scan_history()

            # Загружаем диаграммы
            self.load_charts()

            # Загружаем общую статистику
            self.load_general_stats()

        except Exception as e:
            logger.error(f"Ошибка при загрузке статистики: {e}")

    def load_scan_history(self):
        """Загрузка истории сканирований"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT scan_id, url, start_time, vulnerabilities_found, 
                       scan_duration, status 
                FROM scans 
                WHERE user_id = ? 
                ORDER BY start_time DESC
                LIMIT 100
            """, (self.user_id,))

            rows = cursor.fetchall()
            conn.close()

            self.scans_table.setRowCount(len(rows))

            for i, row in enumerate(rows):
                scan_id = str(row[0])
                url = row[1] if row[1] else "N/A"
                start_time = row[2] if row[2] else "N/A"
                vulns_found = str(row[3]) if row[3] is not None else "0"
                duration = f"{row[4]}с" if row[4] else "N/A"
                status = row[5] if row[5] else "N/A"

                self.scans_table.setItem(i, 0, QTableWidgetItem(scan_id))
                self.scans_table.setItem(i, 1, QTableWidgetItem(url))
                self.scans_table.setItem(i, 2, QTableWidgetItem(start_time))
                self.scans_table.setItem(i, 3, QTableWidgetItem(vulns_found))
                self.scans_table.setItem(i, 4, QTableWidgetItem(duration))
                self.scans_table.setItem(i, 5, QTableWidgetItem(status))

            # Настраиваем ширину колонок
            self.scans_table.resizeColumnsToContents()

        except Exception as e:
            logger.error(f"Ошибка при загрузке истории сканирований: {e}")

    def load_charts(self):
        """Загрузка диаграмм"""
        try:
            # Создаем круговую диаграмму типов уязвимостей
            self.create_vulnerability_pie_chart()

            # Создаем столбчатую диаграмму уязвимостей по времени
            self.create_vulnerability_bar_chart()

        except Exception as e:
            logger.error(f"Ошибка при загрузке диаграмм: {e}")

    def create_vulnerability_pie_chart(self):
        """Создание круговой диаграммы типов уязвимостей"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT vulnerability_type, COUNT(*) as count
                FROM scan_results 
                WHERE user_id = ?
                GROUP BY vulnerability_type
            """, (self.user_id,))

            rows = cursor.fetchall()
            conn.close()

            if not rows:
                no_data_label = QLabel("Нет данных для отображения")
                no_data_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                self.charts_layout.addWidget(no_data_label)
                return

            # Создаем круговую диаграмму
            series: QPieSeries = QPieSeries()

            for row in rows:
                vuln_type = row[0]
                count = row[1]
                series.append(f"{vuln_type}: {count}", count)

            chart = QChart()
            chart.addSeries(series)
            chart.setTitle("Распределение уязвимостей по типам")
            chart.legend().setVisible(True)
            chart.legend().setAlignment(Qt.AlignRight)

            chart_view = QChartView(chart)
            chart_view.setRenderHint(QPainter.Antialiasing)

            self.charts_layout.addWidget(chart_view)

        except Exception as e:
            logger.error(f"Ошибка при создании круговой диаграммы: {e}")

    def create_vulnerability_bar_chart(self):
        """Создание столбчатой диаграммы уязвимостей по времени"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT DATE(timestamp) as date, vulnerability_type, COUNT(*) as count
                FROM scan_results 
                WHERE user_id = ?
                GROUP BY date, vulnerability_type
                ORDER BY date
                LIMIT 30
            """, (self.user_id,))

            rows = cursor.fetchall()
            conn.close()

            if not rows:
                return

            # Группируем данные по типам уязвимостей
            vuln_types = {}
            dates = set()

            for row in rows:
                date = row[0]
                vuln_type = row[1]
                count = row[2]

                dates.add(date)

                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = {}

                vuln_types[vuln_type][date] = count

            # Создаем столбчатую диаграмму
            series_list = []
            colors = ["#FF9999", "#66B2FF", "#99FF99"]
            color_index = 0

            for vuln_type, data in vuln_types.items():
                bar_set = QBarSet(vuln_type)
                bar_set.setColor(colors[color_index % len(colors)])
                color_index += 1

                for date in sorted(dates):
                    bar_set.append(data.get(date, 0))

                series_list.append(bar_set)

            chart = QChart()
            chart.setTitle("Динамика обнаружения уязвимостей")

            axis_x = QValueAxis()
            axis_x.setTitleText("Дата")
            axis_x.setTickCount(min(len(dates), 10))

            axis_y = QValueAxis()
            axis_y.setTitleText("Количество уязвимостей")

            bar_series = QBarSeries()
            for bar_set in series_list:
                bar_series.append(bar_set)

            chart.addSeries(bar_series)
            chart.addAxis(axis_x, Qt.AlignBottom)
            chart.addAxis(axis_y, Qt.AlignLeft)

            bar_series.attachAxis(axis_x)
            bar_series.attachAxis(axis_y)

            chart.legend().setVisible(True)
            chart.legend().setAlignment(Qt.AlignBottom)

            chart_view = QChartView(chart)
            chart_view.setRenderHint(QPainter.Antialiasing)

            self.charts_layout.addWidget(chart_view)

        except Exception as e:
            logger.error(f"Ошибка при создании столбчатой диаграммы: {e}")

    def load_general_stats(self):
        """Загрузка общей статистики"""
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()

            # Общая статистика
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT scan_id) as total_scans,
                    COUNT(*) as total_vulnerabilities,
                    COUNT(DISTINCT url) as unique_urls
                FROM scan_results 
                WHERE user_id = ?
            """, (self.user_id,))

            general_stats = cursor.fetchone()

            # Статистика по типам уязвимостей
            cursor.execute("""
                SELECT vulnerability_type, COUNT(*) as count
                FROM scan_results 
                WHERE user_id = ?
                GROUP BY vulnerability_type
            """, (self.user_id,))

            vuln_stats = cursor.fetchall()

            conn.close()

            # Отображаем общую статистику
            stats_layout = QVBoxLayout()

            # Заголовок
            general_title = QLabel("Общая статистика")
            title_font = QFont()
            title_font.setPointSize(12)
            title_font.setBold(True)
            general_title.setFont(title_font)
            stats_layout.addWidget(general_title)

            # Общие показатели
            general_stats_widget = QWidget()
            general_stats_layout = QHBoxLayout()

            if general_stats:
                total_scans = general_stats[0] if general_stats[0] else 0
                total_vulns = general_stats[1] if general_stats[1] else 0
                unique_urls = general_stats[2] if general_stats[2] else 0

                scans_label = QLabel(f"Всего сканирований: {total_scans}")
                vulns_label = QLabel(f"Всего уязвимостей: {total_vulns}")
                urls_label = QLabel(f"Уникальных URL: {unique_urls}")

                general_stats_layout.addWidget(scans_label)
                general_stats_layout.addWidget(vulns_label)
                general_stats_layout.addWidget(urls_label)

            general_stats_widget.setLayout(general_stats_layout)
            stats_layout.addWidget(general_stats_widget)

            # Статистика по типам уязвимостей
            vuln_title = QLabel("Статистика по типам уязвимостей")
            vuln_title.setFont(title_font)
            stats_layout.addWidget(vuln_title)

            vuln_stats_widget = QWidget()
            vuln_stats_layout = QHBoxLayout()

            for vuln_type, count in vuln_stats:
                type_label = QLabel(f"{vuln_type}: {count}")
                vuln_stats_layout.addWidget(type_label)

            vuln_stats_widget.setLayout(vuln_stats_layout)
            stats_layout.addWidget(vuln_stats_widget)

            # Добавляем растягивающееся пространство
            stats_layout.addStretch()

            self.stats_widget.setLayout(stats_layout)

        except Exception as e:
            logger.error(f"Ошибка при загрузке общей статистики: {e}")
