"""
Исправленный класс StatisticsWidget для views/statistics_widget.py
Без ошибок типизации Pylance
"""

from PyQt6.QtWidgets import (
    QWidget, QGridLayout, QVBoxLayout, QLabel, QProgressBar
)
from PyQt6.QtGui import QFont
from typing import Optional, Dict, Any

class StatisticsWidget(QWidget):
    """Виджет отображения статистики сканирования"""
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.stats_data: Dict[str, Any] = {
            'urls_found': 0,
            'urls_scanned': 0,
            'forms_found': 0,
            'forms_scanned': 0,
            'vulnerabilities': 0,
            'requests_sent': 0,
            'errors': 0,
            'scan_time': '00:00:00',
            'progress': 0
        }
        
        self.setup_ui()
    
    def setup_ui(self):
        """Инициализирует UI"""
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Заголовок
        title_label = QLabel('📊 Статистика сканирования')
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Grid layout для статистики
        grid_layout = QGridLayout()
        grid_layout.setSpacing(10)
        
        # Создаем метки для каждой статистики
        self.stats_labels: Dict[str, QLabel] = {}
        
        stats_config = [
            ('urls_found', 'Найдено URL:', 0, 0),
            ('urls_scanned', 'Просканировано URL:', 0, 2),
            ('forms_found', 'Найдено форм:', 1, 0),
            ('forms_scanned', 'Просканировано форм:', 1, 2),
            ('vulnerabilities', 'Уязвимостей найдено:', 2, 0),
            ('requests_sent', 'Запросов отправлено:', 2, 2),
            ('errors', 'Ошибок:', 3, 0),
            ('scan_time', 'Время сканирования:', 3, 2),
        ]
        
        for stat_key, stat_label, row, col in stats_config:
            # Метка
            label = QLabel(stat_label)
            label_font = QFont()
            label_font.setPointSize(10)
            label.setFont(label_font)
            grid_layout.addWidget(label, row, col)
            
            # Значение
            value_label = QLabel('0')
            value_font = QFont()
            value_font.setPointSize(10)
            value_font.setBold(True)
            value_label.setFont(value_font)
            
            # Правильное использование AlignmentFlag
            from PyQt6.QtCore import Qt
            value_label.setAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )
            
            # Устанавливаем минимальную ширину для значений
            value_label.setMinimumWidth(80)
            
            grid_layout.addWidget(value_label, row, col + 1)
            self.stats_labels[stat_key] = value_label
        
        main_layout.addLayout(grid_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)
        
        # Stretch в конце
        main_layout.addStretch()
        
        self.setLayout(main_layout)
        self.setStyleSheet("""
            StatisticsWidget {
                background-color: #f5f5f5;
                border-radius: 5px;
                border: 1px solid #e0e0e0;
                padding: 10px;
            }
            QLabel {
                color: #333333;
            }
            QProgressBar {
                border: 1px solid #cccccc;
                border-radius: 3px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 2px;
            }
        """)
    def update_stat(self, stat_name: str, value: int):
        """Обновляет одно значение статистики"""
        try:
            # Обновляем хранилище данных
            self.stats_data[stat_name] = value
            
            # Обновляем UI
            if stat_name in self.stats_labels:
                label = self.stats_labels[stat_name]
                
                # Форматируем вывод в зависимости от типа статистики
                if stat_name == 'vulnerabilities':
                    # Раскрашиваем по количеству уязвимостей
                    if value > 0:
                        label.setStyleSheet("color: #d32f2f; font-weight: bold;")
                    else:
                        label.setStyleSheet("color: #388e3c; font-weight: bold;")
                    label.setText(str(value))
                
                elif stat_name == 'errors':
                    # Раскрашиваем ошибки в оранжевый
                    if value > 0:
                        label.setStyleSheet("color: #f57c00; font-weight: bold;")
                    else:
                        label.setStyleSheet("color: #388e3c; font-weight: bold;")
                    label.setText(str(value))
                
                elif stat_name == 'scan_time':
                    # Время отображаем как строка
                    label.setText(str(value))
                
                else:
                    # Остальные числовые значения
                    label.setText(str(value))
        
        except Exception as e:
            from utils.logger import logger
            logger.error(f"Error updating stat {stat_name}: {e}")
    def update_stat_string(self, stat_name: str, value: str):
        """Обновляет значение статистики строкового типа"""
        try:
            if stat_name in self.stats_labels:
                label = self.stats_labels[stat_name]
                label.setText(str(value))
                self.stats_data[stat_name] = value
        except Exception as e:
            from utils.logger import logger
            logger.error(f"Error updating stat string {stat_name}: {e}")
    def update_progress(self, progress: int):
        """Обновляет прогресс-бар"""
        try:
            progress_value = max(0, min(100, progress))
            self.progress_bar.setValue(progress_value)
            self.stats_data['progress'] = progress_value
        except Exception as e:
            from utils.logger import logger
            logger.error(f"Error updating progress: {e}")
    
    def reset_stats(self):
        """Сбрасывает статистику"""
        try:
            for stat_key in self.stats_labels:
                if stat_key == 'scan_time':
                    self.stats_labels[stat_key].setText('00:00:00')
                else:
                    self.stats_labels[stat_key].setText('0')
            
            self.progress_bar.setValue(0)
            
            # Сбрасываем стили
            for label in self.stats_labels.values():
                label.setStyleSheet("")
            
            # Очищаем данные
            for key in self.stats_data:
                self.stats_data[key] = '00:00:00' if key == 'scan_time' else 0
        except Exception as e:
            from utils.logger import logger
            logger.error(f"Error resetting stats: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает текущую статистику"""
        return self.stats_data.copy()
    
    def set_stats_visible(self, visible: bool):
        """Показывает или скрывает виджет"""
        self.setVisible(visible)