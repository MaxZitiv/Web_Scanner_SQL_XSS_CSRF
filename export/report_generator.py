import json
import sqlite3
from typing import Dict, Any, Optional

from fpdf import FPDF

from utils.database import db
from utils.logger import logger, log_and_notify
from utils.performance import format_duration


class ScanReportGenerator:
    """Генератор детальных отчетов о сканировании"""

    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self.scan_data = self._get_scan_data()
        if not self.scan_data:
            raise ValueError(f"Скан с ID {self.scan_id} не найден.")
            
    def _get_scan_data(self) -> Optional[Dict[str, Any]]:
        """Получает все данные о сканировании из БД"""
        conn = db.get_db_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (self.scan_id,))
            scan = cursor.fetchone()
            if not scan:
                return None
            
            scan_dict = dict(scan)
            
            # Парсим JSON-поля
            try:
                scan_dict['vulnerabilities'] = json.loads(scan_dict.get('vulnerabilities', '{}'))
            except (json.JSONDecodeError, TypeError):
                scan_dict['vulnerabilities'] = {}

            try:
                scan_dict['settings'] = json.loads(scan_dict.get('settings', '{}'))
            except (json.JSONDecodeError, TypeError):
                scan_dict['settings'] = {}
            
            return scan_dict
        finally:
            # Соединение больше не нужно закрывать здесь, 
            # так как оно управляется централизованно.
            pass

    def generate_full_report(self) -> str:
        """Генерирует полный текстовый отчет"""
        if not self.scan_data:
            return "Отчет не может быть сгенерирован: данные сканирования не найдены."

        # Извлекаем данные
        target_url = self.scan_data.get('url', 'N/A')
        duration_sec = self.scan_data.get('duration', 0)
        
        settings = self.scan_data.get('settings', {})
        depth = settings.get('max_depth', 0)
        concurrent = settings.get('max_concurrent', 'N/A')
        timeout = settings.get('timeout', 'N/A')
        
        vulns = self.scan_data.get('vulnerabilities', {})
        sql_vulns = vulns.get('sql', [])
        xss_vulns = vulns.get('xss', [])
        csrf_vulns = vulns.get('csrf', [])
        
        total_vulns = len(sql_vulns) + len(xss_vulns) + len(csrf_vulns)
        
        # Считаем общее количество проверок
        total_urls = self.scan_data.get('total_urls_scanned', 0)
        total_forms = self.scan_data.get('total_forms_scanned', 0)
        total_checks = total_urls + total_forms
        
        perf_per_level = (duration_sec / depth) if depth > 0 else duration_sec

        # Определение уровня безопасности
        if total_vulns == 0:
            security_level = "🟢 БЕЗОПАСНО"
            recommendations = [
                "• Продолжайте регулярные проверки безопасности",
                "• Следите за обновлениями компонентов",
                "• Ведите журнал безопасности"
            ]
            recommendations_title = "🟢 СИСТЕМА БЕЗОПАСНА:"
        elif total_vulns <= 5:
            security_level = "🟡 СРЕДНИЙ РИСК"
            recommendations = [
                "• Немедленно устраните найденные уязвимости.",
                "• Проведите дополнительный ручной анализ кода.",
                "• Усильте фильтрацию пользовательского ввода."
            ]
            recommendations_title = "🟡 ОБНАРУЖЕНЫ УЯЗВИМОСТИ:"
        else:
            security_level = "🔴 ВЫСОКИЙ РИСК"
            recommendations = [
                "• СРОЧНО! Устраните все уязвимости.",
                "• Рекомендуется временная остановка сервиса для исправления.",
                "• Проведите полный аудит безопасности с привлечением экспертов."
            ]
            recommendations_title = "🔴 КРИТИЧЕСКИЙ УРОВЕНЬ УГРОЗЫ:"

        # Формирование отчета
        report_lines = [
            "============================================================",
            "🔍 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ",
            "============================================================",
            f"🎯 Цель: {target_url}",
            f"⏱️ Время выполнения: {format_duration(duration_sec)}",
            f"🚀 Производительность: {perf_per_level:.2f} сек/уровень",
            f"⚙️ Настройки: глубина={depth}, параллельные={concurrent}, таймаут={timeout}с",
            "============================================================\n",
            "📊 ОБЩАЯ СТАТИСТИКА",
            "----------------------------------------",
            f"Всего проверок: {total_checks}",
            f"Обнаружено уязвимостей: {total_vulns}",
            f"Уровень безопасности: {security_level}",
            "\n💡 РЕКОМЕНДАЦИИ",
            "----------------------------------------",
            recommendations_title,
            *recommendations
        ]

        if total_vulns > 0:
            report_lines.append("\n" + "="*60)
            report_lines.append("ДЕТАЛИ ОБНАРУЖЕННЫХ УЯЗВИМОСТЕЙ")
            report_lines.append("="*60)

            if sql_vulns:
                report_lines.append("\n---[ SQL Injection ]---")
                for v in sql_vulns:
                    report_lines.append(f"  URL: {v['url']}")
                    report_lines.append(f"  Детали: {v['details']}")
            
            if xss_vulns:
                report_lines.append("\n---[ XSS (Cross-Site Scripting) ]---")
                for v in xss_vulns:
                    report_lines.append(f"  URL: {v['url']}")
                    report_lines.append(f"  Детали: {v['details']}")

            if csrf_vulns:
                report_lines.append("\n---[ CSRF (Cross-Site Request Forgery) ]---")
                for v in csrf_vulns:
                    report_lines.append(f"  URL: {v['url']}")
                    report_lines.append(f"  Детали: {v['details']}")
        
        report_lines.extend([
            "\n" + "="*60,
            "✅ Сканирование завершено",
            "="*60
        ])

        return "\n".join(report_lines)

class PDF(FPDF):
    def __init__(self):
        super().__init__()

        # Добавляем поддержку кириллицы
        self.add_font(family='times', style='', fname='timesnewromanpsmt.ttf.ttf', uni=True)
        self.add_font(family='times', style='B', fname='timesnewromanpsmt.ttf.ttf', uni=True)
        self.add_font(family='times', style='I', fname='timesnewromanpsmt.ttf.ttf', uni=True)

        # Настройка для поддержки UTF-8
        self.set_auto_page_break(auto=True, margin=15)
        self.add_page()
    
    def header(self):
        self.set_font('times', 'B', 16)
        self.cell(0, 10, 'Отчет о сканировании безопасности', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('times', 'I', 8)
        self.cell(0, 10, f'Страница {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title: str):
        self.set_font('times', 'B', 12)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(4)

    def chapter_body(self, body: str) -> None:
        self.set_font('times', '', 12)
        # Обработка текста для корректного отображения в PDF
        body = self._clean_text_for_pdf(body)
        # Используем multi_cell и игнорируем возвращаемое значение
        multi_cell = getattr(self, 'multi_cell')
        multi_cell(0, 5, body)
        self.ln()

    @staticmethod
    def _clean_text_for_pdf(text: str) -> str:
        """Очищает текст для корректного отображения в PDF"""
        try:
            # Удаляем или заменяем специальные символы
            text = text.replace('\x00', '')
            text = text.replace('\uFFFD', '')
            text = text.replace('\u2028', '')
            text = text.replace('\u2029', '')
            text = text.replace('\u000b', '')
            text = text.replace('\u000c', '')
            text = text.replace('\u000e', '')
            text = text.replace('\u000f', '')
            return text
        except Exception as e:
            logger.error(f"Error cleaning text for PDF: {e}")
            return text

    def add_text(self, text: str):
        """Метод для добавления текста в PDF"""
        cleaned_text = self._clean_text_for_pdf(text)
        self.set_font('times', '', 12)
        self.cell(0, 10, cleaned_text)

    def clean_text(self, text: str) -> str:
        return self._clean_text_for_pdf(text)

    def add_section(self, title: str, content: str) -> None:
        self.chapter_title(title)
        self.chapter_body(content)


def generate_pdf_report(scan_id: int, filename: str):
    """Генерирует PDF отчет для указанного сканирования."""
    try:
        generator = ScanReportGenerator(scan_id)
        report_text = generator.generate_full_report()

        pdf = PDF()

        # Настройка шрифтов с поддержкой UTF-8
        try:
            # Пытаемся использовать шрифт с поддержкой кириллицы
            pdf.add_font('times', '', 'timesnewromanpsmt.ttf', uni=True)
            pdf.add_font('times', 'B', 'timesnewromanpsmt.ttf', uni=True)
            pdf.add_font('times', 'I', 'timesnewromanpsmt.ttf', uni=True)
        except (RuntimeError, FileNotFoundError) as e:
            logger.warning(f"Font 'timesnewromanpsmt.ttf' not found: {e}. Using default font.")
            # Используем стандартные шрифты FPDF
            pdf.set_font('helvetica', '', 12)

        # Обрабатываем текст для PDF
        report_text = pdf.clean_text(report_text)

        # Заменяем разделители для лучшего вида
        report_text = report_text.replace("=" * 60, "-" * 80)

        # Добавляем содержимое в PDF
        multi_cell = getattr(pdf, 'multi_cell')
        multi_cell(0, 5, report_text)

        # Сохраняем PDF
        pdf.output(filename, 'F')
        logger.info(f"PDF отчет успешно сохранен в {filename}")

    except (OSError, ValueError, KeyError, AttributeError, ImportError, TypeError, RuntimeError, sqlite3.Error) as e:
        log_and_notify('error', f"Ошибка при создании PDF отчета: {e}")
        raise