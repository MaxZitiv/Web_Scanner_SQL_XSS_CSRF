import csv
import json
import os
import sqlite3
from typing import List, Dict, Any, Optional, Set

from fpdf import FPDF

from utils.database import db
# Добавляем аннотацию типа для db
db: Any
from utils.encryption import decrypt_sensitive_data
from utils.logger import logger, log_and_notify
from utils.performance import get_local_timestamp


def format_duration(seconds: float):
    """Форматирует время в часы, минуты и секунды"""
    if seconds < 60:
        return f"{seconds:.1f} сек"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes} мин {secs:.1f} сек"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours} ч {minutes} мин {secs:.1f} сек"

def format_scan_data_for_export(scans: List[Dict[str, Any]], user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Форматирует данные сканирования для экспорта в более читаемый вид"""
    formatted_data: List[Dict[str, Any]] = []
    
    for scan in scans:
        # Парсим результаты сканирования
        results: List[Dict[str, Any]] = scan.get('result', [])
        if isinstance(results, str):
            try:
                results = json.loads(results)
            except json.JSONDecodeError:
                results = []
        
        # Получаем количество отсканированных URL
        total_urls_scanned = scan.get('total_urls_scanned', 0)
        total_forms_scanned = scan.get('total_forms_scanned', 0)
        total_checks = total_urls_scanned + total_forms_scanned
        
        # Если нет данных о URL, используем количество результатов как fallback
        if total_checks == 0:
            total_checks = len(results)
        
        # Обрабатываем URL - расшифровываем только для авторизованных пользователей
        target_url = scan.get('url', 'N/A')
        if user_id and db.is_user_authenticated(user_id):
            try:
                target_url = decrypt_sensitive_data(target_url)
            except Exception as e:
                logger.warning(f"Failed to decrypt URL for scan {scan.get('id', 'unknown')}: {e}")
                # Если расшифровка не удалась, оставляем зашифрованным
                pass
        
        # Группируем результаты по типам уязвимостей
        vuln_summary: Dict[str, Dict[str, Any]] = {}
        vulnerable_count = 0
        
        for result in results:
            vuln_type = result.get('type', 'Unknown')
            status = result.get('status', 'Unknown')
            url = result.get('url', 'Unknown')
            
            # Расшифровываем URL в результатах только для авторизованных пользователей
            if user_id and db.is_user_authenticated(user_id):
                try:
                    url = decrypt_sensitive_data(url)
                except Exception as e:
                    logger.warning(f"Failed to decrypt URL in result: {e}")
                    # Если расшифровка не удалась, оставляем зашифрованным
                    pass
            
            if vuln_type not in vuln_summary:
                vuln_summary[vuln_type] = {
                    'total': 0,
                    'vulnerable': 0,
                    'safe': 0,
                    'details': []
                }
            
            vuln_summary[vuln_type]['total'] += 1
            
            if 'Vulnerable' in status or 'уязвим' in status.lower():
                vuln_summary[vuln_type]['vulnerable'] += 1
                vulnerable_count += 1
                severity = 'HIGH'
            else:
                vuln_summary[vuln_type]['safe'] += 1
                severity = 'LOW'
            
            vuln_summary[vuln_type]['details'].append({
                'url': url,
                'status': status,
                'severity': severity
            })
        
        # Создаем форматированную запись
        formatted_scan: Dict[str, Any] = {
            'scan_id': scan.get('id', 'N/A'),
            'target_url': target_url,
            'scan_date': scan.get('timestamp', 'N/A'),
            'scan_type': scan.get('scan_type', 'general'),
            'status': scan.get('status', 'completed'),
            'scan_duration': scan.get('scan_duration', 0.0),
            'summary': {
                'total_checks': total_checks,
                'total_urls_scanned': total_urls_scanned,
                'total_forms_scanned': total_forms_scanned,
                'vulnerable_count': vulnerable_count,
                'safe_count': total_checks - vulnerable_count,
                'risk_level': 'HIGH' if vulnerable_count > 0 else 'LOW'
            },
            'vulnerabilities': vuln_summary
        }
        
        formatted_data.append(formatted_scan)
    
    return formatted_data


def export_to_json(data: List[Dict[str, Any]], filename: str = "report.json", user_id: Optional[int] = None) -> bool:
    """Экспорт данных в JSON формат с улучшенной структурой"""
    try:
        if not data:
            logger.warning("No data to export to JSON")
            return False
        
        # Форматируем данные для экспорта
        formatted_data = format_scan_data_for_export(data, user_id)
        
        # Создаем структурированный отчет
        report: Dict[str, Any] = {
            'report_info': {
                'generated_at': get_local_timestamp(),
                'total_scans': len(formatted_data),
                'report_version': '2.0'
            },
            'executive_summary': {
                'total_targets': len(formatted_data),
                'total_vulnerabilities': sum(scan['summary']['vulnerable_count'] for scan in formatted_data),
                'high_risk_targets': len([scan for scan in formatted_data if scan['summary']['risk_level'] == 'HIGH'])
            },
            'detailed_results': formatted_data
        }
            
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        logger.info(f"JSON file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error exporting to JSON: {e}")
        return False


def export_to_csv(data: List[Dict[str, Any]], filename: str = "report.csv", user_id: Optional[int] = None) -> bool:
    """Экспорт данных в CSV формат с детализированной информацией"""
    try:
        if not data:
            logger.warning("No data to export to CSV")
            return False

        # Форматируем данные для экспорта
        formatted_data = format_scan_data_for_export(data, user_id)
        
        # Создаем плоскую структуру для CSV
        csv_rows: List[Dict[str, Any]] = []
        
        for scan in formatted_data:
            base_row: Dict[str, Any] = {
                'Scan ID': scan['scan_id'],
                'Target URL': scan['target_url'],
                'Scan Date': scan['scan_date'],
                'Scan Type': scan['scan_type'],
                'Status': scan['status'],
                'Scan Duration (seconds)': f"{scan['scan_duration']:.2f}",
                'Total Checks': scan['summary']['total_checks'],
                'Vulnerable Count': scan['summary']['vulnerable_count'],
                'Safe Count': scan['summary']['safe_count'],
                'Risk Level': scan['summary']['risk_level']
            }
            
            # Добавляем детали по каждому типу уязвимости
            for vuln_type, vuln_data in scan['vulnerabilities'].items():
                base_row[f'{vuln_type}_Total'] = vuln_data['total']
                base_row[f'{vuln_type}_Vulnerable'] = vuln_data['vulnerable']
                base_row[f'{vuln_type}_Safe'] = vuln_data['safe']
            
            csv_rows.append(base_row)
        
        if csv_rows:
            fieldnames = csv_rows[0].keys()
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_rows)
        
        logger.info(f"CSV file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('e', f"Error exporting to CSV: {e}")
        return False


class PDFReport(FPDF):
    def __init__(self):
        super().__init__()
        # Устанавливаем поддержку UTF-8
        self.set_auto_page_break(auto=True, margin=15)
        
        try:
            font_path = 'timesnewromanpsmt.ttf'
            if not os.path.exists(font_path):
                logger.warning("Times New Roman font not found, using default font")
                # Используем встроенный шрифт с поддержкой UTF-8
                self.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
                self.set_font("DejaVu", size=14)
            else:
                # Добавляем шрифт с поддержкой Unicode
                self.add_font("TimesNewRoman", "", font_path, uni=True)
                self.set_font("TimesNewRoman", size=14)
        except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
            log_and_notify('error', f"Error setting up font: {e}")
            # Fallback на встроенный шрифт
            try:
                self.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
                self.set_font("DejaVu", size=14)
            except (RuntimeError, FileNotFoundError):
                # Последний fallback - используем стандартный шрифт
                self.set_font("Arial", size=14)

    def header(self):
        try:
            self.set_font("TimesNewRoman", "B", 16)
        except (RuntimeError, KeyError, AttributeError):
            try:
                self.set_font("DejaVu", "B", 16)
            except (RuntimeError, KeyError, AttributeError):
                self.set_font("Arial", "B", 16)
        
        self.cell(0, 10, "Отчёт о сканировании уязвимостей", ln=True, align="C")
        
        try:
            self.set_font("TimesNewRoman", "", 10)
        except (RuntimeError, KeyError, AttributeError):
            try:
                self.set_font("DejaVu", "", 10)
            except (RuntimeError, KeyError, AttributeError):
                self.set_font("Arial", "", 10)
        
        self.cell(0, 10, f"Сгенерирован: {get_local_timestamp()}", ln=True, align="C")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        try:
            self.set_font("TimesNewRoman", "", 8)
        except (RuntimeError, KeyError, AttributeError):
            try:
                self.set_font("DejaVu", "", 8)
            except (RuntimeError, KeyError, AttributeError):
                self.set_font("Arial", "", 8)
        
        self.cell(0, 10, f"Страница {self.page_no()}", align="C")

    def chapter_title(self, title: str):
        try:
            self.set_font("TimesNewRoman", "B", 14)
        except (RuntimeError, KeyError, AttributeError):
            try:
                self.set_font("DejaVu", "B", 14)
            except (RuntimeError, KeyError, AttributeError):
                self.set_font("Arial", "B", 14)
        
        self.cell(0, 10, title, ln=True)
        self.ln(5)

    def section_title(self, title: str):
        try:
            self.set_font("TimesNewRoman", "B", 12)
        except (RuntimeError, KeyError, AttributeError):
            try:
                self.set_font("DejaVu", "B", 12)
            except (RuntimeError, KeyError, AttributeError):
                self.set_font("Arial", "B", 12)
        
        self.cell(0, 8, title, ln=True)
        self.ln(2)

    def add_text(self, text: str, font_size: int = 10, url_mode: bool = False):
        try:
            self.set_font("TimesNewRoman", "", font_size if not url_mode else 8)
        except (RuntimeError, KeyError, AttributeError):
            try:
                self.set_font("DejaVu", "", font_size if not url_mode else 8)
            except (RuntimeError, KeyError, AttributeError):
                self.set_font("Arial", "", font_size if not url_mode else 8)
        safe_text = self._sanitize_text(text)
        if url_mode:
            self.set_text_color(0, 0, 180)  # Синий для URL
        self.multi_cell(0, 5 if not url_mode else 4, safe_text)  # type: ignore
        if url_mode:
            self.set_text_color(0, 0, 0)
        self.ln(2 if not url_mode else 1)
    
    @staticmethod
    def _sanitize_text(text: str):
        """Очищает текст от символов, которые могут вызвать проблемы с кодировкой"""
        if not text:
            return ""
        
        # Заменяем проблемные символы
        replacements = {
            '—': '-',  # длинное тире
            '–': '-',  # короткое тире
            '"': '"',  # кавычки
            '"': '"',
            ''': "'",  # апострофы
            ''': "'",
            '…': '...',  # многоточие
            '№': 'N',   # номер
            '°': ' deg', # градус
        }
        
        for old, new in replacements.items():
            text = text.replace(old, new)
        
        # Удаляем или заменяем другие проблемные символы
        import re
        text = re.sub(r'[^\x00-\x7F\u0400-\u04FF\u0500-\u052F\u2DE0-\u2DFF\uA640-\uA69F]+', '?', text)
        
        return text


def export_to_pdf(data: List[Dict[str, Any]], filename: str = "report.pdf", user_id: Optional[int] = None) -> bool:
    """Экспорт данных в PDF формат с улучшенным форматированием"""
    try:
        pdf = PDFReport()
        pdf.add_page()
        
        if not data:
            pdf.add_text("Нет данных для отчёта.", 12)
        else:
            # Форматируем данные для экспорта
            formatted_data = format_scan_data_for_export(data, user_id)
            
            # Общая статистика
            total_scans = len(formatted_data)
            total_vulnerabilities = sum(scan['summary']['vulnerable_count'] for scan in formatted_data)
            high_risk_targets = len([scan for scan in formatted_data if scan['summary']['risk_level'] == 'HIGH'])
            
            pdf.chapter_title("Краткое резюме")
            pdf.add_text(f"Всего сканирований: {total_scans}")
            pdf.add_text(f"Обнаружено уязвимостей: {total_vulnerabilities}")
            pdf.add_text(f"Целей с высоким риском: {high_risk_targets}")
            pdf.ln(10)
            
            # Детальные результаты
            pdf.chapter_title("Детальные результаты")
            
            for i, scan in enumerate(formatted_data, 1):
                pdf.section_title(f"Сканирование {i}: {scan['target_url']}")
                pdf.add_text(f"Дата: {scan['scan_date']}")
                pdf.add_text(f"Тип сканирования: {scan['scan_type']}")
                pdf.add_text(f"Статус: {scan['status']}")
                pdf.add_text(f"Время сканирования: {format_duration(scan.get('scan_duration', 0))}")
                pdf.add_text(f"Уровень риска: {scan['summary']['risk_level']}")
                pdf.add_text(f"Всего проверок: {scan['summary']['total_checks']}")
                pdf.add_text(f"Уязвимостей: {scan['summary']['vulnerable_count']}")
                pdf.add_text(f"Безопасно: {scan['summary']['safe_count']}")
                
                # Детали по типам уязвимостей
                if scan['vulnerabilities']:
                    pdf.add_text("Детали по типам уязвимостей:")
                    for vuln_type, vuln_data in scan['vulnerabilities'].items():
                        pdf.add_text(f"  • {vuln_type}: {vuln_data['vulnerable']} уязвимостей из {vuln_data['total']} проверок")
                        
                        # Показываем детали уязвимостей
                        if vuln_data['vulnerable'] > 0:
                            pdf.add_text("    Уязвимые URL:")
                            for detail in vuln_data['details']:
                                if detail['severity'] == 'HIGH':
                                    pdf.add_text(f"      - {detail['url']}: {detail['status']}", url_mode=True)
                
                pdf.ln(5)
                
                # Проверяем, нужна ли новая страница
                if pdf.get_y() > 250:
                    pdf.add_page()
        
        pdf.output(filename)
        logger.info(f"PDF file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error exporting to PDF: {e}")
        return False


def export_to_html(data: List[Dict[str, Any]], filename: str = "report.html", user_id: Optional[int] = None) -> bool:
    """Экспорт данных в HTML формат с улучшенным форматированием"""
    try:
        if not data:
            logger.warning("No data to export to HTML")
            return False
        
        # Форматируем данные для экспорта
        formatted_data = format_scan_data_for_export(data, user_id)
        
        # Создаем HTML отчет вручную
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Отчет о сканировании уязвимостей</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ background-color: #e8f4f8; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .scan-item {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .vulnerable {{ background-color: #ffe6e6; }}
                .safe {{ background-color: #e6ffe6; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Отчет о сканировании уязвимостей</h1>
                <p><strong>Сгенерирован:</strong> {get_local_timestamp()}</p>
                <p><strong>Всего сканирований:</strong> {len(formatted_data)}</p>
            </div>
        """
        
        # Общая статистика
        total_vulnerabilities = sum(scan['summary']['vulnerable_count'] for scan in formatted_data)
        high_risk_targets = len([scan for scan in formatted_data if scan['summary']['risk_level'] == 'HIGH'])
        
        html_content += f"""
            <div class="summary">
                <h2>Общая статистика</h2>
                <table>
                    <tr><th>Всего сканирований</th><td>{len(formatted_data)}</td></tr>
                    <tr><th>Обнаружено уязвимостей</th><td>{total_vulnerabilities}</td></tr>
                    <tr><th>Целей с высоким риском</th><td>{high_risk_targets}</td></tr>
                </table>
            </div>
        """
        
        # Детальные результаты
        for i, scan in enumerate(formatted_data, 1):
            risk_class = 'vulnerable' if scan['summary']['risk_level'] == 'HIGH' else 'safe'
            html_content += f"""
                <div class="scan-item {risk_class}">
                    <h3>Сканирование {i}: {scan['target_url']}</h3>
                    <p><strong>Дата:</strong> {scan['scan_date']}</p>
                    <p><strong>Тип:</strong> {scan['scan_type']}</p>
                    <p><strong>Статус:</strong> {scan['status']}</p>
                    <p><strong>Длительность:</strong> {format_duration(scan.get('scan_duration', 0))}</p>
                    <p><strong>Уровень риска:</strong> {scan['summary']['risk_level']}</p>
                    <p><strong>Всего проверок:</strong> {scan['summary']['total_checks']}</p>
                    <p><strong>Уязвимостей:</strong> {scan['summary']['vulnerable_count']}</p>
                    <p><strong>Безопасно:</strong> {scan['summary']['safe_count']}</p>
                </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"HTML file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error exporting to HTML: {e}")
        return False


def export_to_txt(data: List[Dict[str, Any]], filename: str = "report.txt", user_id: Optional[int] = None) -> bool:
    """Экспорт данных в текстовый формат"""
    try:
        if not data:
            logger.warning("No data to export to TXT")
            return False
        
        # Форматируем данные для экспорта
        formatted_data = format_scan_data_for_export(data, user_id)
        
        # Создаем текстовый отчет
        report_lines = [
            "=" * 80,
            "ОТЧЕТ О СКАНИРОВАНИИ УЯЗВИМОСТЕЙ",
            "=" * 80,
            f"Сгенерирован: {get_local_timestamp()}",
            f"Всего сканирований: {len(formatted_data)}",
            ""
        ]
        
        # Общая статистика
        total_vulnerabilities = sum(scan['summary']['vulnerable_count'] for scan in formatted_data)
        high_risk_targets = len([scan for scan in formatted_data if scan['summary']['risk_level'] == 'HIGH'])
        
        report_lines.extend([
            "ОБЩАЯ СТАТИСТИКА:",
            "-" * 40,
            f"Всего сканирований: {len(formatted_data)}",
            f"Обнаружено уязвимостей: {total_vulnerabilities}",
            f"Целей с высоким риском: {high_risk_targets}",
            ""
        ])
        
        # Детальные результаты
        for i, scan in enumerate(formatted_data, 1):
            report_lines.extend([
                f"Сканирование {i}: {scan['target_url']}",
                f"  Дата: {scan['scan_date']}",
                f"  Тип: {scan['scan_type']}",
                f"  Статус: {scan['status']}",
                f"  Длительность: {format_duration(scan.get('scan_duration', 0))}",
                f"  Уровень риска: {scan['summary']['risk_level']}",
                f"  Всего проверок: {scan['summary']['total_checks']}",
                f"  Уязвимостей: {scan['summary']['vulnerable_count']}",
                f"  Безопасно: {scan['summary']['safe_count']}",
                ""
            ])
        
        report_lines.extend([
            "=" * 80,
            "Отчет завершен",
            "=" * 80
        ])
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        
        logger.info(f"TXT file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error exporting to TXT: {e}")
        return False


def generate_detailed_report(data: List[Dict[str, Any]], format_type: str = 'json', filename: Optional[str] = None) -> bool:
    """Генерирует детальный отчет в указанном формате"""
    try:
        if not data:
            logger.warning("No data to generate report")
            return False
        
        # Используем универсальную функцию экспорта вместо ScanReportGenerator
        return export_data(data, format_type, filename)
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error generating detailed report: {e}")
        return False


def export_data(data: List[Dict[str, Any]], export_type: str, filename: Optional[str] = None, user_id: Optional[int] = None) -> bool:
    """Основная функция экспорта данных в различные форматы"""
    if not filename:
        filename = f"report.{export_type.lower()}"
    
    try:
        if export_type.lower() == 'json':
            return export_to_json(data, filename, user_id)
        elif export_type.lower() == 'csv':
            return export_to_csv(data, filename, user_id)
        elif export_type.lower() == 'pdf':
            return export_to_pdf(data, filename, user_id)
        elif export_type.lower() == 'html':
            return export_to_html(data, filename, user_id)
        elif export_type.lower() == 'txt':
            return export_to_txt(data, filename, user_id)
        else:
            log_and_notify('error', f"Unsupported export type: {export_type}")
            return False
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error in export_data: {e}")
        return False


def export_single_scan_to_json(scan: Dict[str, Any], filename: str = "single_scan_report.json", user_id: Optional[int] = None) -> bool:
    """Экспорт конкретного сканирования в JSON формат"""
    try:
        if not scan:
            logger.warning("No scan data to export to JSON")
            return False
        
        # Форматируем данные для экспорта
        formatted_data = format_scan_data_for_export([scan], user_id)
        
        # Создаем структурированный отчет для одного сканирования
        report: Dict[str, Any] = {
            'report_info': {
                'generated_at': get_local_timestamp(),
                'scan_id': scan.get('id', 'N/A'),
                'target_url': scan.get('url', 'N/A'),
                'scan_date': scan.get('timestamp', 'N/A'),
                'report_version': '2.0'
            },
            'scan_summary': formatted_data[0] if formatted_data else {},
            'detailed_results': scan.get('result', [])
        }
            
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        logger.info(f"Single scan JSON file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error exporting single scan to JSON: {e}")
        return False


def export_single_scan_to_csv(scan: Dict[str, Any], filename: str = "single_scan_report.csv", user_id: Optional[int] = None) -> bool:
    """Экспорт конкретного сканирования в CSV формат"""
    try:
        if not scan:
            logger.warning("No scan data to export to CSV")
            return False

        # Форматируем данные для экспорта
        formatted_data = format_scan_data_for_export([scan], user_id)
        
        # Создаем плоскую структуру для CSV
        csv_rows: List[Dict[str, Any]] = []
        
        scan_data = formatted_data[0] if formatted_data else {}
        base_row: Dict[str, Any] = {
            'Scan ID': scan_data.get('scan_id', 'N/A'),
            'Target URL': scan_data.get('target_url', 'N/A'),
            'Scan Date': scan_data.get('scan_date', 'N/A'),
            'Scan Type': scan_data.get('scan_type', 'N/A'),
            'Status': scan_data.get('status', 'N/A'),
            'Scan Duration (seconds)': f"{scan_data.get('scan_duration', 0.0):.2f}",
            'Total Checks': scan_data.get('summary', {}).get('total_checks', 0),
            'Vulnerable Count': scan_data.get('summary', {}).get('vulnerable_count', 0),
            'Safe Count': scan_data.get('summary', {}).get('safe_count', 0),
            'Risk Level': scan_data.get('summary', {}).get('risk_level', 'N/A')
        }
        
        # Добавляем детали по каждому типу уязвимости
        for vuln_type, vuln_data in scan_data.get('vulnerabilities', {}).items():
            base_row[f'{vuln_type}_Total'] = vuln_data['total']
            base_row[f'{vuln_type}_Vulnerable'] = vuln_data['vulnerable']
            base_row[f'{vuln_type}_Safe'] = vuln_data['safe']
        
        csv_rows.append(base_row)
        
        # Добавляем детальные результаты
        for result in scan.get('result', []):
            detail_row = {
                'Scan ID': scan.get('id', 'N/A'),
                'Vulnerability Type': result.get('type', 'N/A'),
                'URL': result.get('url', 'N/A'),
                'Status': result.get('status', 'N/A'),
                'Details': result.get('details', 'N/A')
            }
            csv_rows.append(detail_row)
        
        if csv_rows:
            fieldnames: Set[str] = set()
            for row in csv_rows:
                fieldnames.update(row.keys())
            sorted_fieldnames = sorted(list(fieldnames))
            
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=sorted_fieldnames)
                writer.writeheader()
                for row in csv_rows:
                    # Заполняем отсутствующие поля
                    for field in sorted_fieldnames:
                        if field not in row:
                            row[field] = ''
                    writer.writerow(row)
        
        logger.info(f"Single scan CSV file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error exporting single scan to CSV: {e}")
        return False


def export_single_scan_to_pdf(scan: Dict[str, Any], filename: str = "single_scan_report.pdf", user_id: Optional[int] = None) -> bool:
    """Экспорт конкретного сканирования в PDF формат"""
    try:
        if not scan:
            logger.warning("No scan data to export to PDF")
            return False

        # Форматируем данные для экспорта
        formatted_data = format_scan_data_for_export([scan], user_id)
        
        pdf = PDFReport()
        pdf.add_page()
        
        # Заголовок
        pdf.chapter_title(f"Отчет о сканировании #{scan.get('id', 'N/A')}")
        
        # Основная информация
        pdf.section_title("Основная информация")
        pdf.add_text(f"Цель: {scan.get('url', 'N/A')}", url_mode=True)
        pdf.add_text(f"Дата: {scan.get('timestamp', 'N/A')}")
        pdf.add_text(f"Тип: {scan.get('scan_type', 'N/A')}")
        pdf.add_text(f"Статус: {scan.get('status', 'N/A')}")
        pdf.add_text(f"Длительность: {format_duration(scan.get('scan_duration', 0))}")
        pdf.ln(5)
        
        # Статистика
        scan_data = formatted_data[0] if formatted_data else {}
        summary = scan_data.get('summary', {})
        pdf.section_title("Статистика")
        pdf.add_text(f"Всего проверок: {summary.get('total_checks', 0)}")
        pdf.add_text(f"Уязвимостей: {summary.get('vulnerable_count', 0)}")
        pdf.add_text(f"Безопасных: {summary.get('safe_count', 0)}")
        pdf.add_text(f"Уровень риска: {summary.get('risk_level', 'N/A')}")
        pdf.ln(5)
        
        # Детальные результаты
        results = scan.get('result', [])
        if results:
            pdf.section_title("Детальные результаты")
            
            for i, result in enumerate(results, 1):
                pdf.add_text(f"{i}. {result.get('type', 'Unknown')} - {result.get('url', 'Unknown')}", 10, url_mode=True)
                pdf.add_text(f"   Статус: {result.get('status', 'Unknown')}", 9)
                if result.get('details'):
                    pdf.add_text(f"   Детали: {result.get('details', '')}", 9)
                pdf.ln(2)
        
        pdf.output(filename)
        logger.info(f"Single scan PDF file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error exporting single scan to PDF: {e}")
        return False


def export_single_scan_to_html(scan: Dict[str, Any], filename: str = "single_scan_report.html", user_id: Optional[int] = None) -> bool:
    """Экспорт конкретного сканирования в HTML формат"""
    try:
        if not scan:
            logger.warning("No scan data to export to HTML")
            return False

        # Форматируем данные для экспорта
        formatted_data = format_scan_data_for_export([scan], user_id)
        
        scan_data = formatted_data[0] if formatted_data else {}
        summary = scan_data.get('summary', {})
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Отчет о сканировании #{scan.get('id', 'N/A')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ background-color: #e8f4f8; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .results {{ margin: 20px 0; }}
                .result-item {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 3px; }}
                .vulnerable {{ background-color: #ffe6e6; }}
                .safe {{ background-color: #e6ffe6; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Отчет о сканировании #{scan.get('id', 'N/A')}</h1>
                <p><strong>Цель:</strong> {scan.get('url', 'N/A')}</p>
                <p><strong>Дата:</strong> {scan.get('timestamp', 'N/A')}</p>
                <p><strong>Тип:</strong> {scan.get('scan_type', 'N/A')}</p>
                <p><strong>Статус:</strong> {scan.get('status', 'N/A')}</p>
                <p><strong>Длительность:</strong> {format_duration(scan.get('scan_duration', 0))}</p>
            </div>
            
            <div class="summary">
                <h2>Статистика</h2>
                <table>
                    <tr><th>Всего проверок</th><td>{summary.get('total_checks', 0)}</td></tr>
                    <tr><th>Уязвимостей</th><td>{summary.get('vulnerable_count', 0)}</td></tr>
                    <tr><th>Безопасных</th><td>{summary.get('safe_count', 0)}</td></tr>
                    <tr><th>Уровень риска</th><td>{summary.get('risk_level', 'N/A')}</td></tr>
                </table>
            </div>
            
            <div class="results">
                <h2>Детальные результаты</h2>
        """
        
        results = scan.get('result', [])
        for i, result in enumerate(results, 1):
            status_class = 'vulnerable' if 'Vulnerable' in result.get('status', '') else 'safe'
            html_content += f"""
                <div class="result-item {status_class}">
                    <h3>{i}. {result.get('type', 'Unknown')}</h3>
                    <p><strong>URL:</strong> {result.get('url', 'Unknown')}</p>
                    <p><strong>Статус:</strong> {result.get('status', 'Unknown')}</p>
                    {f'<p><strong>Детали:</strong> {result.get("details", "")}</p>' if result.get('details') else ''}
                </div>
            """
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"Single scan HTML file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error exporting single scan to HTML: {e}")
        return False


def export_single_scan_to_txt(scan: Dict[str, Any], filename: str = "single_scan_report.txt", user_id: Optional[int] = None) -> bool:
    """Экспорт конкретного сканирования в TXT формат"""
    try:
        if not scan:
            logger.warning("No scan data to export to TXT")
            return False

        # Форматируем данные для экспорта
        formatted_data = format_scan_data_for_export([scan], user_id)
        
        scan_data = formatted_data[0] if formatted_data else {}
        summary = scan_data.get('summary', {})
        
        report_lines = [
            "=" * 80,
            f"ОТЧЕТ О СКАНИРОВАНИИ #{scan.get('id', 'N/A')}",
            "=" * 80,
            f"Цель: {scan.get('url', 'N/A')}",
            f"Дата: {scan.get('timestamp', 'N/A')}",
            f"Тип: {scan.get('scan_type', 'N/A')}",
            f"Статус: {scan.get('status', 'N/A')}",
            f"Длительность: {format_duration(scan.get('scan_duration', 0))}",
            "",
            "СТАТИСТИКА:",
            "-" * 40,
            f"Всего проверок: {summary.get('total_checks', 0)}",
            f"Уязвимостей: {summary.get('vulnerable_count', 0)}",
            f"Безопасных: {summary.get('safe_count', 0)}",
            f"Уровень риска: {summary.get('risk_level', 'N/A')}",
            "",
            "ДЕТАЛЬНЫЕ РЕЗУЛЬТАТЫ:",
            "-" * 40
        ]
        
        results = scan.get('result', [])
        for i, result in enumerate(results, 1):
            report_lines.extend([
                f"{i}. {result.get('type', 'Unknown')}",
                f"   URL: {result.get('url', 'Unknown')}",
                f"   Статус: {result.get('status', 'Unknown')}"
            ])
            if result.get('details'):
                report_lines.append(f"   Детали: {result.get('details', '')}")
            report_lines.append("")
        
        report_lines.extend([
            "=" * 80,
            "Отчет завершен",
            "=" * 80
        ])
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        
        logger.info(f"Single scan TXT file saved: {filename}")
        return True
    except (OSError, ValueError, KeyError, AttributeError, ImportError, sqlite3.Error) as e:
        log_and_notify('error', f"Error exporting single scan to TXT: {e}")
        return False


def export_single_scan(scan: Dict[str, Any], export_type: str, filename: Optional[str] = None, user_id: Optional[int] = None) -> bool:
    """Экспорт конкретного сканирования в выбранном формате"""
    try:
        if not scan:
            logger.warning("No scan data to export")
            return False
        
        if not filename:
            scan_id = scan.get('id', 'unknown')
            timestamp = get_local_timestamp().replace(':', '').replace(' ', '_')
            filename = f"scan_{scan_id}_{timestamp}.{export_type.lower()}"
        
        export_functions = {
            'json': export_single_scan_to_json,
            'csv': export_single_scan_to_csv,
            'pdf': export_single_scan_to_pdf,
            'html': export_single_scan_to_html,
            'txt': export_single_scan_to_txt
        }
        
        if export_type.lower() not in export_functions:
            log_and_notify('error', f"Unsupported export type: {export_type}")
            return False
        
        # Передаем user_id во все функции экспорта
        return export_functions[export_type.lower()](scan, filename, user_id)
    except (OSError, ValueError, KeyError, AttributeError, ImportError, TypeError, RuntimeError, sqlite3.Error) as e:
        log_and_notify('error', f"Error in export_single_scan: {e}")
        return False
