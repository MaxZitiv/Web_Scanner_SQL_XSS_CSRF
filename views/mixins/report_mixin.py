import json
import os
from datetime import datetime
from typing import Optional
from utils.logger import logger

def _generate_json_report(scan_details: dict) -> Optional[str]:  # noqa: D401  # Экспортируется для будущего использования
    """Генерация JSON отчета"""
    try:
        # Создание имени файла
        filename = f"scan_report_{scan_details['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join("reports", filename)

        # Убедимся, что директория существует
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Сохранение JSON файла
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scan_details, f, ensure_ascii=False, indent=2)

        logger.info(f"Generated JSON report: {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Error generating JSON report: {e}")
        return None