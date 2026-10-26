"""Контекстное экранирование недоверенных данных при экспорте отчётов."""

import csv
import json
import unicodedata
from collections.abc import Mapping, Sequence
from html import escape
from typing import Any, TextIO, cast


def html_text(value: object) -> str:
    return escape(str(value), quote=True)


def csv_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    probe = value
    while probe and (probe[0].isspace() or unicodedata.category(probe[0]) in {"Cc", "Cf"}):
        probe = probe[1:]
    probe = unicodedata.normalize("NFKC", probe)
    if probe.startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        # CSV-кавычки сами по себе не запрещают выполнение формул в Excel.
        return "'" + value
    return value


def write_csv_rows(stream: TextIO, rows: Sequence[Mapping[str, object]]) -> None:
    if not rows:
        return
    # У разных результатов могут быть разные столбцы. Не теряем поздние поля
    # и не создаём частичный файл из-за DictWriter(extrasaction='raise').
    columns = list(dict.fromkeys(key for row in rows for key in row))
    writer = csv.writer(stream, quoting=csv.QUOTE_ALL)
    writer.writerow([csv_cell(column) for column in columns])
    for row in rows:
        writer.writerow([csv_cell(row.get(column, "")) for column in columns])


def result_records(raw: object) -> list[dict[str, Any]]:
    """Одинаковая обработка result из SQLite (JSON) и уже разобранных записей."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    if not isinstance(raw, list):
        return []
    # Не превращаем элементы [null, 42, "text"] в dict и не падаем на всём отчёте.
    return [dict(cast(dict[str, Any], item)) for item in cast(list[object], raw) if isinstance(item, dict)]
