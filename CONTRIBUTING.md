# Проверка типов

Проект рассчитан на **Python 3.14**. Настройки Pyright находятся в
`pyrightconfig.json`: режим `strict`, целевая версия Python 3.14 и окружение
`.venv` в корне репозитория. Для проверки нужны зависимости приложения,
включая PyQt6, aiohttp и BeautifulSoup, а не только сам Pyright.

## Подготовка окружения

Выполняйте команды из корня репозитория.

Linux / macOS:

```sh
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pyright
```

Windows (PowerShell, активация окружения не требуется):

```powershell
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pyright
```

Вместо установки пакета с dev-зависимостями можно установить
`python -m pip install -r requirements.txt`: этот список также содержит
зависимости приложения и Pyright. В обоих случаях используйте Python из `.venv`.

## Если редактор показывает ошибки импортов

- Выберите интерпретатор `.venv/bin/python` (Windows: `.venv\Scripts\python.exe`)
  через **Python: Select Interpreter**.
- Убедитесь, что зависимости установлены именно в это окружение:
  `python -m pip check`.
- Повторите `python -m pyright` из корня репозитория. При необходимости
  перезапустите языковой сервер редактора после установки зависимостей.

Ошибки `reportMissingImports` и связанные с ними `reportUnknown*` могут быть
следствием отсутствующих зависимостей. Не скрывайте их отключением строгого
режима или генерацией заглушек для отсутствующих пакетов. Pyright использует
типы установленных библиотек; локальные `.pylance_stubs` не требуются.

Проверка также запускается в GitHub Actions при push и pull request.
