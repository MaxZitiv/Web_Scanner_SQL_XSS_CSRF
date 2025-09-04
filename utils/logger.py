import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler
from datetime import datetime
import os

# Уровни логирования
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

# Загружаем переменные из .env
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
load_dotenv(dotenv_path=env_path)

def get_log_dir():
    """Возвращает путь к директории для хранения логов"""
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    return log_dir

def set_log_level(logger_name: str, level: str):
    """Устанавливает уровень логирования для указанного логгера"""
    logger = logging.getLogger(logger_name)
    logger.setLevel(LOG_LEVELS.get(level.upper(), logging.INFO))


# SMTP конфигурация из переменных окружения
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
FROM_EMAIL = SMTP_USERNAME

# Валидация email
if not all([SMTP_USERNAME, SMTP_PASSWORD, ADMIN_EMAIL]):
    raise ValueError("SMTP_USERNAME, SMTP_PASSWORD и ADMIN_EMAIL должны быть заданы в .env")

if FROM_EMAIL is None:
    raise ValueError("FROM_EMAIL не может быть None")

# 📁 Папка логов
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# 📌 Общие настройки формата
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# 🔄 Функция создания обработчика по уровню
def get_file_handler(level_name: str, log_file: str):
    handler = RotatingFileHandler(
        filename=os.path.join(LOG_DIR, log_file),
        maxBytes=2 * 1024 * 1024,  # 2 MB
        backupCount=5,
        encoding="utf-8"
    )
    handler.setLevel(getattr(logging, level_name))
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    return handler

# 🧠 Уведомление об ошибке
def notify_admin(level: str, message: str):
    """
    Отправляет email-уведомление администратору через SMTP.
    """
    subject = f"[WebScanner] {level.upper()} Notification"
    body = f"Level: {level.upper()}\n\nMessage:\n{message}"

    msg = MIMEMultipart()
    msg['From'] = str(FROM_EMAIL)
    msg['To'] = str(ADMIN_EMAIL)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(str(SMTP_USERNAME), str(SMTP_PASSWORD))
            server.send_message(msg)
        logger.info(f"Admin notified via email: {ADMIN_EMAIL}")
    except Exception as e:
        log_and_notify('error', f"Failed to send admin notification: {e}")

# 🧩 Кастомный фильтр для разделения логов по уровню
class LevelFilter(logging.Filter):
    def __init__(self, level):
        super().__init__()
        self.level = level

    def filter(self, record):
        return record.levelno == self.level

# 🧱 Инициализация логгера
logger = logging.getLogger("WebScanner")
logger.setLevel(logging.DEBUG)  # Ловим всё — фильтруем в хендлерах

# 📦 Обработчики по уровням
info_handler = get_file_handler("INFO", "info.log")
info_handler.addFilter(LevelFilter(logging.INFO))

warning_handler = get_file_handler("WARNING", "warning.log")
warning_handler.addFilter(LevelFilter(logging.WARNING))

error_handler = get_file_handler("ERROR", "error.log")
error_handler.addFilter(LevelFilter(logging.ERROR))

# 🖥️ Консольный хендлер (только INFO и выше, но не DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))

# ➕ Добавление обработчиков
logger.addHandler(info_handler)
logger.addHandler(warning_handler)
logger.addHandler(error_handler)
logger.addHandler(console_handler)

# 📣 Использование с логированием и уведомлением
def log_and_notify(level: str, message: str) -> None:
    level = level.lower()
    log_func = getattr(logger, level, logger.info)  # По умолчанию INFO

    log_func(message)

    if level in ("warning", "error", "critical"):
        try:
            notify_admin(level.upper(), message)
        except Exception as e:
            log_and_notify('error', f"Failed to notify admin: {e}")
