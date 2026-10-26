"""Хранение ключа без предсказуемого fallback и перезаписи существующих данных."""

import base64
import os
import stat
import tempfile
from pathlib import Path

DEFAULT_KEY_PATH = Path(__file__).resolve().parent.parent / ".db_key"
KEY_SIZE = 32


class KeyStorageError(RuntimeError):
    """Ключ недоступен: продолжать шифрование с другим ключом нельзя."""


def _read_key(path: Path) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise KeyStorageError("Файл ключа должен быть обычным файлом, а не ссылкой или устройством")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        current = os.fstat(stream.fileno())
        if not stat.S_ISREG(current.st_mode) or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise KeyStorageError("Файл ключа изменился во время открытия")
        if os.name == "posix" and (current.st_uid != os.geteuid() or current.st_mode & 0o077):
            raise KeyStorageError("Ключ должен принадлежать текущему пользователю и иметь права 0600 или строже")
        data = stream.read(KEY_SIZE + 1)
    if len(data) != KEY_SIZE:
        raise KeyStorageError("Повреждён файл ключа: требуется ровно 32 байта. Восстановите резервную копию .db_key")
    return data


def _publish_key(path: Path) -> None:
    # Сначала полностью записываем закрытый временный файл. link публикует
    # готовый ключ атомарно и, в отличие от replace, не перезаписывает победителя
    # при одновременном запуске двух процессов.
    fd, temporary_name = tempfile.mkstemp(prefix=".db_key-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(os.urandom(KEY_SIZE))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            return
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def load_master_key(path: str | Path | None = None, *, create: bool = True) -> str:
    configured = os.environ.get("WEB_SCANNER_KEY_FILE")
    key_path = Path(path) if path is not None else Path(configured).expanduser() if configured else DEFAULT_KEY_PATH
    if configured and path is None and not key_path.is_absolute():
        raise KeyStorageError("WEB_SCANNER_KEY_FILE должен содержать абсолютный путь к исходному ключу")
    try:
        try:
            data = _read_key(key_path)
        except FileNotFoundError:
            if not create:
                raise KeyStorageError("Ключ .db_key отсутствует. Для расшифровки восстановите исходный ключ") from None
            _publish_key(key_path)
            data = _read_key(key_path)
        return base64.urlsafe_b64encode(data).decode("ascii")
    except OSError as error:
        raise KeyStorageError(
            "Не удалось безопасно прочитать или сохранить .db_key; запасной ключ не используется"
        ) from error
