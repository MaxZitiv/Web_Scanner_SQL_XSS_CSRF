from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

PreferencesDict = dict[str, Any]


@dataclass
class User:
    """
    Датакласс для представления пользователя.
    """

    id: int | None = None
    username: str = ""
    email: str = ""
    password_hash: str = ""
    is_active: bool = True
    created_at: datetime | None = None
    last_login: datetime | None = None
    avatar_path: str | None = None
    preferences: PreferencesDict = field(default_factory=lambda: PreferencesDict())

    def __post_init__(self):
        """Инициализация значений по умолчанию после создания."""
        if self.created_at is None:
            self.created_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """Преобразование датакласса в словарь для сохранения в JSON."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "password_hash": self.password_hash,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "avatar_path": self.avatar_path,
            "preferences": self.preferences,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> User:
        """Создание датакласса из словаря."""
        created_at = None
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])

        last_login = None
        if data.get("last_login"):
            last_login = datetime.fromisoformat(data["last_login"])

        return cls(
            id=data.get("id"),
            username=data.get("username", ""),
            email=data.get("email", ""),
            password_hash=data.get("password_hash", ""),
            is_active=data.get("is_active", True),
            created_at=created_at,
            last_login=last_login,
            avatar_path=data.get("avatar_path"),
            preferences=data.get("preferences", {}),
        )
