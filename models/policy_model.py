from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class SecurityPolicy:
    """
    Датакласс для представления политики безопасности.
    Содержит все настройки для сканирования уязвимостей.
    """
    name: str
    enabled_vulns: List[str] = field(default_factory=lambda: ["sql", "xss", "csrf"])
    sql_payloads: str = "standard"
    xss_payloads: str = "standard"
    max_depth: int = 3
    max_concurrent: int = 5
    timeout: int = 30
    exclude_urls: List[str] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    respect_robots_txt: bool = True
    rate_limit: int = 0
    stop_on_first_vuln: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Преобразование датакласса в словарь для сохранения в JSON."""
        return {
            "name": self.name,
            "enabled_vulns": self.enabled_vulns,
            "sql_payloads": self.sql_payloads,
            "xss_payloads": self.xss_payloads,
            "max_depth": self.max_depth,
            "max_concurrent": self.max_concurrent,
            "timeout": self.timeout,
            "exclude_urls": self.exclude_urls,
            "custom_headers": self.custom_headers,
            "respect_robots_txt": self.respect_robots_txt,
            "rate_limit": self.rate_limit,
            "stop_on_first_vuln": self.stop_on_first_vuln
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityPolicy':
        """Создание датакласса из словаря."""
        return cls(
            name=data.get("name", "Default"),
            enabled_vulns=data.get("enabled_vulns", ["sql", "xss", "csrf"]),
            sql_payloads=data.get("sql_payloads", "standard"),
            xss_payloads=data.get("xss_payloads", "standard"),
            max_depth=data.get("max_depth", 3),
            max_concurrent=data.get("max_concurrent", 5),
            timeout=data.get("timeout", 30),
            exclude_urls=data.get("exclude_urls", []),
            custom_headers=data.get("custom_headers", {}),
            respect_robots_txt=data.get("respect_robots_txt", True),
            rate_limit=data.get("rate_limit", 0),
            stop_on_first_vuln=data.get("stop_on_first_vuln", False)
        )
