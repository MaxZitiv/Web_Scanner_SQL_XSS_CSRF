from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

@dataclass
class Vulnerability:
    """
    Датакласс для представления уязвимости.
    """
    type: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    description: str = ""
    severity: str = "medium"  # low, medium, high, critical
    evidence: str = ""
    request: Optional[str] = None
    response: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Преобразование датакласса в словарь для сохранения в JSON."""
        return {
            "type": self.type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """Создание датакласса из словаря."""
        return cls(
            type=data.get("type", ""),
            url=data.get("url", ""),
            parameter=data.get("parameter"),
            payload=data.get("payload"),
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            evidence=data.get("evidence", ""),
            request=data.get("request"),
            response=data.get("response")
        )

@dataclass
class ScanResult:
    """
    Датакласс для представления результата сканирования.
    """
    id: Optional[int] = None
    user_id: Optional[int] = None
    url: str = ""
    scan_type: str = "general"
    scan_duration: float = 0.0
    timestamp: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    status: str = "completed"  # completed, failed, in_progress

    def __post_init__(self):
        """Инициализация значений по умолчанию после создания."""
        if self.timestamp is None:
            self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Преобразование датакласса в словарь для сохранения в JSON."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "url": self.url,
            "scan_type": self.scan_type,
            "scan_duration": self.scan_duration,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "vulnerabilities": [vuln.to_dict() for vuln in self.vulnerabilities],
            "status": self.status
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        """Создание датакласса из словаря."""
        vulnerabilities = []
        for vuln_data in data.get("vulnerabilities", []):
            vulnerabilities.append(Vulnerability.from_dict(vuln_data))

        timestamp = None
        if data.get("timestamp"):
            timestamp = datetime.fromisoformat(data["timestamp"])

        return cls(
            id=data.get("id"),
            user_id=data.get("user_id"),
            url=data.get("url", ""),
            scan_type=data.get("scan_type", "general"),
            scan_duration=data.get("scan_duration", 0.0),
            timestamp=timestamp,
            vulnerabilities=vulnerabilities,
            status=data.get("status", "completed")
        )
