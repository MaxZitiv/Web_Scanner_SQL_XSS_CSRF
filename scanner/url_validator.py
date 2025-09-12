from functools import lru_cache
from urllib.parse import urlparse
from typing import Tuple, Optional

@lru_cache(maxsize=1000)
def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Проверяет валидность URL и возвращает (is_valid, error_message)"""
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False, "Invalid URL format"
        if result.scheme not in ['http', 'https']:
            return False, "Unsupported protocol"
        return True, None
    except Exception as e:
        return False, str(e)