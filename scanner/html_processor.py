import hashlib
import time
from typing import List, Dict, Any, Set, Tuple, Optional
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin, urlparse

from utils.logger import logger, log_and_notify
from .cache_manager import cache_manager

class HTMLProcessor:
    """Класс для обработки HTML-контента"""
    
    @staticmethod
    def parse_html(html: str) -> BeautifulSoup:
        """Парсинг HTML с оптимизированными настройками"""
        return BeautifulSoup(html, 'html.parser')
    
    @staticmethod
    def get_form_hash(form_tag: Tag) -> str:
        """Создает уникальный хэш для тега формы"""
        try:
            if not form_tag:
                logger.warning("Invalid or empty form tag passed for hashing")
                return hashlib.sha256(b"invalid_form", usedforsecurity=False).hexdigest()

            action = str(form_tag.get('action', '')) if form_tag else ''
            method = str(form_tag.get('method', 'get')).lower() if form_tag else 'get'
            
            inputs: List[str] = []
            if form_tag:
                for inp in form_tag.find_all(['input', 'textarea', 'select', 'button']):
                    if isinstance(inp, Tag):
                        inp_name = inp.get('name', '')
                        inp_type = inp.get('type', 'text')
                        if inp_name and isinstance(inp_name, str):
                            inputs.append(f"{inp.name}-{inp_type}-{inp_name}")
            
            inputs.sort()
            form_representation = f"action:{action}|method:{method}|inputs:{','.join(inputs)}"
            return hashlib.sha256(form_representation.encode('utf-8', errors='replace'), 
                                usedforsecurity=False).hexdigest()
        except Exception as e:
            log_and_notify('error', f"Critical error creating form hash: {e}")
            return hashlib.sha256(str(time.time()).encode(), usedforsecurity=False).hexdigest()
    
    @staticmethod
    def extract_links_and_forms(html: str, base_url: str) -> Tuple[Set[str], List[Tag]]:
        """Извлекает ссылки и формы из HTML"""
        found_links: Set[str] = set()
        found_forms: List[Tag] = []
        
        try:
            soup = HTMLProcessor.parse_html(html)
            
            # Извлекаем ссылки
            for link in soup.find_all(['a', 'link', 'script', 'img']):
                href = None
                if isinstance(link, Tag):
                    href = link.get('href', '') or link.get('src', '')
                if href:
                    try:
                        absolute_url = urljoin(base_url, str(href))
                        found_links.add(absolute_url)
                    except Exception as e:
                        logger.warning(f"Error processing URL {href}: {e}")
            
            # Извлекаем формы
            forms = soup.find_all('form')
            for form in forms:
                if isinstance(form, Tag):
                    found_forms.append(form)
            
        except Exception as e:
            log_and_notify('error', f"Error extracting links from {base_url}: {e}")
        
        return found_links, found_forms
    
    @staticmethod
    def is_same_domain(url: str, base_domain: str) -> bool:
        """Проверяет, принадлежит ли URL данному домену"""
        try:
            if not url or not base_domain:
                return False
            
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower().split(':')[0]
            base_domain = base_domain.lower().split(':')[0]
            
            if url_domain == base_domain:
                return True
            
            if url_domain.endswith('.' + base_domain):
                return True
            
            if base_domain in ['localhost', '127.0.0.1'] and url_domain in ['localhost', '127.0.0.1']:
                return True
            
            return False
            
        except Exception as e:
            log_and_notify('error', f"Error checking domain {url} against {base_domain}: {e}")
            return False