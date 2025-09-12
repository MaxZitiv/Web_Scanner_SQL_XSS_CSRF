import os
import json
import policies
from utils.database import db
from typing import Dict, Any, List, Optional
from models.policy_model import SecurityPolicy

class PolicyManager:
    def __init__(self, policies_dir: str = "policies"):
        self.policies_dir = policies_dir
        if not os.path.exists(self.policies_dir):
            os.makedirs(self.policies_dir)

    def list_policies(self) -> List[str]:
        return [f[:-5] for f in os.listdir(self.policies_dir) if f.endswith('.json')]

    def load_policy(self, name: str) -> Dict[str, Any]:
        """Загрузка политики из файла и возврат в виде словаря"""
        path = os.path.join(self.policies_dir, f"{name}.json")
        with open(path, "r", encoding="utf-8") as f:
            policy_data = json.load(f)
        return policy_data

    def save_policy(self, name: str, policy) -> None:
        """Сохранение политики в файл после преобразования из датакласса SecurityPolicy или словаря"""
        path = os.path.join(self.policies_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            if isinstance(policy, SecurityPolicy):
                json.dump(policy.to_dict(), f, ensure_ascii=False, indent=2)
            elif isinstance(policy, dict):
                json.dump(policy, f, ensure_ascii=False, indent=2)
            else:
                raise ValueError("Policy must be either SecurityPolicy or dict")

    def delete_policy(self, policy_id: int) -> bool:
        """Удаление политики по её ID"""
        try:
            # Получаем список всех политик
            policies = self.list_policies()

            # Если ID выходит за пределы списка, возвращаем False
            if policy_id < 0 or policy_id >= len(policies):
                return False

            # Получаем имя политики по её ID
            policy_name = policies[policy_id]

            # Формируем путь к файлу политики
            path = os.path.join(self.policies_dir, f"{policy_name}.json")

            # Удаляем файл, если он существует
            if os.path.exists(path):
                os.remove(path)
                return True
            else:
                return False
        except Exception:
            # Игнорируем исключение и просто возвращаем False
            return False

    def get_default_policy(self) -> SecurityPolicy:
        # Можно расширить по желанию
        return SecurityPolicy(
            name="Default",
            enabled_vulns=["sql", "xss", "csrf"],
            sql_payloads="standard",
            xss_payloads="standard",
            max_depth=3,
            max_concurrent=5,
            timeout=30,
            exclude_urls=[],
            custom_headers={},
            respect_robots_txt=True,
            rate_limit=0,
            stop_on_first_vuln=False
        )

    def get_policy_by_id(self, policy_id: int) -> Dict[str, Any]:
        """Получение политики по её ID"""
        try:
            # Получаем список всех политик
            policies = self.list_policies()

            # Если ID выходит за пределы списка, возвращаем политику по умолчанию
            if policy_id < 0 or policy_id >= len(policies):
                return self.get_default_policy().to_dict()

            # Получаем имя политики по её ID
            policy_name = policies[policy_id]

            # Загружаем и возвращаем политику
            return self.load_policy(policy_name)
        except Exception:
            # В случае ошибки возвращаем политику по умолчанию
            return self.get_default_policy().to_dict()

    def get_policy_id(self, name: str) -> int:
        """Получение ID политики по её имени"""
        try:
            # Получаем список всех политик
            policies = self.list_policies()

            # Ищем политику с указанным именем
            for i, policy_name in enumerate(policies):
                if policy_name == name:
                    return i

            # Если политика не найдена, возвращаем -1
            return -1
        except Exception:
            # В случае ошибки возвращаем -1
            return -1

    def get_all_policies(self) -> List[Dict[str, Any]]:
        """Получение списка всех политик с их именами и ID"""
        try:
            policies_list = self.list_policies()

            policies = []
            for i, policy_name in enumerate(policies_list):
                policy_data = self.load_policy(policy_name)
                # Используем метод get для доступа к данным словаря
                name = policy_data.get('name', policy_name) if isinstance(policy_data, dict) else policy_name
                policies.append({
                    'id': i,
                    'name': name
                })

            return policies
        except Exception:
            # В случае ошибки возвращаем пустой список
            return []

    def get_policy(self, policy_id: int) -> Optional[Dict[str, Any]]:
        """Получение политики по её ID"""
        return self.get_policy_by_id(policy_id)

    def update_policy(self, policy_id: int, policy) -> bool:
        """Обновление политики по её ID"""
        try:
            # Получаем список всех политик
            policies = self.list_policies()

            # Если ID выходит за пределы списка, возвращаем False
            if policy_id < 0 or policy_id >= len(policies):
                return False

            # Получаем имя политики по её ID
            policy_name = policies[policy_id]

            # Обновляем политику
            self.save_policy(policy_name, policy)
            return True
        except Exception:
            # В случае ошибки возвращаем False
            return False

    def create_policy(self, policy) -> bool:
        """Создание новой политики"""
        try:
            # Генерируем уникальное имя для политики
            if isinstance(policy, SecurityPolicy):
                policy_name = policy.name
            elif isinstance(policy, dict):
                policy_name = policy.get('name', 'Unnamed Policy')
            else:
                raise ValueError("Policy must be either SecurityPolicy or dict")

            # Проверяем, существует ли уже политика с таким именем
            existing_policies = self.list_policies()
            if policy_name in existing_policies:
                # Если существует, добавляем суффикс
                counter = 1
                while f"{policy_name}_{counter}" in existing_policies:
                    counter += 1
                policy_name = f"{policy_name}_{counter}"

            # Сохраняем политику
            self.save_policy(policy_name, policy)
            return True
        except Exception:
            # В случае ошибки возвращаем False
            return False
