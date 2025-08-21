import os
import json
from typing import Dict, Any, List

class PolicyManager:
    def __init__(self, policies_dir: str = "policies"):
        self.policies_dir = policies_dir
        if not os.path.exists(self.policies_dir):
            os.makedirs(self.policies_dir)

    def list_policies(self) -> List[str]:
        return [f[:-5] for f in os.listdir(self.policies_dir) if f.endswith('.json')]

    def load_policy(self, name: str) -> Dict[str, Any]:
        path = os.path.join(self.policies_dir, f"{name}.json")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_policy(self, name: str, policy: Dict[str, Any]) -> None:
        path = os.path.join(self.policies_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(policy, f, ensure_ascii=False, indent=2)

    def delete_policy(self, name: str) -> None:
        path = os.path.join(self.policies_dir, f"{name}.json")
        if os.path.exists(path):
            os.remove(path)

    def get_default_policy(self) -> Dict[str, Any]:
        # Можно расширить по желанию
        return {
            "name": "Default",
            "enabled_vulns": ["sql", "xss", "csrf"],
            "sql_payloads": "standard",
            "xss_payloads": "standard",
            "max_depth": 3,
            "max_concurrent": 5,
            "timeout": 30,
            "exclude_urls": [],
            "custom_headers": {},
            "respect_robots_txt": True,
            "rate_limit": 0,
            "stop_on_first_vuln": False
        } 