"""
Policy Management Module - Connected to SQLite database
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from ..monitoring.database import SessionLocal, PolicyConfig
from ..config.settings import settings

@dataclass
class Policy:
    name: str
    description: str
    rules: Dict[str, Any]
    enabled: bool = True

class PolicyManager:
    def __init__(self):
        self.policies = self._load_policies()

    def _load_policies(self) -> Dict[str, Policy]:
        """Load policies from SQLite database"""
        session = SessionLocal()
        try:
            db_policies = session.query(PolicyConfig).all()
            if db_policies:
                policies = {}
                for p in db_policies:
                    try:
                        rules = json.loads(p.rules_json)
                    except Exception:
                        rules = {}
                    policies[p.name] = Policy(
                        name=p.name,
                        description=p.description or "",
                        rules=rules,
                        enabled=p.enabled
                    )
                return policies
        except Exception as e:
            print(f"Error loading policies from DB: {e}")
        finally:
            session.close()

        # Fallback to default policies if DB check fails or table is empty
        return self._get_default_policies()

    def _get_default_policies(self) -> Dict[str, Policy]:
        """Get default security policies"""
        return {
            "input_validation": Policy(
                name="input_validation",
                description="Basic input validation rules",
                rules={
                    "max_length": 10000,
                    "min_length": 1,
                    "block_patterns": [
                        "ignore previous instructions",
                        "ignore all previous",
                        "system prompt",
                        "override instructions",
                        "jailbreak",
                        "dan mode",
                        "developer mode"
                    ]
                }
            ),
            "content_filtering": Policy(
                name="content_filtering",
                description="Content-based filtering rules",
                rules={
                    "toxicity_threshold": 0.7,
                    "block_categories": ["toxic", "threat", "insult"],
                    "allow_domains": ["business", "education", "general"]
                }
            ),
            "rate_limiting": Policy(
                name="rate_limiting",
                description="Rate limiting for API usage",
                rules={
                    "requests_per_minute": 60,
                    "requests_per_hour": 1000,
                    "burst_limit": 10
                }
            ),
            "user_access": Policy(
                name="user_access",
                description="Role-based access control",
                rules={
                    "roles": {
                        "admin": {"all_access": True},
                        "user": {"max_requests": 100},
                        "guest": {"max_requests": 10, "restricted_models": True}
                    }
                }
            )
        }

    def _save_policies(self):
        """Save policies state from self.policies back to the database"""
        session = SessionLocal()
        try:
            for name, policy in self.policies.items():
                db_p = session.query(PolicyConfig).filter(PolicyConfig.name == name).first()
                if not db_p:
                    db_p = PolicyConfig(name=name)
                    session.add(db_p)
                db_p.description = policy.description
                db_p.rules_json = json.dumps(policy.rules)
                db_p.enabled = policy.enabled
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error saving policies to DB: {e}")
        finally:
            session.close()

    def check_policy(self, user_id: str, classification: Dict[str, Any]) -> bool:
        """
        Check if request complies with policies
        """
        # Reload latest policies from database
        self.policies = self._load_policies()

        # Check content filtering policy
        content_policy = self.policies.get("content_filtering")
        if content_policy and content_policy.enabled:
            if classification.get("flagged", False):
                return False

            score = classification.get("score", 0)
            if score > content_policy.rules.get("toxicity_threshold", 0.7):
                return False

        return True

    def get_policies(self) -> Dict[str, Dict]:
        """Get all policies"""
        self.policies = self._load_policies()
        return {
            name: {
                "name": policy.name,
                "description": policy.description,
                "rules": policy.rules,
                "enabled": policy.enabled
            }
            for name, policy in self.policies.items()
        }

    def update_policies(self, policies_data: Dict[str, Dict]) -> Dict[str, str]:
        """Update policies"""
        self.policies = self._load_policies()
        updated = []
        session = SessionLocal()
        try:
            for name, policy_data in policies_data.items():
                db_p = session.query(PolicyConfig).filter(PolicyConfig.name == name).first()
                if db_p:
                    if "description" in policy_data:
                        db_p.description = policy_data["description"]
                    if "rules" in policy_data:
                        db_p.rules_json = json.dumps(policy_data["rules"])
                    if "enabled" in policy_data:
                        db_p.enabled = policy_data["enabled"]
                    updated.append(name)
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error updating policies: {e}")
            return {"updated": [], "message": f"Error: {str(e)}"}
        finally:
            session.close()

        # Sync local copy
        self.policies = self._load_policies()
        return {"updated": updated, "message": f"Updated {len(updated)} policies"}

    def enable_policy(self, policy_name: str) -> bool:
        """Enable a specific policy"""
        session = SessionLocal()
        try:
            db_p = session.query(PolicyConfig).filter(PolicyConfig.name == policy_name).first()
            if db_p:
                db_p.enabled = True
                session.commit()
                self.policies = self._load_policies()
                return True
        except Exception as e:
            session.rollback()
            print(f"Error enabling policy: {e}")
        finally:
            session.close()
        return False

    def disable_policy(self, policy_name: str) -> bool:
        """Disable a specific policy"""
        session = SessionLocal()
        try:
            db_p = session.query(PolicyConfig).filter(PolicyConfig.name == policy_name).first()
            if db_p:
                db_p.enabled = False
                session.commit()
                self.policies = self._load_policies()
                return True
        except Exception as e:
            session.rollback()
            print(f"Error disabling policy: {e}")
        finally:
            session.close()
        return False

    def add_policy(self, name: str, policy_data: Dict) -> bool:
        """Add a new policy"""
        session = SessionLocal()
        try:
            db_p = session.query(PolicyConfig).filter(PolicyConfig.name == name).first()
            if not db_p:
                new_policy = PolicyConfig(
                    name=name,
                    description=policy_data.get("description", ""),
                    rules_json=json.dumps(policy_data.get("rules", {})),
                    enabled=policy_data.get("enabled", True)
                )
                session.add(new_policy)
                session.commit()
                self.policies = self._load_policies()
                return True
        except Exception as e:
            session.rollback()
            print(f"Error adding policy: {e}")
        finally:
            session.close()
        return False

    def remove_policy(self, name: str) -> bool:
        """Remove a policy"""
        session = SessionLocal()
        try:
            db_p = session.query(PolicyConfig).filter(PolicyConfig.name == name).first()
            if db_p:
                session.delete(db_p)
                session.commit()
                self.policies = self._load_policies()
                return True
        except Exception as e:
            session.rollback()
            print(f"Error removing policy: {e}")
        finally:
            session.close()
        return False
