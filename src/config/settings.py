"""
Configuration settings for AI Security Gateway
"""

import json
import os
from typing import Any, List, Optional
from urllib.parse import urlparse
try:
    # Try importing from standard pydantic (V1)
    from pydantic import BaseSettings
except (ImportError, Exception):
    try:
        # Try importing from new pydantic-settings package (V2)
        from pydantic_settings import BaseSettings
    except (ImportError, Exception):
        # Fall back to compatibility v1 namespace in Pydantic V2
        from pydantic.v1 import BaseSettings

_DEFAULT_DEV_SECRET = ""
_PLACEHOLDER_SECRETS = {"", "your-secret-key-here", "dev-only-change-me"}
_PRODUCTION_ENVIRONMENTS = {"prod", "production", "staging"}
_DEFAULT_ALLOWED_ORIGINS = ["http://localhost:3000", "http://localhost:8080", "http://localhost:8000"]
_DEFAULT_ALLOWED_METHODS = ["GET", "POST"]
_DEFAULT_ALLOWED_HEADERS = ["Authorization", "Content-Type", "X-API-Key", "X-Admin-Token", "Idempotency-Key"]
_VALID_CORS_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}


def _parse_csv_or_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError("Expected a valid JSON list or comma-separated string") from exc
            return _parse_csv_or_list(parsed)
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    raise ValueError("Expected a comma-separated string or list")


def _unique(values: List[str]) -> List[str]:
    normalized = []
    for value in values:
        if value not in normalized:
            normalized.append(value)
    return normalized


def _normalize_origin(origin: str) -> str:
    if origin == "*":
        return origin

    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid CORS origin: {origin}")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError(f"CORS origin must not include path, query, or fragment: {origin}")
    if parsed.username or parsed.password:
        raise ValueError(f"CORS origin must not include credentials: {origin}")

    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


class Settings(BaseSettings):
    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ENVIRONMENT: str = "production"

    # CORS
    ALLOWED_ORIGINS: Any = _DEFAULT_ALLOWED_ORIGINS
    ALLOWED_METHODS: Any = _DEFAULT_ALLOWED_METHODS
    ALLOWED_HEADERS: Any = _DEFAULT_ALLOWED_HEADERS
    CORS_ALLOW_CREDENTIALS: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./ai_security.db"

    # Security settings
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ENABLE_SECURITY_HEADERS: bool = True
    API_KEY: Optional[str] = None
    ADMIN_API_KEY: Optional[str] = None
    REQUIRE_AUTH: bool = True
    REQUIRE_ADMIN_AUTH: bool = True
    ALLOW_ADMIN_AUTH_VIA_USER_KEY: bool = False
    ALLOW_CLIENT_SYSTEM_PROMPT: bool = False
    DEFAULT_SYSTEM_PROMPT: str = "You are a secure AI assistant."
    ALLOW_PRIVATE_MODEL_URLS: bool = False

    # AI Model settings
    MAX_PROMPT_LENGTH: int = 10000
    MAX_RESPONSE_LENGTH: int = 5000
    AI_CLASSIFIER_LOCAL_ONLY: bool = True

    # Sandbox settings
    SANDBOX_EXECUTION_ENABLED: bool = False
    SANDBOX_TIMEOUT: int = 5  # seconds
    SANDBOX_MAX_OUTPUT_CHARS: int = 20000
    SANDBOX_MAX_CODE_CHARS: int = 20000
    SANDBOX_RUNNER_COMMAND: Optional[str] = None
    SANDBOX_ALLOW_HOST_RUNNER_IN_PRODUCTION: bool = False
    SANDBOX_ALLOW_HOST_RUNNER_IN_TESTS: bool = False

    # Monitoring
    LOG_LEVEL: str = "INFO"
    ELASTICSEARCH_HOST: str = ""
    ELASTICSEARCH_PORT: int = 9200
    REDTEAM_ENDPOINTS_ENABLED: bool = False

    # Human-in-the-Loop
    HITL_ENABLED: bool = True
    HITL_BLOCKING_WAIT: bool = False
    HITL_APPROVAL_TIMEOUT_SECONDS: int = 300
    HITL_EMAIL: str = "admin@example.com"
    HITL_EXPIRY_HOURS: int = 24

    # Authentication Mode
    AUTH_MODE: str = "jwt"  # api_key | jwt
    JWT_SECRET_KEY: str = ""
    JWT_PUBLIC_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "ai-security-gateway"
    JWT_AUDIENCE: str = ""
    JWT_EXPIRY_MINUTES: int = 30

    # Secrets Management
    VAULT_ADDR: str = ""
    VAULT_TOKEN: str = ""
    SECRETS_BACKEND: str = "vault"

    # Notifications
    NOTIFICATION_PROVIDER: str = "log"  # log | email | webhook
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_USE_TLS: bool = True
    WEBHOOK_URL: str = ""

    # LLM Provider Routing
    PROVIDER_RETRY_MAX: int = 3
    PROVIDER_RETRY_BASE_DELAY: float = 0.5
    PROVIDER_CIRCUIT_BREAKER_THRESHOLD: int = 5
    PROVIDER_CIRCUIT_BREAKER_COOLDOWN: float = 30.0
    PROVIDER_EGRESS_ALLOWLIST: str = ""
    PROVIDER_REQUEST_TIMEOUT: float = 30.0

    # Observability & Alerting
    ALERT_BLOCK_RATE_THRESHOLD: float = 0.5
    ALERT_FAILOVER_RATE_THRESHOLD: float = 0.3
    LOG_FORMAT: str = "json"  # json | text

    # Database Pooling (for Postgres)
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10

    # Idempotency Control
    IDEMPOTENCY_TTL_SECONDS: int = 86400  # 24 hours
    IDEMPOTENCY_MAX_RESPONSE_BYTES: int = 1048576  # 1MB

    class Config:
        env_file = ".env"

    def __init__(self, **values):
        super().__init__(**values)
        self.ENVIRONMENT = os.getenv("APP_ENV", self.ENVIRONMENT).strip().lower()
        self.ALLOWED_ORIGINS = self._validated_origins(self.ALLOWED_ORIGINS)
        self.ALLOWED_METHODS = self._validated_methods(self.ALLOWED_METHODS)
        self.ALLOWED_HEADERS = self._validated_headers(self.ALLOWED_HEADERS)
        self.SECRET_KEY = self._validated_secret(self.SECRET_KEY)
        self._validate_production_auth()
        self._validate_production_sandbox()

        if "*" in self.ALLOWED_ORIGINS and self.CORS_ALLOW_CREDENTIALS:
            if self._is_production:
                raise ValueError("Wildcard CORS origins cannot be used with credentials in production")
            self.CORS_ALLOW_CREDENTIALS = False

    @property
    def _is_production(self) -> bool:
        return self.ENVIRONMENT in _PRODUCTION_ENVIRONMENTS

    def _validated_origins(self, origins: Any) -> List[str]:
        normalized = _unique([_normalize_origin(origin) for origin in _parse_csv_or_list(origins)])
        if self._is_production:
            if not normalized:
                raise ValueError("ALLOWED_ORIGINS must be set in production")
            if "*" in normalized:
                raise ValueError("Wildcard CORS origins are not allowed in production")
            insecure = [
                origin for origin in normalized
                if origin.startswith("http://") and "localhost" not in origin and "127.0.0.1" not in origin
            ]
            if insecure:
                raise ValueError("Production CORS origins must use HTTPS")

        return normalized

    def _validated_methods(self, methods: Any) -> List[str]:
        normalized = _unique([method.upper() for method in _parse_csv_or_list(methods)])
        invalid = [method for method in normalized if method != "*" and method not in _VALID_CORS_METHODS]
        if invalid:
            raise ValueError(f"Invalid CORS methods: {', '.join(invalid)}")
        if self._is_production and "*" in normalized:
            raise ValueError("Wildcard CORS methods are not allowed in production")
        return normalized

    def _validated_headers(self, headers: Any) -> List[str]:
        normalized = _unique(_parse_csv_or_list(headers))
        if self._is_production and "*" in normalized:
            raise ValueError("Wildcard CORS headers are not allowed in production")
        return normalized

    def _validated_secret(self, secret_key: str) -> str:
        secret_key = (secret_key or "").strip()
        if secret_key in _PLACEHOLDER_SECRETS:
            if self._is_production:
                raise ValueError("SECRET_KEY must be set to a non-placeholder value in production")
            env_secret = os.getenv("SECRET_KEY", "").strip()
            return env_secret if env_secret not in _PLACEHOLDER_SECRETS else _DEFAULT_DEV_SECRET

        if self._is_production and len(secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters in production")

        return secret_key

    def _validate_production_auth(self):
        if not self._is_production:
            return

        if self.AUTH_MODE not in {"api_key", "jwt"}:
            raise ValueError("AUTH_MODE must be api_key or jwt")
        if not self.REQUIRE_AUTH or not self.REQUIRE_ADMIN_AUTH:
            raise ValueError("Production authentication and administrative authorization must be enabled")
        if self.AUTH_MODE == "api_key":
            if not self.API_KEY or len(self.API_KEY) < 32:
                raise ValueError("Production API-key authentication requires API_KEY with at least 32 characters")
            if not self.ADMIN_API_KEY or len(self.ADMIN_API_KEY) < 32:
                raise ValueError("Production API-key authentication requires ADMIN_API_KEY with at least 32 characters")
            if self.API_KEY == self.ADMIN_API_KEY:
                raise ValueError("API_KEY and ADMIN_API_KEY must be different")
        else:
            jwt_key = (self.JWT_SECRET_KEY or self.SECRET_KEY or "").strip()
            if self.JWT_ALGORITHM == "HS256" and len(jwt_key) < 32:
                raise ValueError("HS256 JWT authentication requires a dedicated secret of at least 32 characters")
            if self.JWT_ALGORITHM == "RS256" and (not self.JWT_SECRET_KEY or not self.JWT_PUBLIC_KEY):
                raise ValueError("RS256 JWT authentication requires separate JWT_SECRET_KEY and JWT_PUBLIC_KEY values")
        if not self.PROVIDER_EGRESS_ALLOWLIST.strip():
            raise ValueError("Production requires PROVIDER_EGRESS_ALLOWLIST")
        if self.SECRETS_BACKEND != "vault":
            raise ValueError("Production requires SECRETS_BACKEND=vault")
        if not (self.VAULT_ADDR or "").strip().startswith("https://"):
            raise ValueError("Production requires an HTTPS VAULT_ADDR")

    def _validate_production_sandbox(self):
        if not self._is_production:
            return
        if self.SANDBOX_ALLOW_HOST_RUNNER_IN_PRODUCTION:
            raise ValueError("Host subprocess sandbox execution is not allowed in production")
        if self.SANDBOX_EXECUTION_ENABLED and not self.SANDBOX_RUNNER_COMMAND:
            raise ValueError("Production sandbox execution requires SANDBOX_RUNNER_COMMAND or SANDBOX_EXECUTION_ENABLED=false")
        if self.REDTEAM_ENDPOINTS_ENABLED:
            raise ValueError("Production must set REDTEAM_ENDPOINTS_ENABLED=false")

    def normalized_log_level(self) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        level = (self.LOG_LEVEL or "INFO").upper()
        return level if level in allowed else "INFO"

settings = Settings()
