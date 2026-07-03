"""
Configuration settings for AI Security Gateway
"""

import os
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

class Settings(BaseSettings):
    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # CORS
    ALLOWED_ORIGINS: list = ["http://localhost:3000", "http://localhost:8080"]

    # Database
    DATABASE_URL: str = "sqlite:///./ai_security.db"

    # Security settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-here")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # AI Model settings
    MAX_PROMPT_LENGTH: int = 10000
    MAX_RESPONSE_LENGTH: int = 5000

    # Sandbox settings
    SANDBOX_TIMEOUT: int = 30  # seconds

    # Monitoring
    LOG_LEVEL: str = "INFO"
    ELASTICSEARCH_HOST: str = "localhost"
    ELASTICSEARCH_PORT: int = 9200

    # Human-in-the-Loop
    HITL_ENABLED: bool = True
    HITL_EMAIL: str = "admin@example.com"

    class Config:
        env_file = ".env"

settings = Settings()
