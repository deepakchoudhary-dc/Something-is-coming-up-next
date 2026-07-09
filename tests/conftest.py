"""
Shared pytest fixtures for AI Security Gateway integration tests.
"""

import os
import pytest

# Force test database before any imports
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(os.environ.get('TEMP', '.'), 'ai_security_test.db')}"
os.environ["REQUIRE_AUTH"] = "false"
os.environ["AUTH_MODE"] = "api_key"
os.environ["LOG_FORMAT"] = "text"

from src.monitoring.database import init_db, engine, Base
init_db()

from fastapi.testclient import TestClient
from src.main import app
from src.config.settings import settings


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create all tables at session start."""
    Base.metadata.create_all(bind=engine)
    yield
    # Optionally drop tables after
    # Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="module")
def client():
    """FastAPI test client."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_headers():
    """Headers for admin-authenticated requests."""
    if settings.ADMIN_API_KEY:
        return {"X-Admin-Token": settings.ADMIN_API_KEY}
    return {}


@pytest.fixture
def user_headers():
    """Headers for user-authenticated requests."""
    if settings.API_KEY:
        return {"X-Api-Key": settings.API_KEY}
    return {}
