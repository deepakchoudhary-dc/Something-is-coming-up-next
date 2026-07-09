"""
Tests for database migration lifecycle.
"""

import os
os.environ.setdefault("DATABASE_URL", f"sqlite:///{os.path.join(os.environ.get('TEMP', '.'), 'ai_security_test.db')}")
os.environ.setdefault("LOG_FORMAT", "text")

from src.monitoring.database import init_db
init_db()

import pytest
from src.monitoring.database import engine, Base, SessionLocal, check_migrations_current
from src.monitoring.database import SecurityLog, HITLRequest, PolicyConfig, GatewayConfig


class TestSchemaIntegrity:
    def test_all_tables_exist(self):
        """All expected tables should exist after init_db."""
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        expected = [
            "security_logs",
            "hitl_requests",
            "policy_configs",
            "gateway_configs",
            "tenants",
            "tenant_users",
            "secret_access_logs",
            "notification_logs",
            "redteam_reports",
        ]
        for table in expected:
            assert table in tables, f"Missing table: {table}"

    def test_security_logs_has_new_columns(self):
        """SecurityLog should have request_id and tenant_id columns."""
        from sqlalchemy import inspect
        inspector = inspect(engine)
        columns = [c["name"] for c in inspector.get_columns("security_logs")]
        assert "request_id" in columns
        assert "tenant_id" in columns

    def test_hitl_requests_has_new_columns(self):
        """HITLRequest should have assignment and notification columns."""
        from sqlalchemy import inspect
        inspector = inspect(engine)
        columns = [c["name"] for c in inspector.get_columns("hitl_requests")]
        assert "assigned_to" in columns
        assert "escalated_at" in columns
        assert "notification_sent" in columns
        assert "tenant_id" in columns

    def test_can_insert_and_query_security_log(self):
        """Should be able to insert and query a SecurityLog."""
        from datetime import datetime
        session = SessionLocal()
        try:
            log = SecurityLog(
                prompt="migration test",
                user_id="test_migration",
                risk_score=0.1,
                flagged=False,
                action_taken="allowed",
                request_id="mig_test_001",
                tenant_id="default",
            )
            session.add(log)
            session.commit()
            
            found = session.query(SecurityLog).filter(SecurityLog.request_id == "mig_test_001").first()
            assert found is not None
            assert found.tenant_id == "default"
        finally:
            session.close()

    def test_migration_check_does_not_crash(self):
        """check_migrations_current should not raise even without alembic stamp."""
        result = check_migrations_current()
        assert isinstance(result, bool)
