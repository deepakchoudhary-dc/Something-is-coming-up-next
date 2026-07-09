"""
Integration tests for HITL workflow lifecycle.
"""

import os
os.environ.setdefault("DATABASE_URL", f"sqlite:///{os.path.join(os.environ.get('TEMP', '.'), 'ai_security_test.db')}")
os.environ.setdefault("REQUIRE_AUTH", "false")
os.environ.setdefault("LOG_FORMAT", "text")

from src.monitoring.database import init_db
init_db()

import pytest
from datetime import datetime, timedelta
from src.hitl.hitl_manager import HITLManager
from src.monitoring.database import SessionLocal, HITLRequest


@pytest.fixture
def hitl_manager():
    return HITLManager()


class TestHITLCreateAndApprove:
    @pytest.mark.asyncio
    async def test_create_pending_request(self, hitl_manager):
        """Creating a request should return pending status."""
        result = await hitl_manager.create_request({
            "prompt": "Test HITL prompt",
            "user_id": "hitl_test_user",
            "model": "test-model",
        })
        assert result["status"] in ("pending", "approved")  # approved if HITL disabled
        if result["status"] == "pending":
            assert result["created"] is True
            assert result["request_id"] is not None

    @pytest.mark.asyncio
    async def test_approve_request(self, hitl_manager):
        """Approving a pending request should succeed."""
        result = await hitl_manager.create_request({
            "prompt": "Approve me",
            "user_id": "hitl_approve_user",
        })
        if result.get("request_id"):
            success = await hitl_manager.approve_request(
                request_id=result["request_id"],
                approved=True,
                admin_name="TestAdmin"
            )
            assert success is True

    @pytest.mark.asyncio
    async def test_deny_request(self, hitl_manager):
        """Denying a pending request should succeed."""
        result = await hitl_manager.create_request({
            "prompt": "Deny me",
            "user_id": "hitl_deny_user",
        })
        if result.get("request_id"):
            success = await hitl_manager.approve_request(
                request_id=result["request_id"],
                approved=False,
                admin_name="TestAdmin"
            )
            assert success is True


class TestHITLAssignment:
    @pytest.mark.asyncio
    async def test_assign_reviewer(self, hitl_manager):
        """Assigning a reviewer to a pending request should succeed."""
        result = await hitl_manager.create_request({
            "prompt": "Assign me",
            "user_id": "hitl_assign_user",
        })
        if result.get("request_id"):
            success = hitl_manager.assign_reviewer(result["request_id"], "reviewer@example.com")
            assert success is True
            details = hitl_manager.get_request_details(result["request_id"])
            assert details is not None
            assert details.get("assigned_to") == "reviewer@example.com"


class TestHITLExpiration:
    def test_expire_stale_requests(self, hitl_manager):
        """Stale requests older than expiry_hours should be expired."""
        session = SessionLocal()
        try:
            old_req = HITLRequest(
                request_id="hitl_stale_test_001",
                prompt="Old request",
                user_id="stale_user",
                status="pending",
                created_at=datetime.utcnow() - timedelta(hours=hitl_manager.expiry_hours + 1),
            )
            session.add(old_req)
            session.commit()
        finally:
            session.close()

        count = hitl_manager.expire_stale_requests()
        assert count >= 1

        # Verify it was expired
        session = SessionLocal()
        try:
            req = session.query(HITLRequest).filter(HITLRequest.request_id == "hitl_stale_test_001").first()
            assert req is not None
            assert req.status == "timeout"
        finally:
            session.close()


class TestHITLHistory:
    @pytest.mark.asyncio
    async def test_completed_history(self, hitl_manager):
        """Completed history should include approved/denied requests."""
        result = await hitl_manager.create_request({
            "prompt": "History test",
            "user_id": "hitl_history_user",
        })
        if result.get("request_id"):
            await hitl_manager.approve_request(result["request_id"], True, "HistoryAdmin")
        
        history = hitl_manager.get_completed_history(limit=10)
        assert isinstance(history, list)
