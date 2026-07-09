"""
Human-in-the-Loop (HITL) Management Module - Connected to SQLite database Locally

Enhanced with:
- Real notification dispatch (email/webhook/log)
- Reviewer assignment
- Expiration and escalation
- Completed review history
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from ..config.settings import settings
from ..monitoring.database import SessionLocal, HITLRequest

logger = logging.getLogger(__name__)


class HITLApprovalResult(dict):
    """Structured HITL result with safe truthiness for legacy bool callers."""

    def __bool__(self) -> bool:
        return self.get("status") == "approved"


class HITLManager:
    def __init__(self):
        self.approval_timeout = settings.HITL_APPROVAL_TIMEOUT_SECONDS
        self.expiry_hours = getattr(settings, "HITL_EXPIRY_HOURS", 24)

    async def create_request(self, request_data: Any) -> HITLApprovalResult:
        """
        Create a human approval request and return immediately.
        """
        if not settings.HITL_ENABLED:
            return HITLApprovalResult({
                "request_id": None,
                "status": "approved",
                "approved": True,
                "blocking": False,
                "created": False,
                "reason": "HITL is disabled"
            })

        request_id = self._generate_request_id()
        fields = self._extract_request_fields(request_data)

        session = SessionLocal()
        try:
            db_request = HITLRequest(
                request_id=request_id,
                prompt=fields["prompt"],
                system_prompt=fields["system_prompt"],
                retrieved_context=fields["retrieved_context"],
                context=fields["context"],
                model=fields["model"],
                user_id=fields["user_id"],
                status="pending",
                notification_sent=False,
                created_at=datetime.utcnow()
            )
            session.add(db_request)
            session.commit()
            logger.info(f"Created HITL pending request: {request_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save HITL request: {e}")
            return HITLApprovalResult({
                "request_id": request_id,
                "status": "error",
                "approved": False,
                "blocking": False,
                "created": False,
                "error": "failed_to_create_hitl_request"
            })
        finally:
            session.close()

        # Send notification via dispatcher
        await self._send_notification(request_id, fields["user_id"], fields["prompt"])
        return HITLApprovalResult({
            "request_id": request_id,
            "status": "pending",
            "approved": False,
            "blocking": False,
            "created": True
        })

    async def request_approval(self, request_data: Any) -> HITLApprovalResult:
        """
        Request human approval for high-risk requests.

        Production default is non-blocking: create a pending request and return
        request_id/status immediately. Set HITL_BLOCKING_WAIT=true to opt in to
        the legacy wait-for-decision behavior.
        """
        if not settings.HITL_BLOCKING_WAIT:
            return await self.create_request(request_data)

        return await self._request_approval_blocking_result(request_data)

    async def request_approval_blocking(self, request_data: Any) -> bool:
        """
        Boolean compatibility method for callers that need a decision before continuing.
        Respects HITL_APPROVAL_TIMEOUT_SECONDS for the maximum wait.
        """
        return bool(await self._request_approval_blocking_result(request_data))

    async def _request_approval_blocking_result(self, request_data: Any) -> HITLApprovalResult:
        """Create a HITL request and block until a decision or timeout."""
        created = await self.create_request(request_data)
        if created.get("status") != "pending":
            return created

        request_id = created["request_id"]

        # Wait for approval with timeout
        try:
            approved = await asyncio.wait_for(
                self._wait_for_approval(request_id),
                timeout=self.approval_timeout
            )
            return HITLApprovalResult({
                "request_id": request_id,
                "status": "approved" if approved else "denied",
                "approved": approved,
                "blocking": True,
                "created": True
            })
        except asyncio.TimeoutError:
            logger.warning(f"Approval timeout for request {request_id}")
            self._mark_timeout(request_id)
            return HITLApprovalResult({
                "request_id": request_id,
                "status": "timeout",
                "approved": False,
                "blocking": True,
                "created": True
            })

    def _extract_request_fields(self, request_data: Any) -> Dict[str, str]:
        """Normalize dict and pydantic-style request objects into audit fields."""
        def field(name: str, default: str = "") -> str:
            if isinstance(request_data, dict):
                value = request_data.get(name, default)
            else:
                value = getattr(request_data, name, default)
            return value if value is not None else default

        return {
            "prompt": field("prompt"),
            "system_prompt": field("system_prompt"),
            "retrieved_context": field("retrieved_context"),
            "context": field("context"),
            "model": field("model", "unknown"),
            "user_id": field("user_id", "unknown")
        }

    def _mark_timeout(self, request_id: str):
        """Mark a pending request as timed out."""
        db_session = SessionLocal()
        try:
            db_req = db_session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
            if db_req and db_req.status == "pending":
                db_req.status = "timeout"
                db_req.decision_at = datetime.utcnow()
                db_session.commit()
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error saving HITL timeout: {e}")
        finally:
            db_session.close()

    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        return f"hitl_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"

    async def _wait_for_approval(self, request_id: str) -> bool:
        """Wait for human approval by polling the SQLite database"""
        while True:
            await asyncio.sleep(2)  # Check DB every 2 seconds
            session = SessionLocal()
            try:
                db_req = session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
                if db_req:
                    if db_req.status == "approved":
                        return True
                    elif db_req.status in ["denied", "timeout"]:
                        return False
            except Exception as e:
                logger.error(f"Error checking HITL status: {e}")
            finally:
                session.close()

    async def approve_request(self, request_id: str, approved: bool, admin_name: str = "Admin") -> bool:
        """Approve or deny a request in the database"""
        session = SessionLocal()
        try:
            db_req = session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
            if db_req and db_req.status == "pending":
                db_req.status = "approved" if approved else "denied"
                db_req.decision_by = admin_name
                db_req.decision_at = datetime.utcnow()
                session.commit()
                logger.info(f"Request {request_id} manually {'approved' if approved else 'denied'} by {admin_name}")
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to approve request {request_id}: {e}")
            return False
        finally:
            session.close()

    def assign_reviewer(self, request_id: str, reviewer: str) -> bool:
        """Assign a reviewer to a pending request."""
        session = SessionLocal()
        try:
            db_req = session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
            if db_req and db_req.status == "pending":
                db_req.assigned_to = reviewer
                session.commit()
                logger.info("Request %s assigned to %s", request_id, reviewer)
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error("Failed to assign reviewer for %s: %s", request_id, e)
            return False
        finally:
            session.close()

    async def _send_notification(self, request_id: str, user_id: str, prompt: str):
        """Send notification via the configured dispatcher."""
        try:
            from ..queue.notifications import get_notification_dispatcher
            dispatcher = get_notification_dispatcher()
            recipient = settings.HITL_EMAIL
            subject = f"[AI Security Gateway] HITL Review Required: {request_id}"
            body = (
                f"A request requires human review.\n\n"
                f"Request ID: {request_id}\n"
                f"User: {user_id}\n"
                f"Prompt preview: {prompt[:200]}...\n\n"
                f"Approve: POST /api/v1/hitl/approve/{request_id} with {{\"approved\": true}}\n"
                f"Deny: POST /api/v1/hitl/approve/{request_id} with {{\"approved\": false}}\n"
            )
            success = await dispatcher.send(
                recipient=recipient,
                subject=subject,
                body=body,
                metadata={"request_id": request_id, "user_id": user_id},
            )
            # Mark notification as sent
            if success:
                session = SessionLocal()
                try:
                    db_req = session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
                    if db_req:
                        db_req.notification_sent = True
                        session.commit()
                except Exception:
                    session.rollback()
                finally:
                    session.close()
        except Exception as exc:
            logger.error("Notification dispatch failed for %s: %s", request_id, exc)

    def get_pending_requests(self) -> Dict[str, Dict]:
        """Get all pending approval requests from DB"""
        session = SessionLocal()
        try:
            db_reqs = session.query(HITLRequest).filter(HITLRequest.status == "pending").all()
            return {
                r.request_id: {
                    "id": r.request_id,
                    "prompt": r.prompt,
                    "context": r.context,
                    "model": r.model,
                    "user_id": r.user_id,
                    "timestamp": r.created_at.isoformat(),
                    "status": r.status,
                    "assigned_to": getattr(r, "assigned_to", None),
                    "notification_sent": getattr(r, "notification_sent", False),
                }
                for r in db_reqs
            }
        except Exception as e:
            logger.error(f"Error fetching pending requests: {e}")
            return {}
        finally:
            session.close()

    def get_request_details(self, request_id: str) -> Optional[Dict]:
        """Get details of a specific request"""
        session = SessionLocal()
        try:
            r = session.query(HITLRequest).filter(HITLRequest.request_id == request_id).first()
            if r:
                return {
                    "id": r.request_id,
                    "prompt": r.prompt,
                    "context": r.context,
                    "model": r.model,
                    "user_id": r.user_id,
                    "timestamp": r.created_at.isoformat(),
                    "status": r.status,
                    "decision_by": r.decision_by,
                    "decision_at": r.decision_at.isoformat() if r.decision_at else None,
                    "assigned_to": getattr(r, "assigned_to", None),
                    "escalated_at": r.escalated_at.isoformat() if getattr(r, "escalated_at", None) else None,
                    "notification_sent": getattr(r, "notification_sent", False),
                }
            return None
        except Exception as e:
            logger.error(f"Error fetching request details: {e}")
            return None
        finally:
            session.close()

    def get_completed_history(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Get completed (approved/denied/timeout) review history."""
        session = SessionLocal()
        try:
            db_reqs = (
                session.query(HITLRequest)
                .filter(HITLRequest.status.in_(["approved", "denied", "timeout"]))
                .order_by(HITLRequest.decision_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            return [{
                "id": r.request_id,
                "user_id": r.user_id,
                "model": r.model,
                "status": r.status,
                "decision_by": r.decision_by,
                "decision_at": r.decision_at.isoformat() if r.decision_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "assigned_to": getattr(r, "assigned_to", None),
            } for r in db_reqs]
        except Exception as e:
            logger.error("Error fetching HITL history: %s", e)
            return []
        finally:
            session.close()

    def expire_stale_requests(self) -> int:
        """Expire pending requests older than HITL_EXPIRY_HOURS.  Returns count expired."""
        cutoff = datetime.utcnow() - timedelta(hours=self.expiry_hours)
        session = SessionLocal()
        try:
            stale = session.query(HITLRequest).filter(
                HITLRequest.status == "pending",
                HITLRequest.created_at < cutoff,
            ).all()
            count = 0
            for req in stale:
                req.status = "timeout"
                req.decision_at = datetime.utcnow()
                req.escalated_at = datetime.utcnow()
                count += 1
            if count:
                session.commit()
                logger.warning("Expired %d stale HITL requests older than %d hours", count, self.expiry_hours)
            return count
        except Exception as e:
            session.rollback()
            logger.error("Error expiring stale HITL requests: %s", e)
            return 0
        finally:
            session.close()

    def cleanup_old_requests(self):
        """Clean up old completed requests from DB"""
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        session = SessionLocal()
        try:
            deleted = session.query(HITLRequest).filter(
                HITLRequest.status != "pending",
                HITLRequest.created_at < cutoff_time
            ).delete()
            session.commit()
            if deleted:
                logger.info(f"Cleaned up {deleted} old HITL requests from DB")
        except Exception as e:
            session.rollback()
            logger.error(f"Error cleaning up old HITL requests: {e}")
        finally:
            session.close()
