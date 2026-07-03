"""
Human-in-the-Loop (HITL) Management Module - Connected to SQLite database
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from ..config.settings import settings
from ..monitoring.database import SessionLocal, HITLRequest

logger = logging.getLogger(__name__)

class HITLManager:
    def __init__(self):
        self.approval_timeout = 300  # 5 minutes

    async def request_approval(self, request_data: Any) -> bool:
        """
        Request human approval for high-risk requests, storing state in database
        """
        if not settings.HITL_ENABLED:
            return True  # Auto-approve if HITL is disabled

        request_id = self._generate_request_id()

        # Handle pydantic or dict
        prompt = getattr(request_data, "prompt", None)
        if prompt is None and isinstance(request_data, dict):
            prompt = request_data.get("prompt", "")
            user_id = request_data.get("user_id", "unknown")
            context = request_data.get("context", "")
            model = request_data.get("model", "unknown")
        else:
            prompt = prompt or ""
            user_id = getattr(request_data, "user_id", "unknown")
            context = getattr(request_data, "context", "")
            model = getattr(request_data, "model", "unknown")

        session = SessionLocal()
        try:
            db_request = HITLRequest(
                request_id=request_id,
                prompt=prompt,
                context=context,
                model=model,
                user_id=user_id,
                status="pending",
                created_at=datetime.utcnow()
            )
            session.add(db_request)
            session.commit()
            logger.info(f"Created HITL pending request: {request_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save HITL request: {e}")
            return False  # Deny if database save fails
        finally:
            session.close()

        # Send notification email (logged)
        await self._send_notification_email(request_id, user_id, prompt)

        # Wait for approval with timeout
        try:
            result = await asyncio.wait_for(
                self._wait_for_approval(request_id),
                timeout=self.approval_timeout
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(f"Approval timeout for request {request_id}")
            # Mark timeout in DB
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
            return False  # Deny on timeout

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

    async def _send_notification_email(self, request_id: str, user_id: str, prompt: str):
        """Log approval notification details (placeholder for production SMTP)"""
        logger.info(
            f"[NOTIFICATION EMAIL] HITL approval required for {request_id}.\n"
            f"User: {user_id}\n"
            f"Prompt: {prompt[:100]}...\n"
            f"Approve: POST /api/v1/hitl/approve/{request_id} with {{\"approved\": true}}"
        )

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
                    "status": r.status
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
                    "decision_at": r.decision_at.isoformat() if r.decision_at else None
                }
            return None
        except Exception as e:
            logger.error(f"Error fetching request details: {e}")
            return None
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
