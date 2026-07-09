"""
Audit trail for secret access and rotation events.

Every get / rotate / store operation can be recorded for compliance.
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Integer, String, Text

from ..monitoring.database import Base, SessionLocal

logger = logging.getLogger(__name__)


class SecretAccessLog(Base):
    __tablename__ = "secret_access_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    action = Column(String(50), nullable=False, index=True)  # get, store, rotate, delete
    reference = Column(String(500), nullable=False)
    actor = Column(String(200), nullable=True)  # user / service identity
    tenant_id = Column(String(100), nullable=True)
    detail = Column(Text, nullable=True)


def log_secret_access(
    action: str,
    reference: str,
    actor: Optional[str] = None,
    tenant_id: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    """Record a secret-access event to the audit table."""
    session = SessionLocal()
    try:
        entry = SecretAccessLog(
            action=action,
            reference=_redact_reference(reference),
            actor=actor or "system",
            tenant_id=tenant_id,
            detail=detail,
            timestamp=datetime.utcnow(),
        )
        session.add(entry)
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("Failed to write secret audit log: %s", exc)
    finally:
        session.close()


def _redact_reference(ref: str) -> str:
    """Strip the actual path/key value for storage, keeping only scheme + hash."""
    if not ref:
        return ref
    if "://" in ref:
        scheme, _, path = ref.partition("://")
        # Keep first 8 chars of path for debugging, mask the rest
        if len(path) > 8:
            return f"{scheme}://{path[:8]}***"
        return ref
    return "***"
