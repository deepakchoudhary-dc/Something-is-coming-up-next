"""Durable, tenant-scoped idempotency control for side-effecting gateway requests."""

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from sqlalchemy.exc import IntegrityError

from ..config.settings import settings
from ..monitoring.database import IdempotencyRecord, SessionLocal

_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{16,128}$")
_ENDPOINT = "/api/v1/process"


class IdempotencyError(Exception):
    status_code = 409


class IdempotencyConflict(IdempotencyError):
    """The caller reused an idempotency key with different request content."""


class IdempotencyInProgress(IdempotencyError):
    """A request with this key is already executing or its outcome is unknown."""


@dataclass(frozen=True)
class IdempotencyClaim:
    record_id: int
    execution_token: str


class IdempotencyService:
    """Portable claim/replay store.

    The claim is committed before any outbound work.  A crash after an external
    request but before completion intentionally leaves the key in progress;
    this fails closed instead of risking a duplicate paid model invocation.
    """

    def validate_key(self, key: Optional[str]) -> str:
        if not key or not _KEY_PATTERN.fullmatch(key):
            raise ValueError("Idempotency-Key must be 16-128 URL-safe characters")
        return key

    def fingerprint(self, body: Dict[str, Any]) -> str:
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def claim_or_replay(
        self, *, tenant_id: str, subject: str, key: str, request_fingerprint: str
    ) -> tuple[Optional[IdempotencyClaim], Optional[Dict[str, Any]]]:
        key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        now = datetime.utcnow()
        session = SessionLocal()
        try:
            existing = self._get(session, tenant_id, subject, key_digest)
            if existing and existing.expires_at <= now:
                session.delete(existing)
                session.commit()
                existing = None
            if existing:
                return self._existing(existing, request_fingerprint)

            token = uuid.uuid4().hex
            record = IdempotencyRecord(
                tenant_id=tenant_id,
                subject=subject,
                endpoint=_ENDPOINT,
                key_digest=key_digest,
                request_fingerprint=request_fingerprint,
                state="in_progress",
                execution_token=token,
                created_at=now,
                updated_at=now,
                expires_at=now + timedelta(seconds=settings.IDEMPOTENCY_TTL_SECONDS),
            )
            session.add(record)
            try:
                session.commit()
                return IdempotencyClaim(record.id, token), None
            except IntegrityError:
                session.rollback()
                winner = self._get(session, tenant_id, subject, key_digest)
                if winner is None:
                    raise
                return self._existing(winner, request_fingerprint)
        finally:
            session.close()

    def complete(self, claim: IdempotencyClaim, response: Dict[str, Any]) -> None:
        serialized = json.dumps(response, separators=(",", ":"), ensure_ascii=False)
        if len(serialized.encode("utf-8")) > settings.IDEMPOTENCY_MAX_RESPONSE_BYTES:
            raise IdempotencyError("Idempotency response exceeds the configured storage limit")
        session = SessionLocal()
        try:
            record = session.query(IdempotencyRecord).filter(
                IdempotencyRecord.id == claim.record_id,
                IdempotencyRecord.execution_token == claim.execution_token,
                IdempotencyRecord.state == "in_progress",
            ).first()
            if record is None:
                raise IdempotencyInProgress("Idempotency claim is no longer owned by this request")
            record.state = "completed"
            record.response_status = 200
            record.response_json = serialized
            record.completed_at = datetime.utcnow()
            record.updated_at = record.completed_at
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def release(self, claim: Optional[IdempotencyClaim]) -> None:
        """Release only work that failed before a durable application response."""
        if claim is None:
            return
        session = SessionLocal()
        try:
            session.query(IdempotencyRecord).filter(
                IdempotencyRecord.id == claim.record_id,
                IdempotencyRecord.execution_token == claim.execution_token,
                IdempotencyRecord.state == "in_progress",
            ).delete(synchronize_session=False)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    @staticmethod
    def _get(session: Any, tenant_id: str, subject: str, key_digest: str) -> Optional[IdempotencyRecord]:
        return session.query(IdempotencyRecord).filter(
            IdempotencyRecord.tenant_id == tenant_id,
            IdempotencyRecord.subject == subject,
            IdempotencyRecord.endpoint == _ENDPOINT,
            IdempotencyRecord.key_digest == key_digest,
        ).first()

    @staticmethod
    def _existing(record: IdempotencyRecord, request_fingerprint: str) -> tuple[Optional[IdempotencyClaim], Optional[Dict[str, Any]]]:
        if record.request_fingerprint != request_fingerprint:
            raise IdempotencyConflict("Idempotency-Key was already used with a different request")
        if record.state == "completed" and record.response_json:
            return None, json.loads(record.response_json)
        raise IdempotencyInProgress("A request with this Idempotency-Key is still in progress")