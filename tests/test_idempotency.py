"""
Unit and integration tests for Idempotency Service and Gateway Idempotency Controls.
"""

import os
import time
import pytest
from datetime import datetime, timedelta

os.environ.setdefault(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(os.environ.get('TEMP', '.'), 'ai_security_idempotency_test.db')}"
)
os.environ.setdefault("REQUIRE_AUTH", "false")
os.environ.setdefault("LOG_FORMAT", "text")

from src.monitoring.database import init_db, SessionLocal, IdempotencyRecord
init_db()

from fastapi.testclient import TestClient
from src.main import app
from src.gateway.idempotency import (
    IdempotencyService,
    IdempotencyClaim,
    IdempotencyError,
    IdempotencyConflict,
    IdempotencyInProgress,
)
from src.config.settings import settings


@pytest.fixture
def service():
    return IdempotencyService()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


class TestIdempotencyValidation:
    def test_valid_keys(self, service):
        valid_key = "a" * 16
        assert service.validate_key(valid_key) == valid_key

        valid_key_mixed = "ValidKey-123.456_~abc"
        assert service.validate_key(valid_key_mixed) == valid_key_mixed

    def test_invalid_keys_rejected(self, service):
        with pytest.raises(ValueError, match="16-128 URL-safe characters"):
            service.validate_key("")

        with pytest.raises(ValueError, match="16-128 URL-safe characters"):
            service.validate_key("too_short")

        with pytest.raises(ValueError, match="16-128 URL-safe characters"):
            service.validate_key("a" * 129)

        with pytest.raises(ValueError, match="16-128 URL-safe characters"):
            service.validate_key("invalid key with spaces!!")


class TestIdempotencyFingerprint:
    def test_deterministic_fingerprint(self, service):
        body1 = {"prompt": "Hello", "model": "gpt-3.5-turbo"}
        body2 = {"model": "gpt-3.5-turbo", "prompt": "Hello"}
        assert service.fingerprint(body1) == service.fingerprint(body2)

    def test_different_bodies_have_different_fingerprints(self, service):
        body1 = {"prompt": "Hello"}
        body2 = {"prompt": "World"}
        assert service.fingerprint(body1) != service.fingerprint(body2)


class TestIdempotencyLifecycle:
    def test_claim_complete_and_replay(self, service):
        tenant_id = "tenant_test_1"
        subject = "user_test_1"
        key = "unique-test-key-000000001"
        body = {"prompt": "Idempotency unit test prompt"}
        fp = service.fingerprint(body)

        # First attempt -> Claim
        claim, replayed = service.claim_or_replay(
            tenant_id=tenant_id, subject=subject, key=key, request_fingerprint=fp
        )
        assert claim is not None
        assert replayed is None

        # Complete the claim
        resp_data = {"response": "Processed output", "security_score": 0.1, "action_taken": "allowed"}
        service.complete(claim, resp_data)

        # Re-attempt with same key and body -> Replay response
        claim_2, replayed_2 = service.claim_or_replay(
            tenant_id=tenant_id, subject=subject, key=key, request_fingerprint=fp
        )
        assert claim_2 is None
        assert replayed_2 == resp_data

    def test_conflict_on_different_body(self, service):
        tenant_id = "tenant_test_2"
        subject = "user_test_2"
        key = "unique-test-key-000000002"
        body1 = {"prompt": "Original prompt"}
        body2 = {"prompt": "Tampered prompt"}

        claim, _ = service.claim_or_replay(
            tenant_id=tenant_id, subject=subject, key=key, request_fingerprint=service.fingerprint(body1)
        )
        assert claim is not None

        # Same key with different body raises conflict
        with pytest.raises(IdempotencyConflict, match="already used with a different request"):
            service.claim_or_replay(
                tenant_id=tenant_id, subject=subject, key=key, request_fingerprint=service.fingerprint(body2)
            )

    def test_in_progress_re-claim_rejected(self, service):
        tenant_id = "tenant_test_3"
        subject = "user_test_3"
        key = "unique-test-key-000000003"
        body = {"prompt": "In-progress prompt"}
        fp = service.fingerprint(body)

        claim, _ = service.claim_or_replay(
            tenant_id=tenant_id, subject=subject, key=key, request_fingerprint=fp
        )
        assert claim is not None

        # Re-claiming while state='in_progress' raises IdempotencyInProgress
        with pytest.raises(IdempotencyInProgress, match="still in progress"):
            service.claim_or_replay(
                tenant_id=tenant_id, subject=subject, key=key, request_fingerprint=fp
            )

    def test_release_allows_retry(self, service):
        tenant_id = "tenant_test_4"
        subject = "user_test_4"
        key = "unique-test-key-000000004"
        body = {"prompt": "Failed execution prompt"}
        fp = service.fingerprint(body)

        claim, _ = service.claim_or_replay(
            tenant_id=tenant_id, subject=subject, key=key, request_fingerprint=fp
        )
        assert claim is not None

        # Release claim (e.g. after exception)
        service.release(claim)

        # Key should now be available for new claim
        claim_retry, replayed = service.claim_or_replay(
            tenant_id=tenant_id, subject=subject, key=key, request_fingerprint=fp
        )
        assert claim_retry is not None
        assert replayed is None

    def test_exceed_max_response_bytes_raises(self, service):
        tenant_id = "tenant_test_5"
        subject = "user_test_5"
        key = "unique-test-key-000000005"
        body = {"prompt": "Large response test"}
        fp = service.fingerprint(body)

        claim, _ = service.claim_or_replay(
            tenant_id=tenant_id, subject=subject, key=key, request_fingerprint=fp
        )

        large_payload = {"data": "x" * (settings.IDEMPOTENCY_MAX_RESPONSE_BYTES + 100)}
        with pytest.raises(IdempotencyError, match="exceeds the configured storage limit"):
            service.complete(claim, large_payload)


class TestApiRouteIdempotency:
    def test_api_process_with_idempotency_key(self, client):
        key = "api-test-key-1234567890"
        headers = {"Idempotency-Key": key}
        payload = {"prompt": "What is 2 + 2?", "user_id": "test_idemp_user"}

        # First API call
        resp1 = client.post("/api/v1/process", json=payload, headers=headers)
        assert resp1.status_code == 200
        data1 = resp1.json()

        # Second API call with same key -> Replays stored response
        resp2 = client.post("/api/v1/process", json=payload, headers=headers)
        assert resp2.status_code == 200
        data2 = resp2.json()

        assert data1["request_id"] == data2["request_id"]
        assert data1["response"] == data2["response"]

    def test_api_process_key_conflict(self, client):
        key = "api-test-key-conflict-12345"
        headers = {"Idempotency-Key": key}

        # First request
        resp1 = client.post("/api/v1/process", json={"prompt": "First prompt"}, headers=headers)
        assert resp1.status_code == 200

        # Second request with different body using same key
        resp2 = client.post("/api/v1/process", json={"prompt": "Second prompt"}, headers=headers)
        assert resp2.status_code == 409
        assert "different request" in resp2.json()["detail"]
