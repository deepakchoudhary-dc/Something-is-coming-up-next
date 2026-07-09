"""
JWT token issuance and verification for the AI Security Gateway.

Supports HS256 (symmetric) and RS256 (asymmetric) algorithms.
Tokens carry subject, tenant_id, roles, and standard JWT claims.
"""

import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt as pyjwt

from ..config.settings import settings

logger = logging.getLogger(__name__)

_SUPPORTED_ALGORITHMS = {"HS256", "RS256"}


class TokenError(Exception):
    """Raised when a token cannot be created or verified."""


def _resolve_algorithm() -> str:
    alg = getattr(settings, "JWT_ALGORITHM", "HS256")
    if alg not in _SUPPORTED_ALGORITHMS:
        raise TokenError(f"Unsupported JWT algorithm: {alg}")
    return alg


def _resolve_signing_key() -> str:
    key = getattr(settings, "JWT_SECRET_KEY", "") or settings.SECRET_KEY
    if not key:
        raise TokenError("JWT signing key is not configured")
    return key


def _resolve_verification_key() -> str:
    """For RS256 the verification key may differ (public key).  Falls back to signing key for HS256."""
    return getattr(settings, "JWT_PUBLIC_KEY", "") or _resolve_signing_key()


def create_access_token(
    subject: str,
    tenant_id: str,
    roles: List[str],
    extra_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Issue a signed JWT with standard and gateway-specific claims."""
    algorithm = _resolve_algorithm()
    key = _resolve_signing_key()

    now = datetime.now(timezone.utc)
    expiry = expires_delta or timedelta(minutes=getattr(settings, "JWT_EXPIRY_MINUTES", 30))
    exp = now + expiry

    payload: Dict[str, Any] = {
        "sub": subject,
        "tenant_id": tenant_id,
        "roles": roles,
        "iat": now,
        "exp": exp,
        "iss": getattr(settings, "JWT_ISSUER", "ai-security-gateway"),
    }
    audience = getattr(settings, "JWT_AUDIENCE", "")
    if audience:
        payload["aud"] = audience
    if extra_claims:
        payload.update(extra_claims)

    try:
        token: str = pyjwt.encode(payload, key, algorithm=algorithm)
        return token
    except Exception as exc:
        logger.error("Failed to create JWT: %s", exc)
        raise TokenError("Token creation failed") from exc


def decode_access_token(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT.  Returns the full claims dict on success."""
    algorithm = _resolve_algorithm()
    key = _resolve_verification_key()

    decode_options: Dict[str, Any] = {
        "algorithms": [algorithm],
        "options": {"require": ["sub", "tenant_id", "roles", "exp", "iat"]},
    }

    issuer = getattr(settings, "JWT_ISSUER", "ai-security-gateway")
    if issuer:
        decode_options["issuer"] = issuer

    audience = getattr(settings, "JWT_AUDIENCE", "")
    if audience:
        decode_options["audience"] = audience

    try:
        claims: Dict[str, Any] = pyjwt.decode(token, key, **decode_options)
        return claims
    except pyjwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except pyjwt.InvalidTokenError as exc:
        raise TokenError(f"Invalid token: {exc}") from exc


def create_refresh_token(subject: str, tenant_id: str) -> str:
    """Issue a longer-lived refresh token with minimal claims."""
    algorithm = _resolve_algorithm()
    key = _resolve_signing_key()

    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=7)

    payload = {
        "sub": subject,
        "tenant_id": tenant_id,
        "type": "refresh",
        "iat": now,
        "exp": exp,
        "iss": getattr(settings, "JWT_ISSUER", "ai-security-gateway"),
    }
    return pyjwt.encode(payload, key, algorithm=algorithm)


def decode_refresh_token(token: str) -> Dict[str, Any]:
    """Verify a refresh token.  Ensures the ``type`` claim is ``refresh``."""
    claims = decode_access_token(token)
    if claims.get("type") != "refresh":
        raise TokenError("Token is not a refresh token")
    return claims
