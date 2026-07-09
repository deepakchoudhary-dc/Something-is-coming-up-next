"""
Tenant and user identity models with FastAPI dependency injection.

Provides the ``get_current_user`` dependency that extracts identity
from either a JWT bearer token or a legacy API key, depending on
``AUTH_MODE``.
"""

import enum
import logging
import secrets
from datetime import datetime
from typing import List, Optional

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from ..config.settings import settings
from ..monitoring.database import Base, SessionLocal
from .jwt_auth import TokenError, decode_access_token

logger = logging.getLogger(__name__)


# ── Role Enum ──────────────────────────────────────────────────────────
class UserRole(str, enum.Enum):
    viewer = "viewer"
    user = "user"
    auditor = "auditor"
    reviewer = "reviewer"
    admin = "admin"


# ── SQLAlchemy Models ──────────────────────────────────────────────────
class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), unique=True, nullable=False, index=True)
    api_key_hash = Column(String(255), nullable=True)
    settings_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("TenantUser", back_populates="tenant", lazy="selectin")


class TenantUser(Base):
    __tablename__ = "tenant_users"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(200), nullable=False, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(Enum(UserRole), default=UserRole.user, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    tenant = relationship("Tenant", back_populates="users")


# ── Identity Container ────────────────────────────────────────────────
class CurrentUser:
    """Lightweight identity object propagated through request processing."""

    __slots__ = ("subject", "tenant_id", "roles", "auth_method")

    def __init__(self, subject: str, tenant_id: str, roles: List[str], auth_method: str = "jwt"):
        self.subject = subject
        self.tenant_id = tenant_id
        self.roles = roles
        self.auth_method = auth_method

    def has_role(self, role: str) -> bool:
        return role in self.roles or "admin" in self.roles

    def __repr__(self) -> str:
        return f"<CurrentUser subject={self.subject!r} tenant={self.tenant_id!r} roles={self.roles!r}>"


# ── FastAPI Dependencies ──────────────────────────────────────────────

def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


async def get_current_user(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_admin_token: Optional[str] = Header(default=None),
) -> CurrentUser:
    """Resolve the calling identity from either JWT or legacy API-key."""
    auth_mode = getattr(settings, "AUTH_MODE", "api_key")

    # ── JWT path ──────────────────────────────────────────────────
    if auth_mode == "jwt":
        token = _extract_bearer_token(authorization)
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
        try:
            claims = decode_access_token(token)
        except TokenError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
        return CurrentUser(
            subject=claims["sub"],
            tenant_id=claims["tenant_id"],
            roles=claims.get("roles", []),
            auth_method="jwt",
        )

    # ── Legacy API-key path (default for development) ─────────────
    if not settings.REQUIRE_AUTH:
        return CurrentUser(subject="anonymous", tenant_id="default", roles=["admin"], auth_method="api_key")

    if not settings.API_KEY:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Authentication is not configured")

    # Check admin token first
    if x_admin_token and settings.ADMIN_API_KEY and secrets.compare_digest(x_admin_token, settings.ADMIN_API_KEY):
        return CurrentUser(subject="admin", tenant_id="default", roles=["admin"], auth_method="api_key")

    # Check user API key
    if x_api_key and secrets.compare_digest(x_api_key, settings.API_KEY):
        # Determine if admin via user key when allowed
        roles = ["user"]
        if settings.ALLOW_ADMIN_AUTH_VIA_USER_KEY and x_api_key == settings.ADMIN_API_KEY:
            roles = ["admin"]
        return CurrentUser(subject="api_key_user", tenant_id="default", roles=roles, auth_method="api_key")

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


async def get_current_user_optional(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_admin_token: Optional[str] = Header(default=None),
) -> Optional[CurrentUser]:
    """Same as get_current_user but returns None instead of raising when unauthenticated."""
    try:
        return await get_current_user(authorization, x_api_key, x_admin_token)
    except HTTPException:
        return None
