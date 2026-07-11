"""
Role-Based Access Control (RBAC) guards for FastAPI endpoints.

Usage::

    @router.get("/admin-only", dependencies=[Depends(require_role("admin"))])
    async def admin_endpoint():
        ...

    @router.get("/review", dependencies=[Depends(require_role("reviewer", "admin"))])
    async def review_endpoint():
        ...
"""

import logging
from typing import Callable, List

from fastapi import Depends, HTTPException, status

from .tenant import CurrentUser, get_current_user

logger = logging.getLogger(__name__)


def require_role(*allowed_roles: str) -> Callable:
    """Return a FastAPI dependency that enforces one-of role membership."""

    async def _guard(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.has_role("admin"):
            return current_user
        for role in allowed_roles:
            if current_user.has_role(role):
                return current_user
        logger.warning(
            "RBAC denied: user=%s tenant=%s roles=%s required=%s",
            current_user.subject, current_user.tenant_id, current_user.roles, allowed_roles,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires one of roles: {', '.join(allowed_roles)}",
        )

    return _guard


def require_admin() -> Callable:
    """Shorthand for ``require_role("admin")``."""
    return require_role("admin")


def require_reviewer() -> Callable:
    """Allow admin or reviewer roles."""
    return require_role("reviewer", "admin")


def require_auditor() -> Callable:
    """Allow admin, auditor, or reviewer roles."""
    return require_role("auditor", "reviewer", "admin")


def require_tenant_access(tenant_id: str) -> Callable:
    """Ensure the current user belongs to the specified tenant."""

    async def _guard(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.tenant_id != tenant_id and not current_user.has_role("admin"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: tenant mismatch",
            )
        return current_user

    return _guard
