"""
Secrets management abstraction for the AI Security Gateway.

Provides a uniform interface for storing, retrieving, and rotating secrets
regardless of the backend (environment variables, HashiCorp Vault, etc.).

Secrets are stored in the database as *references* (e.g. ``env://OPENAI_KEY``
or ``vault://secret/data/provider-keys#api_key``), never as raw values.
"""

import abc
import hashlib
import logging
import os
import re
import time
from typing import Any, Dict, Optional

from ..config.settings import settings

logger = logging.getLogger(__name__)

_REFERENCE_PATTERN = re.compile(r"^(?P<backend>\w+)://(?P<path>.+)$")


class SecretsError(Exception):
    """Raised on secret retrieval or storage failure."""


# ── Abstract interface ─────────────────────────────────────────────────
class SecretsBackend(abc.ABC):
    """Backend contract that every secrets provider must implement."""

    @abc.abstractmethod
    def get(self, path: str) -> str:
        """Retrieve the plaintext secret value for *path*."""

    @abc.abstractmethod
    def store(self, path: str, value: str) -> str:
        """Persist *value* and return the canonical reference string."""

    @abc.abstractmethod
    def rotate(self, path: str, new_value: str) -> str:
        """Replace the secret at *path* with *new_value*."""

    @abc.abstractmethod
    def delete(self, path: str) -> None:
        """Delete the secret at *path*."""


# ── Environment-variable backend (dev / staging) ──────────────────────
class EnvSecretsBackend(SecretsBackend):
    """Reads secrets from environment variables.

    Reference format: ``env://VAR_NAME``
    """

    def get(self, path: str) -> str:
        value = os.environ.get(path)
        if value is None:
            raise SecretsError(f"Environment variable {path!r} is not set")
        return value

    def store(self, path: str, value: str) -> str:
        os.environ[path] = value
        return f"env://{path}"

    def rotate(self, path: str, new_value: str) -> str:
        return self.store(path, new_value)

    def delete(self, path: str) -> None:
        os.environ.pop(path, None)


# ── HashiCorp Vault backend (production) ──────────────────────────────
class VaultSecretsBackend(SecretsBackend):
    """Reads / writes secrets via the Vault KV v2 API.

    Reference format: ``vault://mount/path#field``

    Requires ``hvac`` to be installed and ``VAULT_ADDR`` / ``VAULT_TOKEN``
    environment variables (or settings equivalents) to be configured.
    """

    def __init__(self):
        try:
            import hvac
        except ImportError as exc:
            raise SecretsError("hvac package is required for Vault backend") from exc

        vault_addr = getattr(settings, "VAULT_ADDR", "") or os.environ.get("VAULT_ADDR", "")
        vault_token = getattr(settings, "VAULT_TOKEN", "") or os.environ.get("VAULT_TOKEN", "")
        if not vault_addr:
            raise SecretsError("VAULT_ADDR is not configured")

        self._client = hvac.Client(url=vault_addr, token=vault_token)
        if not self._client.is_authenticated():
            raise SecretsError("Vault authentication failed")
        logger.info("Vault secrets backend connected to %s", vault_addr)

    def _parse_path(self, path: str):
        """Split ``mount/path#field`` into components."""
        field = None
        if "#" in path:
            path, field = path.rsplit("#", 1)
        parts = path.split("/", 1)
        if len(parts) < 2:
            raise SecretsError(f"Invalid Vault path: {path}")
        return parts[0], parts[1], field

    def get(self, path: str) -> str:
        mount, secret_path, field = self._parse_path(path)
        try:
            result = self._client.secrets.kv.v2.read_secret_version(
                mount_point=mount, path=secret_path, raise_on_deleted_version=True,
            )
        except Exception as exc:
            raise SecretsError(f"Vault read failed for {path}: {exc}") from exc
        data = result.get("data", {}).get("data", {})
        if field:
            if field not in data:
                raise SecretsError(f"Field {field!r} not found at Vault path {path}")
            return data[field]
        if len(data) == 1:
            return next(iter(data.values()))
        raise SecretsError(f"Vault path {path} has multiple fields; specify #field")

    def store(self, path: str, value: str) -> str:
        mount, secret_path, field = self._parse_path(path)
        field = field or "value"
        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                mount_point=mount, path=secret_path, secret={field: value},
            )
        except Exception as exc:
            raise SecretsError(f"Vault write failed for {path}: {exc}") from exc
        return f"vault://{mount}/{secret_path}#{field}"

    def rotate(self, path: str, new_value: str) -> str:
        return self.store(path, new_value)

    def delete(self, path: str) -> None:
        mount, secret_path, _ = self._parse_path(path)
        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                mount_point=mount, path=secret_path,
            )
        except Exception as exc:
            logger.error("Vault delete failed for %s: %s", path, exc)


# ── In-memory backend (tests) ────────────────────────────────────────
class InMemorySecretsBackend(SecretsBackend):
    """Thread-safe in-memory store for unit tests."""

    def __init__(self):
        self._store: Dict[str, str] = {}

    def get(self, path: str) -> str:
        if path not in self._store:
            raise SecretsError(f"Secret {path!r} not found")
        return self._store[path]

    def store(self, path: str, value: str) -> str:
        self._store[path] = value
        return f"mem://{path}"

    def rotate(self, path: str, new_value: str) -> str:
        return self.store(path, new_value)

    def delete(self, path: str) -> None:
        self._store.pop(path, None)


# ── Facade ─────────────────────────────────────────────────────────────
class SecretsManager:
    """Unified facade that dispatches to the correct backend based on the reference prefix."""

    def __init__(self):
        self._backends: Dict[str, SecretsBackend] = {}
        if not settings._is_production:
            self._backends["env"] = EnvSecretsBackend()
        # Attempt to initialise Vault backend if configured
        vault_addr = getattr(settings, "VAULT_ADDR", "") or os.environ.get("VAULT_ADDR", "")
        if vault_addr:
            try:
                self._backends["vault"] = VaultSecretsBackend()
            except SecretsError as exc:
                logger.warning("Vault backend unavailable: %s", exc)

    def _resolve_backend(self, reference: str) -> tuple:
        match = _REFERENCE_PATTERN.match(reference)
        if not match:
            raise SecretsError(f"Malformed secret reference: {reference!r}")
        backend_name = match.group("backend")
        path = match.group("path")
        backend = self._backends.get(backend_name)
        if backend is None:
            raise SecretsError(f"No backend registered for scheme {backend_name!r}")
        return backend, path

    def get_secret(self, reference: str, actor: Optional[str] = None, tenant_id: Optional[str] = None) -> str:
        """Retrieve the plaintext value for a stored reference."""
        if not reference or not _REFERENCE_PATTERN.match(reference):
            # Not a reference — return as-is (backward compat for raw values in dev)
            return reference
        backend, path = self._resolve_backend(reference)
        if settings._is_production and not reference.startswith("vault://"):
            raise SecretsError("Production only permits vault:// secret references")
        value = backend.get(path)
        try:
            from .audit_trail import log_secret_access
            log_secret_access("get", reference, actor=actor, tenant_id=tenant_id)
        except Exception as exc:
            logger.error("Failed to log secret access: %s", exc)
        return value

    def store_secret(self, value: str, backend_name: str = "env", path: Optional[str] = None, actor: Optional[str] = None, tenant_id: Optional[str] = None) -> str:
        """Persist a secret and return the reference string."""
        if backend_name not in self._backends:
            raise SecretsError(f"Backend {backend_name!r} is not available")
        if path is None:
            path = f"GATEWAY_SECRET_{hashlib.sha256(value.encode()).hexdigest()[:12].upper()}"
        ref = self._backends[backend_name].store(path, value)
        try:
            from .audit_trail import log_secret_access
            log_secret_access("store", ref, actor=actor, tenant_id=tenant_id)
        except Exception as exc:
            logger.error("Failed to log secret storage: %s", exc)
        return ref

    def rotate_secret(self, reference: str, new_value: str, actor: Optional[str] = None, tenant_id: Optional[str] = None) -> str:
        """Replace the secret behind a reference with a new value."""
        backend, path = self._resolve_backend(reference)
        ref = backend.rotate(path, new_value)
        try:
            from .audit_trail import log_secret_access
            log_secret_access("rotate", ref, actor=actor, tenant_id=tenant_id)
        except Exception as exc:
            logger.error("Failed to log secret rotation: %s", exc)
        return ref

    def is_reference(self, value: str) -> bool:
        """Check whether a string looks like a secret reference."""
        return bool(_REFERENCE_PATTERN.match(value or ""))

    def is_masked(self, value: str) -> bool:
        """Check whether a string looks like a masked display value."""
        return bool(value) and ("..." in value or "***" in value or value.strip() == "********")


# Module-level singleton
_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    global _manager
    if _manager is None:
        _manager = SecretsManager()
    return _manager
