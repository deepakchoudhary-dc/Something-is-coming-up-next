"""
Provider routing with failover, circuit breaker, retry, and egress allowlist.

The ``ProviderRouter`` is the single entry point that the gateway router
uses to send requests to external LLM providers.  It encapsulates:

- Provider selection (primary → fallback)
- Circuit-breaker integration
- Retry with backoff
- Egress domain allowlist enforcement
"""

import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..config.settings import settings
from .base import LLMMessage, LLMProvider, LLMResponse, ProviderError
from .circuit_breaker import CircuitBreaker, CircuitBreakerOpen
from .mock_provider import MockProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .retry import RetryBudgetExhausted, retry_with_backoff

logger = logging.getLogger(__name__)


class EgressDenied(ProviderError):
    """Raised when an outbound URL is not on the egress allowlist."""

    def __init__(self, url: str):
        super().__init__(f"Egress denied: {url} is not on the allowlist", retryable=False)


class ProviderRouter:
    """Top-level provider orchestrator for the gateway."""

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._max_retries = int(getattr(settings, "PROVIDER_RETRY_MAX", 3))
        self._base_delay = float(getattr(settings, "PROVIDER_RETRY_BASE_DELAY", 0.5))
        self._request_timeout = float(getattr(settings, "PROVIDER_REQUEST_TIMEOUT", 30.0))
        self._cb_threshold = int(getattr(settings, "PROVIDER_CIRCUIT_BREAKER_THRESHOLD", 5))
        self._cb_cooldown = float(getattr(settings, "PROVIDER_CIRCUIT_BREAKER_COOLDOWN", 30.0))
        self._egress_allowlist = self._parse_allowlist(
            getattr(settings, "PROVIDER_EGRESS_ALLOWLIST", "")
        )

    def _parse_allowlist(self, raw: str) -> List[str]:
        if not raw:
            return []
        return [d.strip().lower() for d in raw.split(",") if d.strip()]

    def _check_egress(self, url: str) -> None:
        """Enforce egress allowlist if configured."""
        if not self._egress_allowlist:
            return
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not any(host == allowed or host.endswith("." + allowed) for allowed in self._egress_allowlist):
            raise EgressDenied(url)

    def _get_breaker(self, provider_key: str) -> CircuitBreaker:
        if provider_key not in self._breakers:
            self._breakers[provider_key] = CircuitBreaker(
                name=provider_key,
                failure_threshold=self._cb_threshold,
                cooldown_seconds=self._cb_cooldown,
            )
        return self._breakers[provider_key]

    def build_provider(self, provider_type: str, url: str, key: str, model: str) -> LLMProvider:
        """Construct a provider instance from config values."""
        if provider_type == "mock":
            return MockProvider()
        if provider_type in ("openai", "custom"):
            return OpenAIProvider(base_url=url, api_key=key, default_model=model)
        if provider_type == "anthropic":
            return AnthropicProvider(base_url=url, api_key=key, default_model=model)
        raise ProviderError(f"Unknown provider type: {provider_type}", retryable=False)

    def complete(
        self,
        messages: List[LLMMessage],
        primary_provider_type: str,
        primary_url: str,
        primary_key: str,
        primary_model: str,
        fallback_enabled: bool = False,
        fallback_provider_type: str = "mock",
        fallback_url: str = "",
        fallback_key: str = "",
        fallback_model: str = "",
    ) -> LLMResponse:
        """Route a completion through primary (with retry + CB), failing over to fallback."""

        # ── Try primary ───────────────────────────────────────────
        if primary_provider_type != "mock":
            self._check_egress(primary_url)

        primary = self.build_provider(primary_provider_type, primary_url, primary_key, primary_model)
        breaker = self._get_breaker(f"primary:{primary_provider_type}")

        try:
            breaker.check()
            response = retry_with_backoff(
                fn=lambda: primary.complete(messages, primary_model, timeout=self._request_timeout),
                max_retries=self._max_retries,
                base_delay=self._base_delay,
                budget_seconds=self._request_timeout * 2,
            )
            breaker.record_success()
            return response
        except CircuitBreakerOpen as exc:
            logger.warning("Primary circuit open: %s", exc)
        except (RetryBudgetExhausted, ProviderError) as exc:
            breaker.record_failure()
            logger.error("Primary provider failed: %s", exc)

        # ── Failover ──────────────────────────────────────────────
        if not fallback_enabled:
            raise ProviderError(
                "Primary provider failed and no fallback is configured", retryable=False
            )

        logger.warning("Failing over to fallback provider: %s", fallback_provider_type)

        if fallback_provider_type != "mock":
            self._check_egress(fallback_url)

        fallback = self.build_provider(fallback_provider_type, fallback_url, fallback_key, fallback_model)
        fb_breaker = self._get_breaker(f"fallback:{fallback_provider_type}")

        try:
            fb_breaker.check()
            response = retry_with_backoff(
                fn=lambda: fallback.complete(messages, fallback_model, timeout=self._request_timeout),
                max_retries=max(1, self._max_retries // 2),
                base_delay=self._base_delay,
                budget_seconds=self._request_timeout,
            )
            fb_breaker.record_success()
            response.provider = f"{fallback.name}(fallback)"
            return response
        except CircuitBreakerOpen as exc:
            raise ProviderError(f"Fallback circuit also open: {exc}", retryable=False)
        except (RetryBudgetExhausted, ProviderError) as exc:
            fb_breaker.record_failure()
            raise ProviderError(
                f"Both primary and fallback providers failed. Last: {exc}", retryable=False
            )

    def get_circuit_states(self) -> Dict[str, dict]:
        """Return current circuit breaker states for observability."""
        return {name: cb.to_dict() for name, cb in self._breakers.items()}
