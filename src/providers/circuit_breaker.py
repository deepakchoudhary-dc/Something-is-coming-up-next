"""
Thread-safe circuit breaker for outbound LLM provider calls.

State machine: CLOSED → OPEN (after N failures) → HALF_OPEN (after cooldown) → CLOSED (on success).
"""

import logging
import threading
import time
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpen(Exception):
    """Raised when the circuit is open and calls are being short-circuited."""


class CircuitBreaker:
    """Per-provider circuit breaker with configurable thresholds."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
        half_open_max_attempts: int = 2,
    ):
        self.name = name
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._half_open_max_attempts = half_open_max_attempts

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0
        self._half_open_attempts = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if time.monotonic() - self._last_failure_time >= self._cooldown_seconds:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_attempts = 0
                    logger.info("Circuit %s transitioned OPEN → HALF_OPEN", self.name)
            return self._state

    def check(self) -> None:
        """Call before making a request.  Raises ``CircuitBreakerOpen`` if the circuit is open."""
        current = self.state
        if current == CircuitState.OPEN:
            raise CircuitBreakerOpen(
                f"Circuit breaker {self.name!r} is OPEN — calls blocked for "
                f"{self._cooldown_seconds - (time.monotonic() - self._last_failure_time):.1f}s more"
            )
        if current == CircuitState.HALF_OPEN:
            with self._lock:
                if self._half_open_attempts >= self._half_open_max_attempts:
                    raise CircuitBreakerOpen(
                        f"Circuit breaker {self.name!r} HALF_OPEN attempt limit reached"
                    )
                self._half_open_attempts += 1

    def record_success(self) -> None:
        """Record a successful call — resets the breaker to CLOSED."""
        with self._lock:
            if self._state != CircuitState.CLOSED:
                logger.info("Circuit %s → CLOSED (success)", self.name)
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_attempts = 0

    def record_failure(self) -> None:
        """Record a failed call.  Opens the circuit when the threshold is exceeded."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning("Circuit %s → OPEN (half-open probe failed, count=%d)",
                               self.name, self._failure_count)
            elif self._failure_count >= self._failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning("Circuit %s → OPEN (failure threshold %d reached)",
                               self.name, self._failure_threshold)

    def reset(self) -> None:
        """Force-reset to CLOSED (for testing / admin override)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_attempts = 0
            logger.info("Circuit %s manually reset to CLOSED", self.name)

    def to_dict(self) -> dict:
        """Serialise current state for observability endpoints."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self._failure_threshold,
            "cooldown_seconds": self._cooldown_seconds,
        }
