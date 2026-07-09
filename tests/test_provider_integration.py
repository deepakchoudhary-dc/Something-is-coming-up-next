"""
Integration tests for LLM provider adapters, circuit breaker, and retry logic.
"""

import pytest
import time
from src.providers.base import LLMMessage, LLMResponse, LLMUsage, ProviderError
from src.providers.mock_provider import MockProvider
from src.providers.circuit_breaker import CircuitBreaker, CircuitBreakerOpen, CircuitState
from src.providers.retry import retry_with_backoff, RetryBudgetExhausted


class TestMockProvider:
    def test_mock_returns_response(self):
        """Mock provider should return a valid LLMResponse."""
        provider = MockProvider()
        messages = [LLMMessage(role="user", content="Hello")]
        resp = provider.complete(messages)
        assert isinstance(resp, LLMResponse)
        assert resp.content == "Processed successfully."
        assert resp.provider == "mock"
        assert resp.usage.total_tokens > 0

    def test_mock_custom_response(self):
        """Mock provider should use custom default response."""
        provider = MockProvider(default_response="Custom reply")
        messages = [LLMMessage(role="user", content="Test")]
        resp = provider.complete(messages)
        assert resp.content == "Custom reply"


class TestCircuitBreaker:
    def test_starts_closed(self):
        """Circuit breaker should start in CLOSED state."""
        cb = CircuitBreaker("test", failure_threshold=3, cooldown_seconds=1.0)
        assert cb.state == CircuitState.CLOSED

    def test_opens_after_threshold(self):
        """Circuit should open after N failures."""
        cb = CircuitBreaker("test", failure_threshold=3, cooldown_seconds=10.0)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_blocks_when_open(self):
        """Should raise CircuitBreakerOpen when open."""
        cb = CircuitBreaker("test", failure_threshold=2, cooldown_seconds=10.0)
        cb.record_failure()
        cb.record_failure()
        with pytest.raises(CircuitBreakerOpen):
            cb.check()

    def test_half_open_after_cooldown(self):
        """Circuit should transition to HALF_OPEN after cooldown."""
        cb = CircuitBreaker("test", failure_threshold=1, cooldown_seconds=0.1)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

    def test_closes_on_success(self):
        """Circuit should close on successful call."""
        cb = CircuitBreaker("test", failure_threshold=1, cooldown_seconds=0.1)
        cb.record_failure()
        time.sleep(0.15)
        cb.check()  # HALF_OPEN allows this
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_reset(self):
        """Manual reset should close the circuit."""
        cb = CircuitBreaker("test", failure_threshold=1)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED

    def test_to_dict(self):
        """Serialisation should include all fields."""
        cb = CircuitBreaker("test_breaker", failure_threshold=5, cooldown_seconds=30.0)
        d = cb.to_dict()
        assert d["name"] == "test_breaker"
        assert d["state"] == "closed"
        assert d["failure_threshold"] == 5


class TestRetryWithBackoff:
    def test_succeeds_without_retry(self):
        """Should return immediately on success."""
        result = retry_with_backoff(lambda: "ok", max_retries=3)
        assert result == "ok"

    def test_retries_on_retryable_error(self):
        """Should retry and eventually succeed."""
        call_count = [0]

        def flaky():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ProviderError("fail", retryable=True)
            return "ok"

        result = retry_with_backoff(flaky, max_retries=3, base_delay=0.01)
        assert result == "ok"
        assert call_count[0] == 3

    def test_does_not_retry_non_retryable(self):
        """Should raise immediately on non-retryable error."""
        def always_fail():
            raise ProviderError("permanent", retryable=False)

        with pytest.raises(ProviderError, match="permanent"):
            retry_with_backoff(always_fail, max_retries=3)

    def test_exhausts_retries(self):
        """Should raise RetryBudgetExhausted when all retries fail."""
        def always_fail():
            raise ProviderError("fail", retryable=True)

        with pytest.raises(RetryBudgetExhausted):
            retry_with_backoff(always_fail, max_retries=2, base_delay=0.01)

    def test_budget_seconds_limit(self):
        """Should respect the time budget."""
        def slow_fail():
            time.sleep(0.05)
            raise ProviderError("slow", retryable=True)

        with pytest.raises(RetryBudgetExhausted):
            retry_with_backoff(slow_fail, max_retries=100, base_delay=0.01, budget_seconds=0.1)
