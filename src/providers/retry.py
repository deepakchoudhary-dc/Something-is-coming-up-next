"""
Retry logic with exponential backoff and jitter for LLM provider calls.

Budget-aware: tracks total retry time and refuses to exceed the caller's timeout.
"""

import logging
import random
import time
from typing import Callable, Optional, TypeVar

from .base import ProviderError

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RetryBudgetExhausted(Exception):
    """Raised when retries are exhausted or the time budget is spent."""


def retry_with_backoff(
    fn: Callable[[], T],
    max_retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    budget_seconds: Optional[float] = None,
) -> T:
    """Execute *fn*, retrying on retryable ``ProviderError`` with exponential backoff + jitter.

    Args:
        fn: Zero-argument callable to execute.
        max_retries: Maximum number of retry attempts (not counting the first try).
        base_delay: Initial delay between retries in seconds.
        max_delay: Cap on the per-retry delay.
        budget_seconds: Total wall-clock budget.  If the elapsed time exceeds
            this, remaining retries are abandoned.

    Returns:
        The return value of *fn* on success.

    Raises:
        RetryBudgetExhausted: When all retries fail or the budget runs out.
        ProviderError: Re-raised on non-retryable errors.
    """
    start = time.monotonic()
    last_exc: Optional[Exception] = None

    for attempt in range(1 + max_retries):
        # Budget check
        if budget_seconds is not None and (time.monotonic() - start) >= budget_seconds:
            raise RetryBudgetExhausted(
                f"Retry budget of {budget_seconds}s exhausted after {attempt} attempt(s)"
            )

        try:
            result = fn()
            if attempt > 0:
                logger.info("Succeeded on retry attempt %d", attempt)
            return result
        except ProviderError as exc:
            last_exc = exc
            if not exc.retryable:
                raise
            if attempt >= max_retries:
                break
            delay = min(base_delay * (2 ** attempt) + random.uniform(0, base_delay), max_delay)
            # Check remaining budget
            if budget_seconds is not None:
                remaining = budget_seconds - (time.monotonic() - start)
                if delay > remaining:
                    delay = max(0, remaining)
                    if delay <= 0:
                        break
            logger.warning(
                "Provider error (attempt %d/%d), retrying in %.2fs: %s",
                attempt + 1, max_retries + 1, delay, exc,
            )
            time.sleep(delay)
        except Exception as exc:
            # Non-provider errors are not retried
            raise

    raise RetryBudgetExhausted(
        f"All {max_retries + 1} attempts failed. Last error: {last_exc}"
    )
