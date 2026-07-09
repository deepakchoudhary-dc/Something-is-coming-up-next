"""
Deterministic mock LLM provider for testing and development.

Returns predictable responses without any network calls.
"""

import logging
import time
from typing import Any, Dict, List, Optional

from .base import LLMMessage, LLMProvider, LLMResponse, LLMUsage

logger = logging.getLogger(__name__)


class MockProvider(LLMProvider):
    """Returns canned responses for local development and testing."""

    def __init__(self, default_response: str = "Processed successfully."):
        self._default_response = default_response

    @property
    def name(self) -> str:
        return "mock"

    def complete(
        self,
        messages: List[LLMMessage],
        model: str = "mock-model",
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        timeout: float = 30.0,
    ) -> LLMResponse:
        start = time.monotonic()

        # Build a deterministic response based on input
        user_content = ""
        for m in messages:
            if m.role == "user":
                user_content = m.content
                break

        response_text = self._default_response
        prompt_tokens = sum(len(m.content.split()) for m in messages)
        completion_tokens = len(response_text.split())

        latency = (time.monotonic() - start) * 1000

        return LLMResponse(
            content=response_text,
            model=model,
            usage=LLMUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            raw_response={"mock": True},
            provider=self.name,
            latency_ms=latency,
        )
