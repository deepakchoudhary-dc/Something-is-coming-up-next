"""
Base types for LLM provider adapters.

Every provider implements the ``LLMProvider`` protocol so the gateway
can swap backends without changing routing logic.
"""

import abc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LLMMessage:
    role: str  # system | user | assistant
    content: str


@dataclass
class LLMUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class LLMResponse:
    content: str
    model: str
    usage: LLMUsage = field(default_factory=LLMUsage)
    raw_response: Optional[Dict[str, Any]] = None
    provider: str = ""
    latency_ms: float = 0.0


class ProviderError(Exception):
    """Base exception for provider failures."""

    def __init__(self, message: str, status_code: Optional[int] = None, retryable: bool = True):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


class LLMProvider(abc.ABC):
    """Abstract base for outbound LLM providers."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Short identifier for this provider (e.g. 'openai', 'anthropic')."""

    @abc.abstractmethod
    def complete(
        self,
        messages: List[LLMMessage],
        model: str,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        timeout: float = 30.0,
    ) -> LLMResponse:
        """Send a completion request and return the response."""

    def validate_response(self, raw: Dict[str, Any]) -> None:
        """Optional hook to validate raw API response schema before parsing."""
