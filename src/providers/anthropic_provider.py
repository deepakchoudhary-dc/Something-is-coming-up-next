"""
Anthropic Claude LLM provider adapter.

Implements the Anthropic Messages API format with strict response validation.
"""

import logging
import time
from typing import Any, Dict, List, Optional

import requests

from .base import LLMMessage, LLMProvider, LLMResponse, LLMUsage, ProviderError

logger = logging.getLogger(__name__)

_ANTHROPIC_API_VERSION = "2023-06-01"
_NON_RETRYABLE_STATUS = {400, 401, 403, 404}


class AnthropicProvider(LLMProvider):
    """Adapter for the Anthropic Messages API."""

    def __init__(self, base_url: str = "https://api.anthropic.com/v1/messages",
                 api_key: str = "", default_model: str = "claude-3-haiku-20240307"):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._default_model = default_model
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "anthropic-version": _ANTHROPIC_API_VERSION,
        })
        if api_key:
            self._session.headers["x-api-key"] = api_key

    @property
    def name(self) -> str:
        return "anthropic"

    def complete(
        self,
        messages: List[LLMMessage],
        model: str = "",
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        timeout: float = 30.0,
    ) -> LLMResponse:
        model = model or self._default_model

        # Separate system message from user/assistant turns
        system_text = ""
        api_messages = []
        for m in messages:
            if m.role == "system":
                system_text = m.content
            else:
                api_messages.append({"role": m.role, "content": m.content})

        if not api_messages:
            raise ProviderError("At least one non-system message is required", retryable=False)

        payload: Dict[str, Any] = {
            "model": model,
            "messages": api_messages,
            "temperature": temperature,
            "max_tokens": max_tokens or 4096,
        }
        if system_text:
            payload["system"] = system_text

        start = time.monotonic()
        try:
            resp = self._session.post(self._base_url, json=payload, timeout=timeout)
        except requests.exceptions.Timeout as exc:
            raise ProviderError(f"Request timed out after {timeout}s", retryable=True) from exc
        except requests.exceptions.ConnectionError as exc:
            raise ProviderError(f"Connection failed: {exc}", retryable=True) from exc
        latency = (time.monotonic() - start) * 1000

        if resp.status_code != 200:
            retryable = resp.status_code not in _NON_RETRYABLE_STATUS
            error_detail = resp.text[:500]
            raise ProviderError(
                f"Anthropic API error {resp.status_code}: {error_detail}",
                status_code=resp.status_code,
                retryable=retryable,
            )

        raw = resp.json()
        self.validate_response(raw)
        return self._parse_response(raw, model, latency)

    def validate_response(self, raw: Dict[str, Any]) -> None:
        if "content" not in raw:
            raise ProviderError("Response missing 'content' field", retryable=False)
        content_blocks = raw["content"]
        if not isinstance(content_blocks, list) or not content_blocks:
            raise ProviderError("Response 'content' must be a non-empty array", retryable=False)

    def _parse_response(self, raw: Dict[str, Any], model: str, latency: float) -> LLMResponse:
        # Concatenate all text blocks
        text_parts = []
        for block in raw["content"]:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif isinstance(block, str):
                text_parts.append(block)
        content = "".join(text_parts)

        usage_raw = raw.get("usage", {})
        usage = LLMUsage(
            prompt_tokens=usage_raw.get("input_tokens", 0),
            completion_tokens=usage_raw.get("output_tokens", 0),
            total_tokens=usage_raw.get("input_tokens", 0) + usage_raw.get("output_tokens", 0),
        )

        return LLMResponse(
            content=content,
            model=raw.get("model", model),
            usage=usage,
            raw_response=raw,
            provider=self.name,
            latency_ms=latency,
        )
