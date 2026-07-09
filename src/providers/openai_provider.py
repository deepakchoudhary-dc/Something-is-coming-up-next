"""
OpenAI-compatible LLM provider adapter.

Works with OpenAI, Azure OpenAI, vLLM, Ollama, and any endpoint
that speaks the OpenAI chat completions API format.
"""

import logging
import time
from typing import Any, Dict, List, Optional

import requests

from .base import LLMMessage, LLMProvider, LLMResponse, LLMUsage, ProviderError

logger = logging.getLogger(__name__)

_NON_RETRYABLE_STATUS = {400, 401, 403, 404, 422}


class OpenAIProvider(LLMProvider):
    """Adapter for OpenAI-compatible chat completion endpoints."""

    def __init__(self, base_url: str, api_key: str = "", default_model: str = "gpt-3.5-turbo"):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._default_model = default_model
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"

    @property
    def name(self) -> str:
        return "openai"

    def complete(
        self,
        messages: List[LLMMessage],
        model: str = "",
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        timeout: float = 30.0,
    ) -> LLMResponse:
        model = model or self._default_model
        payload: Dict[str, Any] = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

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
            raise ProviderError(
                f"OpenAI API error {resp.status_code}: {resp.text[:500]}",
                status_code=resp.status_code,
                retryable=retryable,
            )

        raw = resp.json()
        self.validate_response(raw)
        return self._parse_response(raw, model, latency)

    def validate_response(self, raw: Dict[str, Any]) -> None:
        if "choices" not in raw:
            raise ProviderError("Response missing 'choices' field", retryable=False)
        if not raw["choices"]:
            raise ProviderError("Response 'choices' array is empty", retryable=False)
        first = raw["choices"][0]
        if "message" not in first or "content" not in first.get("message", {}):
            raise ProviderError("Response choice missing 'message.content'", retryable=False)

    def _parse_response(self, raw: Dict[str, Any], model: str, latency: float) -> LLMResponse:
        choice = raw["choices"][0]
        content = choice["message"]["content"]
        usage_raw = raw.get("usage", {})
        usage = LLMUsage(
            prompt_tokens=usage_raw.get("prompt_tokens", 0),
            completion_tokens=usage_raw.get("completion_tokens", 0),
            total_tokens=usage_raw.get("total_tokens", 0),
        )
        return LLMResponse(
            content=content,
            model=raw.get("model", model),
            usage=usage,
            raw_response=raw,
            provider=self.name,
            latency_ms=latency,
        )
