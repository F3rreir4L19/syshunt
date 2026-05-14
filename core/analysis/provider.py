from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


class AIProvider(ABC):
    """Abstract interface for LLM providers used by the AI classifier."""

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Send *prompt* to the model and return the response text."""
        raise NotImplementedError

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this provider is configured and reachable."""
        raise NotImplementedError


class AnthropicProvider(AIProvider):
    """Provider backed by Anthropic Claude API."""

    def __init__(self, model: str = "claude-sonnet-4-6", api_key: str | None = None) -> None:
        self.model = model
        self._api_key = api_key if api_key is not None else os.getenv("ANTHROPIC_API_KEY", "")

    def is_available(self) -> bool:
        return bool(self._api_key)

    def complete(self, prompt: str) -> str:
        import anthropic

        client = anthropic.Anthropic(api_key=self._api_key)
        message = client.messages.create(
            model=self.model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text


class OpenAICompatibleProvider(AIProvider):
    """Provider backed by any OpenAI-compatible API endpoint."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY", "")
        self._base_url = base_url if base_url is not None else os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self._model = model if model is not None else os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def is_available(self) -> bool:
        return bool(self._api_key)

    def complete(self, prompt: str) -> str:
        try:
            import openai
        except ImportError as exc:
            raise ImportError(
                "Install syshunt[openai] to use OpenAI-compatible providers"
            ) from exc

        client = openai.OpenAI(api_key=self._api_key, base_url=self._base_url)
        response = client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""


class OllamaProvider(AIProvider):
    """Provider backed by a local Ollama instance."""

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        self._base_url = base_url if base_url is not None else os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self._model = model if model is not None else os.getenv("OLLAMA_MODEL", "llama3.2")

    def is_available(self) -> bool:
        import urllib.request

        try:
            urllib.request.urlopen(f"{self._base_url}/api/tags", timeout=2)
            return True
        except Exception:
            return False

    def complete(self, prompt: str) -> str:
        import json
        import urllib.request

        payload = json.dumps({"model": self._model, "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request(
            f"{self._base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        return data.get("response", "")


def get_provider(session: "Session | None" = None) -> AIProvider | None:
    """Detect and return the best available AIProvider, or None if none configured.

    When *session* is provided, API keys and provider preference are read from
    the ``system_settings`` table first, falling back to env vars. Keys are
    injected directly into the provider constructor — ``os.environ`` is never
    mutated.
    """
    if session is not None:
        from core.db.queries import get_setting

        anthropic_key = get_setting(session, "ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
        openai_key = get_setting(session, "OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        openai_base_url = get_setting(session, "OPENAI_BASE_URL") or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        openai_model = get_setting(session, "OPENAI_MODEL") or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        ollama_base_url = get_setting(session, "OLLAMA_BASE_URL") or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        ollama_model = get_setting(session, "OLLAMA_MODEL") or os.getenv("OLLAMA_MODEL", "llama3.2")
        ai_provider = (get_setting(session, "AI_PROVIDER") or os.getenv("AI_PROVIDER", "")).lower()
    else:
        anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        openai_key = os.getenv("OPENAI_API_KEY", "")
        openai_base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")
        ai_provider = os.getenv("AI_PROVIDER", "").lower()

    if ai_provider == "anthropic" or (not ai_provider and anthropic_key):
        p = AnthropicProvider(api_key=anthropic_key)
        if p.is_available():
            return p

    if ai_provider == "openai" or (not ai_provider and openai_key):
        p = OpenAICompatibleProvider(api_key=openai_key, base_url=openai_base_url, model=openai_model)
        if p.is_available():
            return p

    if ai_provider == "ollama" or not ai_provider:
        p = OllamaProvider(base_url=ollama_base_url, model=ollama_model)
        if p.is_available():
            return p

    return None
