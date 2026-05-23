"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import logging
import os
import re
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

APPROVED_MODELS = [
    "gpt-4",
    "gpt-4o",
    "gpt-4-turbo",
    "gpt-3.5-turbo",
    "claude-3-opus",
    "claude-3-sonnet",
    "claude-3-haiku",
    "claude-3-5-sonnet",
    "mistral-large",
    "mistral-medium",
    "mistral-small",
    "llama-3-70b",
    "llama-3-8b",
]

ALLOWED_ROLES = {"system", "user", "assistant", "function", "tool"}

DYNAMIC_CODE_PATTERNS = re.compile(
    r"\b(eval|exec|subprocess|__import__|compile|execfile|globals|locals|vars|getattr|setattr|delattr|open|__builtins__)\s*\(",
    re.IGNORECASE,
)

MAX_CONTENT_LENGTH = 32000


def _sanitize_llm_output(content: str) -> str:
    """Check LLM output for dynamic code execution primitives."""
    if DYNAMIC_CODE_PATTERNS.search(content):
        raise ValueError(
            "LLM output contains potentially dangerous dynamic code execution primitives."
        )
    return content


def _validate_and_sanitize_inputs(model: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate and sanitize model string and messages before sending to LLM API."""
    if not model or not isinstance(model, str):
        raise ValueError("Model must be a non-empty string.")
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', model):
        raise ValueError(f"Model string contains unsafe characters: {model}")

    if not messages or not isinstance(messages, list):
        raise ValueError("Messages must be a non-empty list.")

    sanitized_messages = []
    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            raise ValueError(f"Message at index {i} must be a dict.")
        role = message.get("role")
        if role not in ALLOWED_ROLES:
            raise ValueError(
                f"Message at index {i} has invalid role '{role}'. Allowed roles: {ALLOWED_ROLES}"
            )
        content = message.get("content")
        if not isinstance(content, str):
            raise ValueError(f"Message at index {i} 'content' must be a string.")
        truncated_content = content[:MAX_CONTENT_LENGTH]
        sanitized_message = dict(message)
        sanitized_message["content"] = truncated_content
        sanitized_messages.append(sanitized_message)

    return sanitized_messages


class OpenAICompatibleClient:
    """Minimal async wrapper around a chat-completions style API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.base_url = (
            base_url
            or os.getenv("MODEL_GATEWAY_BASE_URL")
            or "http://127.0.0.1:4000/v1"
        ).rstrip("/")
        self.api_key = api_key or os.getenv("MODEL_GATEWAY_API_KEY")

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 400,
    ) -> str:
        if model not in APPROVED_MODELS:
            raise ValueError(
                f"Model '{model}' is not in the approved models list. "
                f"Approved models: {APPROVED_MODELS}"
            )

        sanitized_messages = _validate_and_sanitize_inputs(model, messages)

        logger.info(
            "Sending request to LLM",
            extra={
                "model": model,
                "messages": sanitized_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )

        payload = {
            "model": model,
            "messages": sanitized_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        def _post() -> str:
            try:
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=20,
                )
                response.raise_for_status()
                data = response.json()
                choices = data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    content = message.get("content", "")
                    if isinstance(content, str):
                        sanitized_content = _sanitize_llm_output(content.strip())
                        logger.info(
                            "Received response from LLM",
                            extra={"model": model, "response_content": sanitized_content},
                        )
                        return sanitized_content
                return f"Model API returned no content for model {model}."
            except requests.RequestException as exc:
                logger.warning(
                    "Model gateway request failed",
                    extra={"model": model, "error": str(exc)},
                )
                return f"Model gateway unavailable for {model}: {exc}"

        return await asyncio.to_thread(_post)