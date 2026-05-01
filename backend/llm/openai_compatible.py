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

APPROVED_MODELS = {
    "gpt-4",
    "gpt-4-turbo",
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-3.5-turbo",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "amazon.titan-text-express-v1",
    "amazon.titan-text-lite-v1",
    "anthropic.claude-3-sonnet-20240229-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0",
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
}

ALLOWED_ROLES = {"system", "user", "assistant", "tool", "function"}

DYNAMIC_CODE_PRIMITIVES = re.compile(
    r"\b(eval|exec|subprocess|os\.system|os\.popen|compile|__import__|"
    r"importlib|execfile|input|open|globals|locals|vars|getattr|setattr|"
    r"delattr|__builtins__|__class__|__subclasses__)\s*\(",
    re.IGNORECASE,
)

MAX_CONTENT_LENGTH = 100_000
MAX_MODEL_LENGTH = 128


def _validate_llm_output(content: str) -> str:
    """Check LLM output for dynamic code execution primitives."""
    if DYNAMIC_CODE_PRIMITIVES.search(content):
        raise ValueError(
            "LLM output contains potentially dangerous dynamic code execution primitives."
        )
    return content


def _strip_control_characters(value: str) -> str:
    """Remove null bytes and control characters from a string."""
    # Remove null bytes
    value = value.replace("\x00", "")
    # Remove other control characters except common whitespace
    value = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return value


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

    def _validate_and_sanitize(
        self,
        model: str,
        messages: list[dict[str, Any]],
    ) -> tuple[str, list[dict[str, Any]]]:
        """Validate and sanitize model and messages before use."""
        # Validate model
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string.")
        model = model.strip()
        if len(model) > MAX_MODEL_LENGTH:
            raise ValueError(
                f"model identifier exceeds maximum length of {MAX_MODEL_LENGTH}."
            )
        if not re.match(r"^[a-zA-Z0-9_\-.:/@]+$", model):
            raise ValueError(
                "model identifier contains invalid characters. Only alphanumeric, "
                "hyphens, underscores, dots, colons, slashes, and @ are allowed."
            )

        # Validate messages
        if not isinstance(messages, list) or len(messages) == 0:
            raise ValueError("messages must be a non-empty list.")

        sanitized_messages = []
        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                raise ValueError(f"messages[{i}] must be a dict.")

            # Validate only allowed keys
            allowed_keys = {"role", "content"}
            extra_keys = set(msg.keys()) - allowed_keys
            if extra_keys:
                raise ValueError(
                    f"messages[{i}] contains disallowed keys: {extra_keys}. "
                    f"Only 'role' and 'content' are permitted."
                )

            if "role" not in msg:
                raise ValueError(f"messages[{i}] is missing required key 'role'.")
            if "content" not in msg:
                raise ValueError(f"messages[{i}] is missing required key 'content'.")

            role = msg["role"]
            content = msg["content"]

            if not isinstance(role, str):
                raise ValueError(f"messages[{i}]['role'] must be a string.")
            if role not in ALLOWED_ROLES:
                raise ValueError(
                    f"messages[{i}]['role'] is '{role}', which is not one of the "
                    f"permitted roles: {ALLOWED_ROLES}."
                )

            if not isinstance(content, str):
                raise ValueError(f"messages[{i}]['content'] must be a string.")

            # Sanitize content
            content = _strip_control_characters(content)
            content = content.strip()
            if len(content) > MAX_CONTENT_LENGTH:
                content = content[:MAX_CONTENT_LENGTH]

            sanitized_messages.append({"role": role, "content": content})

        return model, sanitized_messages

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 400,
    ) -> str:
        # Validate model against approved list
        if model not in APPROVED_MODELS:
            raise ValueError(
                f"Model '{model}' is not in the approved models list. "
                f"Approved models: {APPROVED_MODELS}"
            )

        # Validate and sanitize inputs
        model, messages = self._validate_and_sanitize(model, messages)

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        def _post() -> str:
            try:
                logger.info(
                    "Sending LLM request",
                    extra={
                        "model": model,
                        "messages": messages,
                        "temperature": temperature,
                        "max_tokens": max_tokens,
                    },
                )
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
                        content = content.strip()
                        _validate_llm_output(content)
                        logger.info(
                            "Received LLM response",
                            extra={"model": model, "content": content},
                        )
                        return content
                return f"Model API returned no content for model {model}."
            except requests.RequestException as exc:
                logger.warning(
                    "Model gateway request failed",
                    extra={"model": model, "error": str(exc)},
                )
                return f"Model gateway unavailable for {model}: {exc}"

        return await asyncio.to_thread(_post)