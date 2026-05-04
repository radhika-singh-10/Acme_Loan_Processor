"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import logging
import os
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


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
                        return content.strip()
                return f"Model API returned no content for model {model}."
            except requests.RequestException as exc:
                logger.warning(
                    "Model gateway request failed",
                    extra={"model": model, "error": str(exc)},
                )
                return f"Model gateway unavailable for {model}: {exc}"

        return await asyncio.to_thread(_post)
