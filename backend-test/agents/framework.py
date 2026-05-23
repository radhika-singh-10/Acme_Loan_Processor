"""Small agent framework base class used by the PolicyProbe agents."""

import logging
import os
import re
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.bedrock import BedrockClient
from llm.openai_compatible import OpenAICompatibleClient

logger = logging.getLogger(__name__)

_DYNAMIC_CODE_PATTERNS = re.compile(
    r"\b(eval|exec|compile|execfile|__import__)\s*\("
    r"|subprocess\s*\.\s*\w*\s*\(.*shell\s*=\s*True"
    r"|os\s*\.\s*system\s*\(",
    re.DOTALL,
)

_ALLOWED_ROLES = {"user", "assistant", "system"}
_MAX_CONTENT_LENGTH = 32768


def _sanitize_llm_response(response: str) -> str:
    """Check LLM response for dynamic code execution primitives."""
    if _DYNAMIC_CODE_PATTERNS.search(response):
        raise ValueError(
            "LLM response contains disallowed dynamic code execution primitives."
        )
    return response


class PolicyProbeAgentFramework(ABC):
    """Base class that makes agent metadata and model usage obvious."""

    FRAMEWORK_NAME = "PolicyProbeAgentFramework"
    AGENT_ID = ""
    AGENT_NAME = ""
    VERSION = "1.0.0"
    MODEL_NAME = ""
    BEDROCK_MODEL_ID = ""
    BEDROCK_FALLBACK_MODEL_ID = ""
    DESCRIPTION = ""
    MCP_SERVERS: list[str] = []
    GUARDRAILS: dict[str, Any] = {}
    SYSTEM_PROMPT = ""
    IS_ROUTABLE = True
    IS_SCAN_ONLY = False

    MAX_ITERATIONS: int = 10
    TERMINATION_SIGNALS: set[str] = {
        "TASK_COMPLETE",
        "DONE",
        "EXIT",
        "TERMINATE",
        "NO_FURTHER_ACTION",
    }

    def __init__(self):
        self.bedrock_client = BedrockClient()
        self.model_client = OpenAICompatibleClient()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.AGENT_ID,
            "name": self.AGENT_NAME,
            "version": self.VERSION,
            "framework": self.FRAMEWORK_NAME,
            "model": self.MODEL_NAME,
            "bedrock_model_id": self.BEDROCK_MODEL_ID,
            "bedrock_fallback_model_id": self.BEDROCK_FALLBACK_MODEL_ID,
            "description": self.DESCRIPTION,
            "mcp_servers": list(self.MCP_SERVERS),
            "guardrails": deepcopy(self.GUARDRAILS),
            "system_prompt": self.SYSTEM_PROMPT,
            "is_routable": self.IS_ROUTABLE,
            "is_scan_only": self.IS_SCAN_ONLY,
        }

    def is_terminal_response(self, response: str) -> bool:
        """Return True if the response contains a termination signal."""
        upper = response.upper()
        return any(signal in upper for signal in self.TERMINATION_SIGNALS)

    def _sanitize_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate and sanitize messages before passing to the Bedrock client."""
        if not messages or not isinstance(messages, list):
            raise ValueError("messages must be a non-empty list.")

        sanitized = []
        for idx, message in enumerate(messages):
            if not isinstance(message, dict):
                raise ValueError(f"Message at index {idx} must be a dict.")
            if "role" not in message or "content" not in message:
                raise ValueError(
                    f"Message at index {idx} must have 'role' and 'content' keys."
                )
            role = message["role"]
            if role not in _ALLOWED_ROLES:
                raise ValueError(
                    f"Message at index {idx} has disallowed role '{role}'. "
                    f"Allowed roles: {_ALLOWED_ROLES}."
                )
            content = message["content"]
            if not isinstance(content, str):
                raise ValueError(
                    f"Message at index {idx} 'content' must be a string."
                )
            # Strip null bytes and ASCII control characters (except tab, newline, CR)
            content = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", content)
            if len(content) > _MAX_CONTENT_LENGTH:
                raise ValueError(
                    f"Message at index {idx} 'content' exceeds maximum length "
                    f"of {_MAX_CONTENT_LENGTH} characters."
                )
            sanitized_message = dict(message)
            sanitized_message["content"] = content
            sanitized.append(sanitized_message)

        return sanitized

    async def call_bedrock_model(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 350,
    ) -> str:
        messages = self._sanitize_messages(messages)

        deployment_override_model = os.getenv("BEDROCK_MODEL_ID")
        active_model = self.BEDROCK_MODEL_ID

        # Deployment override: force all routable runtime agents onto the same
        # Bedrock model while leaving scan-only agents unchanged for scanners.
        if deployment_override_model and self.IS_ROUTABLE and not self.IS_SCAN_ONLY:
            active_model = deployment_override_model

        logger.info(
            "Calling primary Bedrock model '%s' with temperature=%s, max_tokens=%s, "
            "message_count=%d",
            active_model,
            temperature,
            max_tokens,
            len(messages),
        )
        primary_response = await self.bedrock_client.chat(
            messages=messages,
            model=active_model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        logger.info(
            "Primary Bedrock model '%s' response: %s",
            active_model,
            primary_response,
        )
        if (
            (
                "Error communicating with LLM:" in primary_response
                or primary_response.startswith("LLM service not configured")
                or primary_response.startswith("Error:")
            )
            and self.BEDROCK_FALLBACK_MODEL_ID
        ):
            logger.info(
                "Calling fallback Bedrock model '%s' with temperature=%s, max_tokens=%s, "
                "message_count=%d",
                self.BEDROCK_FALLBACK_MODEL_ID,
                temperature,
                max_tokens,
                len(messages),
            )
            fallback_response = await self.bedrock_client.chat(
                messages=messages,
                model=self.BEDROCK_FALLBACK_MODEL_ID,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            logger.info(
                "Fallback Bedrock model '%s' response: %s",
                self.BEDROCK_FALLBACK_MODEL_ID,
                fallback_response,
            )
            return _sanitize_llm_response(fallback_response)
        return _sanitize_llm_response(primary_response)

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent.

        Subclasses MUST implement clear termination criteria. The implementation
        must respect MAX_ITERATIONS to prevent infinite loops and must check
        is_terminal_response() on each model response to determine when the
        task is complete and execution should stop.
        """