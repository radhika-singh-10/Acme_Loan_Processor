"""Small agent framework base class used by the PolicyProbe agents."""

import logging
import os
import re
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.bedrock import BedrockClient

logger = logging.getLogger(__name__)

MAX_CONTENT_LENGTH = 100_000
ALLOWED_ROLES = {"user", "assistant", "system"}

DYNAMIC_CODE_PATTERNS = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bcompile\s*\(",
    r"\bexecfile\s*\(",
    r"\b__import__\s*\(",
    r"\bos\.system\s*\(",
    r"\bsubprocess\b.*shell\s*=\s*True",
    r"\bgetattr\s*\(.*__",
    r"\bunicode_escape\b",
]

_DYNAMIC_CODE_RE = re.compile("|".join(DYNAMIC_CODE_PATTERNS), re.DOTALL)


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

    TASK_COMPLETE_KEY = "task_complete"
    MAX_ITERATIONS = 10

    def __init__(self):
        self.bedrock_client = BedrockClient()
        self.model_client = BedrockClient()
        self._iteration_count = 0

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

    def is_task_complete(self, result: dict[str, Any]) -> bool:
        """Return True if the result dict signals task completion."""
        return bool(result.get(self.TASK_COMPLETE_KEY, False))

    def _check_iteration_limit(self) -> None:
        """Increment iteration counter and raise if the hard stop is reached."""
        self._iteration_count += 1
        if self._iteration_count > self.MAX_ITERATIONS:
            raise RuntimeError(
                f"Agent '{self.AGENT_NAME}' exceeded MAX_ITERATIONS "
                f"({self.MAX_ITERATIONS}). Stopping execution."
            )

    @staticmethod
    def _sanitize_llm_output(response: str) -> str:
        """Raise ValueError if the LLM response contains dynamic code execution primitives."""
        if _DYNAMIC_CODE_RE.search(response):
            raise ValueError(
                "LLM response contains disallowed dynamic code execution primitives."
            )
        return response

    def _sanitize_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate and sanitize the messages list before sending to the Bedrock client."""
        if not messages or not isinstance(messages, list):
            raise ValueError("messages must be a non-empty list.")

        sanitized = []
        for idx, message in enumerate(messages):
            if not isinstance(message, dict):
                raise ValueError(f"Message at index {idx} must be a dict.")
            if "role" not in message or "content" not in message:
                raise ValueError(
                    f"Message at index {idx} is missing required 'role' or 'content' keys."
                )
            role = message["role"]
            if role not in ALLOWED_ROLES:
                raise ValueError(
                    f"Message at index {idx} has disallowed role '{role}'. "
                    f"Allowed roles: {ALLOWED_ROLES}."
                )
            content = message["content"]
            if isinstance(content, str):
                # Strip null bytes
                content = content.replace("\x00", "")
                # Truncate excessively long content
                if len(content) > MAX_CONTENT_LENGTH:
                    logger.warning(
                        "Message at index %d content truncated from %d to %d characters.",
                        idx,
                        len(content),
                        MAX_CONTENT_LENGTH,
                    )
                    content = content[:MAX_CONTENT_LENGTH]
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
            "Calling Bedrock model '%s' | agent='%s' | temperature=%s | max_tokens=%s | "
            "num_messages=%d",
            active_model,
            self.AGENT_NAME,
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
            "Received response from Bedrock model '%s' | agent='%s' | response_length=%d",
            active_model,
            self.AGENT_NAME,
            len(primary_response) if isinstance(primary_response, str) else -1,
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
                "Primary model '%s' returned an error response; falling back to '%s' | agent='%s'",
                active_model,
                self.BEDROCK_FALLBACK_MODEL_ID,
                self.AGENT_NAME,
            )
            fallback_response = await self.bedrock_client.chat(
                messages=messages,
                model=self.BEDROCK_FALLBACK_MODEL_ID,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            logger.info(
                "Received fallback response from Bedrock model '%s' | agent='%s' | "
                "response_length=%d",
                self.BEDROCK_FALLBACK_MODEL_ID,
                self.AGENT_NAME,
                len(fallback_response) if isinstance(fallback_response, str) else -1,
            )
            self._sanitize_llm_output(fallback_response)
            return fallback_response

        self._sanitize_llm_output(primary_response)
        return primary_response

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent.

        Subclasses must set the TASK_COMPLETE_KEY flag in the returned dict to
        signal that the agent has finished its task. Subclasses that loop must
        call _check_iteration_limit() on each iteration to enforce MAX_ITERATIONS.
        """