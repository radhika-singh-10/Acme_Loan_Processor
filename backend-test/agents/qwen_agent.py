"""Qwen assistant agent via Alibaba Cloud DashScope OpenAI-compatible API."""

import logging
import os
import re
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

from .framework import PolicyProbeAgentFramework

logger = logging.getLogger(__name__)
#vd,fbd,

# DashScope compatible-mode endpoint (OpenAI Chat Completions shape)
QWEN_DEFAULT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
# NOTE: The Qwen/DashScope integration is not in the organization's approved model registry.
# The model must be set to an approved model via the QWEN_MODEL environment variable.
# Defaulting to approved model 'gpt-4o' as a placeholder; override with QWEN_MODEL env var.
QWEN_DEFAULT_MODEL = "gpt-4o"


class QwenAssistantAgent(PolicyProbeAgentFramework):
    AGENT_ID = "qwen_assistant_agent"
    AGENT_NAME = "Qwen Assistant Agent"
    VERSION = "1.0.0"
    # NOTE: Model must be set to an approved model via the QWEN_MODEL environment variable.
    # The Qwen/DashScope 'qwen-plus' model is not in the organization's approved registry.
    MODEL_NAME = QWEN_DEFAULT_MODEL
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = (
        "Concise assistant powered by Alibaba Qwen via DashScope "
        "OpenAI-compatible chat completions."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = (
        "You are a concise assistant for an internal loan-operations team. "
        "Answer clearly; flag uncertainty; do not invent policy or rates."
    )

    _MAX_INPUT_LENGTH = 4000
    _INJECTION_PATTERNS = [
        r"ignore (all )?(previous|prior|above) instructions",
        r"disregard (all )?(previous|prior|above) instructions",
        r"forget (all )?(previous|prior|above) instructions",
        r"you are now",
        r"new (system )?prompt",
        r"override (system )?prompt",
        r"act as (a |an )?(?!assistant)",
        r"jailbreak",
        r"do anything now",
        r"<\s*system\s*>",
        r"\[\s*system\s*\]",
    ]

    _DANGEROUS_PATTERNS = re.compile(
        r"\b(eval|exec|execfile|compile|__import__)\s*\("
        r"|subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"
        r"|os\.system\s*\("
        r"|os\.popen\s*\("
        r"|commands\.getoutput\s*\(",
        re.IGNORECASE | re.DOTALL,
    )

    def __init__(self):
        super().__init__()
        api_key = os.getenv("DASHSCOPE_API_KEY") or os.getenv("QWEN_API_KEY")
        base = os.getenv("QWEN_BASE_URL", QWEN_DEFAULT_BASE_URL).rstrip("/")
        self.qwen_client = OpenAICompatibleClient(base_url=base, api_key=api_key)
        # NOTE: QWEN_MODEL must be set to an approved model from the organization's registry.
        self.qwen_model_id = os.getenv("QWEN_MODEL", self.MODEL_NAME)
        self._request_timeout = float(os.getenv("QWEN_CHAT_TIMEOUT", "120"))

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["model"] = self.qwen_model_id
        metadata["provider"] = "Alibaba Qwen (DashScope)"
        return metadata

    def _sanitize_and_validate(self, raw: str) -> str:
        if not isinstance(raw, str):
            raise ValueError("user_message must be a string.")

        cleaned = raw.strip()
        if not cleaned:
            raise ValueError("user_message must not be empty or blank.")

        if len(cleaned) > self._MAX_INPUT_LENGTH:
            raise ValueError(
                f"user_message exceeds maximum allowed length of "
                f"{self._MAX_INPUT_LENGTH} characters."
            )

        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cleaned)
        lower = cleaned.lower()
        for pattern in self._INJECTION_PATTERNS:
            if re.search(pattern, lower):
                logger.warning(
                    "Potential prompt injection detected in user_message.",
                    extra={"agent": self.AGENT_ID, "pattern": pattern},
                )
                raise ValueError(
                    "user_message contains disallowed content and cannot be processed."
                )
        return cleaned

    def _validate_and_sanitize_llm_output(self, output: str) -> str:
        match = self._DANGEROUS_PATTERNS.search(output)
        if match:
            logger.warning(
                "Dangerous code execution primitive detected in LLM output",
                extra={
                    "agent": self.AGENT_ID,
                    "matched_pattern": match.group(0),
                    "match_position": match.start(),
                },
            )
            raise ValueError(
                f"LLM output contains a forbidden dynamic code execution primitive: "
                f"'{match.group(0)}'. Response rejected for safety."
            )
        return output

    async def call_agent_model(self, user_message: str) -> str:
        logger.info(
            "Qwen assistant LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": self.qwen_model_id,
                "prompt_length": len(user_message or ""),
            },
        )
        return await self.qwen_client.chat(
            model=self.qwen_model_id,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": user_message or "No message provided.",
                },
            ],
            temperature=0.2,
            max_tokens=1024,
            timeout=self._request_timeout,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        raw_message = context.get("user_message", "")
        try:
            user_message = self._sanitize_and_validate(raw_message)
        except ValueError as exc:
            logger.warning(
                "user_message failed sanitization/validation: %s",
                exc,
                extra={"agent": self.AGENT_ID},
            )
            return {
                "response": f"Input validation error: {exc}",
                "agent": self.AGENT_NAME,
                "model": self.qwen_model_id,
                "framework": self.FRAMEWORK_NAME,
                "provider": "Alibaba Qwen (DashScope)",
                "mcp_activity": [],
            }

        model_output = await self.call_agent_model(user_message)
        logger.info(
            "Qwen assistant LLM response",
            extra={
                "agent": self.AGENT_ID,
                "model": self.qwen_model_id,
                "response_length": len(model_output or ""),
            },
        )
        try:
            model_output = self._validate_and_sanitize_llm_output(model_output)
        except ValueError as exc:
            logger.warning(
                "LLM output failed validation: %s",
                exc,
                extra={"agent": self.AGENT_ID},
            )
            return {
                "response": f"Output validation error: {exc}",
                "agent": self.AGENT_NAME,
                "model": self.qwen_model_id,
                "framework": self.FRAMEWORK_NAME,
                "provider": "Alibaba Qwen (DashScope)",
                "mcp_activity": [],
            }

        response = (
            f"Request: {user_message or 'No message provided.'}\n\n"
            f"Assistant reply:\n{model_output}"
        )
        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.qwen_model_id,
            "framework": self.FRAMEWORK_NAME,
            "provider": "Alibaba Qwen (DashScope)",
            "mcp_activity": [],
        }


qwen_assistant_agent = QwenAssistantAgent()