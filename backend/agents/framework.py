"""Small agent framework base class used by the PolicyProbe agents."""

import os
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.bedrock import BedrockClient
from llm.openai_compatible import OpenAICompatibleClient


class PolicyProbeAgentFramework(ABC):
    """Base class that makes agent metadata and model usage obvious."""

    FRAMEWORK_NAME = "PolicyProbeAgentFramework"
    AGENT_ID = ""
    AGENT_NAME = ""
    VERSION = "1.0.0"
    MODEL_NAME = ""
    BEDROCK_MODEL_ID = ""
    BEDROCK_FALLBACK_MODEL_ID = "amazon.nova-pro-v1:0"
    DESCRIPTION = ""
    MCP_SERVERS: list[tuple[str, str]] = []  # (server_url, auth_token)

    @staticmethod
    def sanitize_mcp_output(output: str) -> str:
        """Sanitize MCP server output to prevent injection attacks."""
        import html
        return html.escape(output)
    GUARDRAILS: dict[str, Any] = {}
    SYSTEM_PROMPT = ""
    IS_ROUTABLE = True
    IS_SCAN_ONLY = False

    def __init__(self):
        self.bedrock_client = BedrockClient()
        self.model_client = BedrockClient()

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
            "mcp_servers": [{"url": url, "auth_token": token} for url, token in self.MCP_SERVERS],
            "mcp_server_auth": deepcopy(self.MCP_SERVER_AUTH),
            "guardrails": deepcopy(self.GUARDRAILS),
            "system_prompt": self.SYSTEM_PROMPT,
            "is_routable": self.IS_ROUTABLE,
            "is_scan_only": self.IS_SCAN_ONLY,
        }

    async def call_bedrock_model(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 350,
    ) -> str:
        deployment_override_model = os.getenv("BEDROCK_MODEL_ID")
        active_model = self.BEDROCK_MODEL_ID

        # Deployment override: force all routable runtime agents onto the same
        # Bedrock model while leaving scan-only agents unchanged for scanners.
        if deployment_override_model and self.IS_ROUTABLE and not self.IS_SCAN_ONLY:
            active_model = deployment_override_model

        # Sanitize and validate messages before sending to the model
        validated_messages = self._sanitize_messages(messages)
                # Security check: reject messages containing hidden prompts, base64, or shell commands
        self._validate_messages(messages)
        primary_response = await self.bedrock_client.chat(
            messages=messages,
            model=active_model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        # Log the LLM interaction
        print(f"LLM call: model={active_model}, messages={messages}, response={primary_response}")
        if (
            (
                "Error communicating with LLM:" in primary_response
                or primary_response.startswith("LLM service not configured")
                or primary_response.startswith("Error:")
            )
            and self.BEDROCK_FALLBACK_MODEL_ID
        ):
            fallback_response = await self.bedrock_client.chat(
                messages=messages,
                model=self.BEDROCK_FALLBACK_MODEL_ID,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            # Log the fallback LLM interaction
            print(f"LLM call: model={self.BEDROCK_FALLBACK_MODEL_ID}, messages={messages}, response={fallback_response}")
            return fallback_response
        # Validate and sanitize LLM output for eval/exec primitives
        sanitized = self._sanitize_llm_output(primary_response)
        return sanitized

    def _sanitize_llm_output(self, output: str) -> str:
        """Validate and sanitize LLM output to prevent eval/exec primitives."""
        dangerous_patterns = ["eval(", "exec(", "__import__(", "compile(", "execfile("]
        for pattern in dangerous_patterns:
            if pattern in output:
                raise ValueError(f"LLM output contains dangerous pattern: {pattern}")
        return output

    def _sanitize_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sanitize and validate messages before sending to the model.

        Ensures each message has required keys ('role', 'content') and that
        content is a string. Strips any unexpected keys or dangerous content.
        """
        sanitized = []
        allowed_roles = {"system", "user", "assistant"}
        for msg in messages:
            if not isinstance(msg, dict):
                continue  # skip invalid messages
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role not in allowed_roles or not isinstance(content, str):
                continue  # skip messages with invalid role or non-string content
            sanitized.append({"role": role, "content": content})
        return sanitized

    def _validate_messages(self, messages: list[dict[str, Any]]) -> None:
        """Check messages for hidden prompts, base64, or shell commands."""
        import re
        suspicious_patterns = [
            r'\b(base64)\b',
            r'\b(?:sh|bash|cmd|powershell|exec|system|popen|subprocess)\b',
            r'\b(?:eval|exec|compile|__import__)\b',
            r'\b(?:rm\s+-rf|del\s+/f|format\s+/q)\b',
        ]
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                for pattern in suspicious_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        raise ValueError("Message contains prohibited content (hidden prompt, base64, or shell command).")
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and "text" in part:
                        for pattern in suspicious_patterns:
                            if re.search(pattern, part["text"], re.IGNORECASE):
                                raise ValueError("Message contains prohibited content (hidden prompt, base64, or shell command).")

    @abstractmethod
    async def handle(self, context: dict[str, Any], auth_token: str = "") -> dict[str, Any]:
        """Handle a request for this agent."""
        if not auth_token or auth_token != os.getenv("INTER_AGENT_AUTH_TOKEN", ""):
            return {"error": "Authentication failed: invalid or missing auth token"}
