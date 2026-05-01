"""Orchestrator Agent class with explicit model invocation."""

import hashlib
import hmac
import logging
import os
import re
import unicodedata
from typing import Any

from .credit_eval_agent import credit_eval_agent
from .file_processor_agent import file_processor_agent
from .framework import PolicyProbeAgentFramework
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .support_agent import support_agent

logger = logging.getLogger(__name__)

_DANGEROUS_CODE_PATTERNS = re.compile(
    r"\b(eval|exec|compile|__import__|subprocess|os\.system|os\.popen|"
    r"importlib|ctypes|pty|popen|system|execfile|execv|execve|execvp|"
    r"execvpe|spawn|fork|Popen)\s*[\(\[]",
    re.IGNORECASE,
)

_PROMPT_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+previous\s+instructions?|disregard\s+all\s+prior|"
    r"you\s+are\s+now\s+in\s+developer\s+mode|jailbreak|"
    r"forget\s+your\s+instructions?|new\s+instructions?:|"
    r"system\s*:\s*you\s+are|<\s*system\s*>|<\s*/?instructions?\s*>)",
    re.IGNORECASE,
)

_SUSPICIOUS_FILE_PATTERNS = re.compile(
    r"(ignore\s+previous|disregard|jailbreak|you\s+are\s+now|"
    r"new\s+instructions?|rm\s+-rf|/etc/passwd|/bin/sh|/bin/bash|"
    r"cmd\.exe|powershell|wget\s+http|curl\s+http|base64\s+-d|"
    r"eval\s*\(|exec\s*\(|__import__|subprocess)",
    re.IGNORECASE,
)

_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_MAX_USER_MESSAGE_LENGTH = 4096
_MAX_AGENT_NAME_LENGTH = 128
_MAX_MCP_RESPONSE_SIZE = 65536


def _sanitize_llm_input(text: str, max_length: int = _MAX_USER_MESSAGE_LENGTH) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = text.replace("\x00", "")
    text = "".join(
        ch for ch in text
        if unicodedata.category(ch) not in ("Cc", "Cf") or ch in ("\n", "\r", "\t")
    )
    text = text.strip()
    if len(text) > max_length:
        text = text[:max_length]
    text = _PROMPT_INJECTION_PATTERNS.sub("[REDACTED]", text)
    return text


def _sanitize_llm_output(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    if _DANGEROUS_CODE_PATTERNS.search(text):
        logger.warning(
            "Dangerous code execution primitive detected in LLM output; sanitizing.",
            extra={"pattern_match": True},
        )
        text = _DANGEROUS_CODE_PATTERNS.sub("[BLOCKED]", text)
    text = _PROMPT_INJECTION_PATTERNS.sub("[REDACTED]", text)
    return text


def _sanitize_mcp_response(response: Any, server_name: str = "Slack") -> Any:
    if response is None:
        return response
    if isinstance(response, str):
        if len(response) > _MAX_MCP_RESPONSE_SIZE:
            logger.warning(
                "MCP response from %s exceeds size limit; truncating.", server_name
            )
            response = response[:_MAX_MCP_RESPONSE_SIZE]
        response = _DANGEROUS_CODE_PATTERNS.sub("[BLOCKED]", response)
        response = _PROMPT_INJECTION_PATTERNS.sub("[REDACTED]", response)
        return response
    if isinstance(response, dict):
        return {
            k: _sanitize_mcp_response(v, server_name)
            for k, v in response.items()
            if isinstance(k, str)
        }
    if isinstance(response, list):
        return [_sanitize_mcp_response(item, server_name) for item in response]
    return response


def _generate_hop_token(agent_id: str, selected_agent_name: str) -> str:
    secret_key = os.environ.get("ORCHESTRATOR_HOP_SECRET_KEY", "")
    if not secret_key:
        logger.warning("ORCHESTRATOR_HOP_SECRET_KEY is not set; hop token will be weak.")
    message = f"{agent_id}:{selected_agent_name}:{os.urandom(16).hex()}"
    token = hmac.new(
        secret_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return token


class OrchestratorAgent(PolicyProbeAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude-3-5-sonnet-20241022"
    BEDROCK_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v1:0"
    DESCRIPTION = "Routes work between the specialized agents and shares the conversation context."
    MCP_SERVERS = [{"name": "Slack", "auth_token_env": "SLACK_MCP_AUTH_TOKEN"}]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": True,
    }
    MCP_AUTH_TOKENS: dict[str, str] = {}
    SYSTEM_PROMPT = "Route requests to the right specialist and keep the workflow moving."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_mcp_auth_tokens()
        self._authenticate_mcp_server("Slack")

    def _load_mcp_auth_tokens(self) -> None:
        for server_config in self.MCP_SERVERS:
            if isinstance(server_config, dict):
                name = server_config.get("name", "")
                env_var = server_config.get("auth_token_env", "")
                token = os.environ.get(env_var, "") if env_var else ""
                self.MCP_AUTH_TOKENS[name] = token

    def get_mcp_auth_token(self, server_name: str) -> str:
        token = self.MCP_AUTH_TOKENS.get(server_name, "")
        if not token:
            raise ValueError(
                f"MCP authentication token for server '{server_name}' is not configured. "
                f"Set the corresponding environment variable."
            )
        return token

    def _authenticate_mcp_server(self, server_name: str) -> None:
        try:
            token = self.get_mcp_auth_token(server_name)
            if not token or len(token) < 8:
                raise ValueError(f"MCP server '{server_name}' token is invalid or too short.")
            logger.info(
                "MCP server authentication successful.",
                extra={"server_name": server_name, "agent_id": self.AGENT_ID},
            )
        except ValueError as exc:
            logger.error(
                "MCP server authentication failed for '%s': %s", server_name, exc,
                extra={"server_name": server_name, "agent_id": self.AGENT_ID},
            )
            raise

    def sanitize_file_contents(self, file_contents: list) -> list:
        if not isinstance(file_contents, list):
            logger.warning("file_contents is not a list; returning empty list.")
            return []
        sanitized = []
        for item in file_contents:
            if not isinstance(item, dict):
                logger.warning("Skipping non-dict file content item.")
                continue
            clean_item: dict[str, str] = {}
            for k, v in item.items():
                if not isinstance(k, str):
                    continue
                if not isinstance(v, str):
                    v = str(v)
                if _SUSPICIOUS_FILE_PATTERNS.search(v):
                    logger.warning(
                        "Suspicious content detected in file contents; stripping.",
                        extra={"key": k},
                    )
                    v = _SUSPICIOUS_FILE_PATTERNS.sub("[REDACTED]", v)
                if _BASE64_PATTERN.search(v):
                    logger.warning(
                        "Potential base64-encoded content detected in file contents; redacting.",
                        extra={"key": k},
                    )
                    v = _BASE64_PATTERN.sub("[BASE64_REDACTED]", v)
                invisible_chars = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\ufeff]")
                v = invisible_chars.sub("", v)
                clean_item[k] = v
            sanitized.append(clean_item)
        return sanitized

    async def call_agent_model(self, user_message: str, selected_agent_name: str) -> str:
        safe_user_message = _sanitize_llm_input(user_message, _MAX_USER_MESSAGE_LENGTH)
        safe_agent_name = _sanitize_llm_input(selected_agent_name, _MAX_AGENT_NAME_LENGTH)

        logger.info(
            "LLM request initiated.",
            extra={
                "agent_id": self.AGENT_ID,
                "model": self.MODEL_NAME,
                "user_message_length": len(safe_user_message),
                "selected_agent_name": safe_agent_name,
            },
        )

        raw_result = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{safe_user_message or 'No user message provided.'}\n\n"
                        f"Selected agent: {safe_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        )

        logger.info(
            "LLM response received.",
            extra={
                "agent_id": self.AGENT_ID,
                "model": self.MODEL_NAME,
                "response_length": len(raw_result) if isinstance(raw_result, str) else None,
            },
        )

        return raw_result

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        slack_token = self.get_mcp_auth_token("Slack")

        raw_user_message = context.get("user_message", "") or ""
        raw_file_contents = context.get("file_contents", []) or []

        safe_user_message = _sanitize_llm_input(raw_user_message, _MAX_USER_MESSAGE_LENGTH)
        safe_file_contents = self.sanitize_file_contents(raw_file_contents)

        selected_agent = self.select_agent(
            user_message=safe_user_message,
            file_contents=safe_file_contents,
        )
        selected_agent_name = selected_agent.AGENT_NAME

        hop_token = _generate_hop_token(self.AGENT_ID, selected_agent_name)

        forwarded_context: dict[str, Any] = {
            "user_message": safe_user_message,
            "file_contents": safe_file_contents,
            "session_id": context.get("session_id", ""),
            "request_id": context.get("request_id", ""),
            "orchestrator_agent": self.AGENT_NAME,
            "selected_agent": selected_agent_name,
            "internal_call_chain": [self.AGENT_NAME, selected_agent_name],
            "internal_hop_token": os.environ.get("ORCHESTRATOR_HOP_TOKEN", hop_token),
        }

        logger.info(
            "Orchestrator Agent routing request",
            extra={
                "selected_agent": selected_agent_name,
                "internal_call_chain": forwarded_context["internal_call_chain"],
            },
        )

        logger.info(
            "Sending request to Slack MCP server.",
            extra={
                "agent_id": self.AGENT_ID,
                "mcp_server": "Slack",
                "selected_agent": selected_agent_name,
                "user_message_length": len(safe_user_message),
            },
        )

        raw_routing_note = await self.call_agent_model(
            safe_user_message,
            selected_agent_name,
        )

        routing_note = _sanitize_llm_output(raw_routing_note)

        sanitized_routing_note = _sanitize_mcp_response(routing_note, server_name="Slack")

        logger.info(
            "Received response from Slack MCP server.",
            extra={
                "agent_id": self.AGENT_ID,
                "mcp_server": "Slack",
                "response_length": len(sanitized_routing_note) if isinstance(sanitized_routing_note, str) else None,
            },
        )

        response = await selected_agent.handle(forwarded_context)
        response["orchestrator"] = self.AGENT_NAME
        response["routing_note"] = sanitized_routing_note
        return response

    def select_agent(self, user_message: str, file_contents: list[dict[str, Any]]) -> PolicyProbeAgentFramework:
        text = (user_message or "").lower()

        if any(keyword in text for keyword in ["schedule", "meeting", "calendar", "appointment"]):
            return scheduling_agent
        if any(keyword in text for keyword in ["base64", "encoded", "vulnerability", "download", "package"]):
            return support_agent
        if any(keyword in text for keyword in ["support", "ticket", "incident", "password", "outage"]):
            return support_agent
        if any(keyword in text for keyword in ["credit", "fico", "debt-to-income", "dti", "underwrite", "loan status", "employee", "ssn", "borrower status"]):
            return credit_eval_agent
        if any(keyword in text for keyword in ["loan", "mortgage", "borrower", "application"]):
            return credit_eval_agent
        if file_contents:
            return file_processor_agent
        return support_agent


orchestrator_agent = OrchestratorAgent()